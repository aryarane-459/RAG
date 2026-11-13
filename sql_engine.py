import json
import time
from datetime import datetime, date
from decimal import Decimal
import uuid
import psycopg2
from psycopg2.extras import RealDictCursor
import sqlglot
from sqlglot import exp
import ollama
from fastapi import HTTPException
from database import get_db_connection
from encryption import decrypt_password

# Schema cache with TTL
# Key: database_id -> {"schema_text": str, "allowed_tables": set, "table_columns": dict, "timestamp": float}
_SCHEMA_CACHE = {}
SCHEMA_CACHE_TTL_SECONDS = 600  # 10 minutes


def _json_serializable(val):
    """Convert non-serializable database values to JSON serializable objects."""
    if isinstance(val, (datetime, date)):
        return val.isoformat()
    if isinstance(val, Decimal):
        return float(val) if (val % 1) else int(val)
    if isinstance(val, uuid.UUID):
        return str(val)
    return val


def _sanitize_rows(rows: list[dict]) -> list[dict]:
    """Sanitize all rows in query results for JSON serialization."""
    sanitized = []
    for row in rows:
        sanitized.append({k: _json_serializable(v) for k, v in row.items()})
    return sanitized


def get_target_db_credentials(database_id: str, current_user: dict) -> dict:
    """
    Validate user authorization and fetch database connection credentials from central DB.
    Admins can access all active databases.
    Normal users can only access active databases assigned to them in database_user_access.
    """
    user_uid = current_user.get("uid")
    user_role = str(current_user.get("role", "")).strip().lower()

    conn = get_db_connection()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            # 1. Check access rights
            if user_role != "admin":
                cur.execute(
                    """
                    SELECT 1
                    FROM database_user_access
                    WHERE database_id = %s
                    """,
                    (database_id,)
                )
                has_restriction = cur.fetchone()
                if has_restriction:
                    cur.execute(
                        """
                        SELECT 1
                        FROM database_user_access
                        WHERE database_id = %s AND uid = %s
                        """,
                        (database_id, user_uid)
                    )
                    access = cur.fetchone()
                    if not access:
                        raise HTTPException(
                            status_code=403,
                            detail="You do not have permission to access this database."
                        )

            # 2. Fetch database connection information
            cur.execute(
                """
                SELECT database_id, database_name, db_type, host, port, db_name, db_username, encrypted_password, is_active
                FROM registered_databases
                WHERE database_id = %s
                """,
                (database_id,)
            )
            db_record = cur.fetchone()

            if not db_record:
                raise HTTPException(
                    status_code=404,
                    detail="Database not found."
                )

            if not db_record.get("is_active"):
                raise HTTPException(
                    status_code=400,
                    detail="This database is currently marked as inactive."
                )

            # Decrypt password
            decrypted_pass = decrypt_password(db_record["encrypted_password"])

            return {
                "database_id": str(db_record["database_id"]),
                "database_name": db_record["database_name"],
                "host": db_record["host"],
                "port": db_record["port"],
                "dbname": db_record["db_name"],
                "user": db_record["db_username"],
                "password": decrypted_pass,
            }
    finally:
        conn.close()


def extract_database_schema(db_params: dict, database_id: str = None) -> tuple[str, set[str], dict]:
    """
    Dynamically extract schema (tables, columns, types, primary keys, foreign keys)
    from the target PostgreSQL database's public schema.
    Uses in-memory TTL caching.
    Returns: (schema_text, allowed_tables, table_columns)
    """
    cache_key = database_id or f"{db_params['host']}:{db_params['port']}:{db_params['dbname']}"
    now = time.time()

    if cache_key in _SCHEMA_CACHE:
        entry = _SCHEMA_CACHE[cache_key]
        if now - entry["timestamp"] < SCHEMA_CACHE_TTL_SECONDS:
            return entry["schema_text"], entry["allowed_tables"], entry["table_columns"]

    # Connect to target DB
    try:
        conn = psycopg2.connect(
            host=db_params["host"],
            port=db_params["port"],
            dbname=db_params["dbname"],
            user=db_params["user"],
            password=db_params["password"],
            connect_timeout=5
        )
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Unable to connect to target database: {str(e)}"
        )

    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            # 1. Fetch tables and columns
            cur.execute(
                """
                SELECT 
                    c.table_name,
                    c.column_name,
                    c.data_type,
                    c.is_nullable
                FROM information_schema.columns c
                JOIN information_schema.tables t 
                    ON c.table_name = t.table_name 
                    AND c.table_schema = t.table_schema
                WHERE c.table_schema = 'public'
                  AND t.table_type = 'BASE TABLE'
                ORDER BY c.table_name, c.ordinal_position;
                """
            )
            cols = cur.fetchall()

            # 2. Fetch primary keys
            cur.execute(
                """
                SELECT
                    tc.table_name,
                    kcu.column_name
                FROM information_schema.table_constraints tc
                JOIN information_schema.key_column_usage kcu
                    ON tc.constraint_name = kcu.constraint_name
                    AND tc.table_schema = kcu.table_schema
                WHERE tc.constraint_type = 'PRIMARY KEY'
                  AND tc.table_schema = 'public';
                """
            )
            pks = cur.fetchall()

            # 3. Fetch foreign keys
            cur.execute(
                """
                SELECT
                    tc.table_name AS source_table,
                    kcu.column_name AS source_column,
                    ccu.table_name AS target_table,
                    ccu.column_name AS target_column
                FROM information_schema.table_constraints tc
                JOIN information_schema.key_column_usage kcu
                    ON tc.constraint_name = kcu.constraint_name
                    AND tc.table_schema = kcu.table_schema
                JOIN information_schema.constraint_column_usage ccu
                    ON ccu.constraint_name = tc.constraint_name
                    AND ccu.table_schema = tc.table_schema
                WHERE tc.constraint_type = 'FOREIGN KEY'
                  AND tc.table_schema = 'public';
                """
            )
            fks = cur.fetchall()

    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to inspect target database schema: {str(e)}"
        )
    finally:
        conn.close()

    if not cols:
        raise HTTPException(
            status_code=400,
            detail="Target database contains no public base tables."
        )

    # Process structure
    table_pks = {}
    for pk in pks:
        tname = pk["table_name"]
        table_pks.setdefault(tname, []).append(pk["column_name"])

    table_fks = {}
    for fk in fks:
        tname = fk["source_table"]
        table_fks.setdefault(tname, []).append(
            f"{fk['source_column']} -> {fk['target_table']}({fk['target_column']})"
        )

    tables_dict = {}
    allowed_tables = set()
    table_columns = {}

    for row in cols:
        tname = row["table_name"]
        col_name = row["column_name"]
        dtype = row["data_type"]
        allowed_tables.add(tname.lower())
        table_columns.setdefault(tname.lower(), set()).add(col_name.lower())

        if tname not in tables_dict:
            tables_dict[tname] = []
        tables_dict[tname].append(f"{col_name} ({dtype})")

    # Format schema string
    lines = [f"Database Schema for '{db_params['dbname']}':\n"]
    for tname, columns in tables_dict.items():
        lines.append(f"Table: {tname}")
        lines.append("  Columns:")
        for col in columns:
            lines.append(f"    - {col}")
        if tname in table_pks:
            lines.append(f"  Primary Key: {', '.join(table_pks[tname])}")
        if tname in table_fks:
            lines.append(f"  Foreign Keys: {', '.join(table_fks[tname])}")
        lines.append("")

    schema_text = "\n".join(lines)

    # Save to cache
    _SCHEMA_CACHE[cache_key] = {
        "schema_text": schema_text,
        "allowed_tables": allowed_tables,
        "table_columns": table_columns,
        "timestamp": now
    }

    return schema_text, allowed_tables, table_columns


def validate_sql(sql_str: str, allowed_tables: set[str], max_limit: int = 100) -> str:
    """
    Validate and sanitize LLM-generated SQL query using SQLGlot.
    Enforces:
    - Exactly one SQL statement
    - Only SELECT queries (no INSERT, UPDATE, DELETE, DROP, ALTER, TRUNCATE, etc.)
    - All referenced tables exist in allowed_tables
    - Enforces a LIMIT clause (maximum max_limit)
    Returns: dialect-sanitized SQL query string.
    """
    clean_sql = sql_str.strip().strip(";")

    try:
        parsed = sqlglot.parse(clean_sql, read="postgres")
    except Exception as e:
        raise ValueError(f"SQL syntax error: {str(e)}")

    if not parsed or len(parsed) != 1:
        raise ValueError("Invalid SQL: Only a single SQL query statement is permitted.")

    expression = parsed[0]

    # Verify root expression is a SELECT or UNION of SELECTs
    if not isinstance(expression, (exp.Select, exp.Union)):
        raise ValueError("Security violation: Only read-only SELECT queries are allowed.")

    # Check for any modifying or dangerous expressions anywhere in the AST
    forbidden_types = (
        exp.Insert,
        exp.Update,
        exp.Delete,
        exp.Drop,
        exp.Alter,
        exp.TruncateTable,
        exp.Create,
        exp.Command,
        exp.Commit,
        exp.Rollback,
        exp.Merge,
        exp.Grant,
        exp.Revoke,
    )

    for node in expression.walk():
        if isinstance(node, forbidden_types):
            raise ValueError(f"Security violation: Statement contains forbidden operation ({node.__class__.__name__}).")

    # Validate table references against allowed_tables
    tables = [t.name.lower() for t in expression.find_all(exp.Table) if t.name]
    for table_name in tables:
        if table_name not in allowed_tables:
            raise ValueError(
                f"Security violation: Table '{table_name}' is not in the allowed database schema."
            )

    # Enforce LIMIT
    existing_limit = expression.args.get("limit")
    if existing_limit is None:
        expression = expression.limit(max_limit)
    else:
        # Check if limit expression is an integer literal and cap it
        try:
            limit_val = int(existing_limit.expression.this)
            if limit_val > max_limit:
                expression.set("limit", exp.Limit(expression=exp.Literal.number(max_limit)))
        except Exception:
            expression.set("limit", exp.Limit(expression=exp.Literal.number(max_limit)))

    return expression.sql(dialect="postgres")


def generate_sql(question: str, schema_text: str, model_name: str = "llama3.2") -> tuple[str, str]:
    """
    Generate PostgreSQL SELECT query from natural language question using Ollama.
    Returns: (sql_query, explanation)
    """
    system_prompt = (
        "You are an expert PostgreSQL Text-to-SQL assistant.\n"
        "Given the database schema and a user question, generate a single, valid PostgreSQL SELECT query that answers the question.\n"
        "Strict Guidelines:\n"
        "1. ONLY output valid JSON with two keys: \"sql\" and \"explanation\".\n"
        "2. Only write SELECT queries. NEVER write INSERT, UPDATE, DELETE, DROP, ALTER, TRUNCATE, or schema-altering commands.\n"
        "3. Use ONLY table and column names that exist in the provided schema.\n"
        "4. For ANY text filtering, comparisons, or searches, ALWAYS use case-insensitive matching with ILIKE (e.g. type ILIKE 'Movie' or title ILIKE '%batman%') or LOWER(...) so that casing differences do not cause zero matches.\n"
        "5. Use appropriate JOINs, GROUP BY, ORDER BY, and aggregation functions (COUNT, SUM, AVG, MIN, MAX) when required.\n"
        "6. Always add an appropriate LIMIT clause (up to 100) if multiple rows are expected.\n"
        "7. Format output strictly as JSON: {\"sql\": \"SELECT ...\", \"explanation\": \"...\"}"
    )

    user_prompt = (
        f"Database Schema:\n{schema_text}\n\n"
        f"User Question: {question}\n\n"
        "Generate the JSON response containing the SQL query and explanation."
    )

    try:
        response = ollama.generate(
            model=model_name,
            system=system_prompt,
            prompt=user_prompt,
            format="json",
            options={"temperature": 0.1}
        )
        content = response.get("response", "").strip()
        data = json.loads(content)
        sql = data.get("sql", "").strip()
        explanation = data.get("explanation", "").strip()
        if not sql:
            raise ValueError("LLM generated an empty SQL query.")
        return sql, explanation
    except json.JSONDecodeError:
        raise ValueError("Failed to parse JSON response from LLM during SQL generation.")
    except Exception as e:
        raise ValueError(f"Error during SQL generation: {str(e)}")


def execute_sql(
    db_params: dict,
    sql_query: str,
    timeout_ms: int = 10000,
    max_rows: int = 100
) -> list[dict]:
    """
    Execute validated SQL query against target PostgreSQL database using a read-only session
    with strict statement timeout.
    Returns list of dictionary rows with JSON-serializable types.
    """
    try:
        conn = psycopg2.connect(
            host=db_params["host"],
            port=db_params["port"],
            dbname=db_params["dbname"],
            user=db_params["user"],
            password=db_params["password"],
            connect_timeout=5
        )
        # Enforce read-only at the session level
        conn.set_session(readonly=True, autocommit=True)
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to connect to database for query execution: {str(e)}"
        )

    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            # Set query execution timeout
            cur.execute(f"SET statement_timeout = {int(timeout_ms)};")
            cur.execute(sql_query)
            rows = cur.fetchmany(max_rows)
            return _sanitize_rows(rows)
    except psycopg2.Error as e:
        # Pass database error message back for correction or error handling
        error_msg = e.pgerror or str(e)
        raise RuntimeError(f"Database execution error: {error_msg}")
    finally:
        conn.close()


def correct_sql(
    question: str,
    schema_text: str,
    failed_sql: str,
    error_msg: str,
    allowed_tables: set[str],
    model_name: str = "llama3.2"
) -> tuple[str, str]:
    """
    Single controlled correction attempt when SQL fails at the database level.
    Returns: (corrected_sql, explanation)
    """
    prompt = (
        "You are an expert PostgreSQL database engineer.\n"
        "A previously generated SQL query failed with a database error.\n"
        "Fix the query based on the database schema and the error message.\n\n"
        f"Database Schema:\n{schema_text}\n\n"
        f"User Question: {question}\n"
        f"Failed SQL: {failed_sql}\n"
        f"Database Error: {error_msg}\n\n"
        "Instructions:\n"
        "- Generate a corrected PostgreSQL SELECT query that fixes this error.\n"
        "- Only write SELECT queries.\n"
        "- Output strictly JSON with keys \"sql\" and \"explanation\".\n"
    )

    try:
        response = ollama.generate(
            model=model_name,
            prompt=prompt,
            format="json",
            options={"temperature": 0.1}
        )
        content = response.get("response", "").strip()
        data = json.loads(content)
        raw_sql = data.get("sql", "").strip()
        explanation = data.get("explanation", "").strip()
        if not raw_sql:
            raise ValueError("LLM generated an empty correction query.")
        validated_sql = validate_sql(raw_sql, allowed_tables)
        return validated_sql, explanation
    except Exception as e:
        raise ValueError(f"Correction failed: {str(e)}")


def generate_nl_answer(
    question: str,
    sql_query: str,
    results: list[dict],
    model_name: str = "llama3.2"
) -> str:
    """
    Generate natural language conversational answer based strictly on the retrieved database results.
    """
    # Limit number of records shown to LLM to prevent prompt explosion
    sample_results = results[:50]
    results_str = json.dumps(sample_results, indent=2)

    prompt = (
        "You are DocuMind's intelligent data assistant.\n"
        "Answer the user's question clearly, accurately, and conversationally based ONLY on the database query results below.\n\n"
        f"User Question: {question}\n"
        f"Executed SQL Query: {sql_query}\n"
        f"Database Results:\n{results_str}\n\n"
        "Instructions:\n"
        "1. Base your answer strictly on the provided database results. Never invent or hallucinate data, counts, or titles.\n"
        "2. If the results contain an aggregate value such as count, sum, average, or max/min, directly provide that computed figure as the answer to the question (e.g. 'There are 6,131 movies in the database.'). Do NOT say you don't have information when an aggregate row is returned.\n"
        "3. If the results are empty (0 rows), clearly state that no matching records were found in the database.\n"
        "4. Provide relevant specific names, counts, or dates from the results.\n"
        "5. Keep the answer direct, informative, and well-structured.\n"
    )

    try:
        response = ollama.generate(
            model=model_name,
            prompt=prompt,
            options={"temperature": 0.2}
        )
        answer = response.get("response", "").strip()
        return answer
    except Exception as e:
        # Fallback in case LLM answer generation fails
        if not results:
            return "No matching records were found in the database for your query."
        return f"Retrieved {len(results)} record(s) matching your question."


def process_nl2sql(database_id: str, question: str, current_user: dict) -> dict:
    """
    Main Text-to-SQL pipeline coordinating:
    1. Authentication & database authorization check
    2. Dynamic schema extraction (with caching)
    3. SQL generation via Ollama (llama3.2)
    4. Strict SQLGlot validation
    5. Execution on read-only session with statement timeout
    6. Controlled 1-attempt SQL correction loop on error
    7. Natural language answer synthesis via Ollama
    """
    # Step 1: Authorization and connection retrieval
    db_credentials = get_target_db_credentials(database_id, current_user)

    # Step 2: Extract schema dynamically
    schema_text, allowed_tables, table_columns = extract_database_schema(
        db_credentials, database_id=database_id
    )

    # Step 3: Generate SQL
    raw_sql, explanation = generate_sql(question, schema_text)

    # Step 4: Validate SQL
    try:
        validated_sql = validate_sql(raw_sql, allowed_tables)
    except ValueError as ve:
        raise HTTPException(
            status_code=400,
            detail=f"Generated SQL failed security validation: {str(ve)}"
        )

    # Step 5 & 6: Execute with 1-attempt controlled correction loop
    results = None
    executed_sql = validated_sql

    try:
        results = execute_sql(db_credentials, executed_sql)
    except RuntimeError as db_err:
        # Controlled 1-attempt correction
        try:
            corrected_sql, corr_explanation = correct_sql(
                question=question,
                schema_text=schema_text,
                failed_sql=executed_sql,
                error_msg=str(db_err),
                allowed_tables=allowed_tables
            )
            executed_sql = corrected_sql
            results = execute_sql(db_credentials, executed_sql)
        except Exception as retry_err:
            raise HTTPException(
                status_code=400,
                detail=f"Database query execution failed: {str(db_err)}"
            )

    # Step 7: Generate natural language answer
    answer = generate_nl_answer(question, executed_sql, results)

    return {
        "success": True,
        "question": question,
        "sql_query": executed_sql,
        "results": results,
        "answer": answer
    }

