
import re
from rank_bm25 import BM25Okapi
from database import get_db_connection


def tokenize(text: str):
    return re.findall(r"\b\w+\b", text.lower())


def get_db_chunks(pdf_ids=None):

    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        if pdf_ids:
            cursor.execute(
                """
                SELECT chunk_id, pdf_id, chunk_number, chunk_text
                FROM chunks
                WHERE pdf_id = ANY(%s)
                """,
                (pdf_ids,)
            )
        else:
            cursor.execute(
                """
                SELECT chunk_id, pdf_id, chunk_number, chunk_text
                FROM chunks
                """
            )

        rows = cursor.fetchall()
        chunks = []

        for row in rows:
            chunks.append({
                "chunk_id": row[0],
                "pdf_id": row[1],
                "chunk_number": row[2],
                "text": row[3]
            })

        return chunks

    finally:
        cursor.close()
        conn.close()


def bm25_search(question: str, pdf_ids=None, top_k=20):

    chunks = get_db_chunks(pdf_ids)

    if not chunks:
        return []

    tokenized_chunks = [
        tokenize(chunk["text"])
        for chunk in chunks
    ]

    bm25 = BM25Okapi(tokenized_chunks)

    query_tokens = tokenize(question)

    if not query_tokens:
        return []

    scores = bm25.get_scores(query_tokens)

    ranked_indices = sorted(
        range(len(scores)),
        key=lambda i: scores[i],
        reverse=True
    )

    results = []

    for index in ranked_indices:

        score = float(scores[index])

        if score <= 0:
            continue

        chunk = chunks[index].copy()
        chunk["bm25_score"] = score

        results.append(chunk)

        if len(results) >= top_k:
            break

    return results
