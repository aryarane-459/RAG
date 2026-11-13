import os
import hashlib

import ollama
from qdrant_client import QdrantClient
from qdrant_client.models import (
    Distance,
    VectorParams,
    PointStruct,
    Filter,
    FieldCondition,
    MatchValue,
)

from database import get_db_connection
from parser import Pdf_to_Text



QDRANT_URL = os.getenv("QDRANT_URL", "http://localhost:6333")
COLLECTION_NAME = "Newapplication"

EMBEDDING_MODEL = "bge-m3"
VECTOR_SIZE = 1024

CHUNK_SIZE = 1500
CHUNK_OVERLAP = 300

BATCH_SIZE = 32

qdrant = QdrantClient(url=QDRANT_URL)


# print("Qdrant URL:", QDRANT_URL)
# print("Collection exists:", qdrant.collection_exists(COLLECTION_NAME))
# print("Collections:", qdrant.get_collections())
def setup_collection():
    """Create the Qdrant collection if it does not exist."""

    if not qdrant.collection_exists(
        collection_name=COLLECTION_NAME
    ):
        qdrant.create_collection(
            collection_name=COLLECTION_NAME,
            vectors_config=VectorParams(
                size=VECTOR_SIZE,
                distance=Distance.COSINE,
            ),
        )
        print(f"Created Qdrant collection: {COLLECTION_NAME}")
    else:
        print(f"Using Qdrant collection: {COLLECTION_NAME}")



def split_into_chunks(text):
    """Split extracted PDF text into overlapping chunks."""

    chunks = []
    start = 0
    text_length = len(text)

    while start < text_length:
        end = min(start + CHUNK_SIZE, text_length)
        chunk = text[start:end].strip()

        if chunk:
            chunks.append(chunk)

        if end >= text_length:
            break

        start = end - CHUNK_OVERLAP

    return chunks



def generate_embedding(text):
    """Generate a vector using the local Ollama model."""

    result = ollama.embed(
        model=EMBEDDING_MODEL,
        input=text,
    )

    vector = result["embeddings"][0]

    if len(vector) != VECTOR_SIZE:
        raise ValueError(
            f"Expected {VECTOR_SIZE} dimensions, "
            f"but received {len(vector)}"
        )

    return vector



def generate_point_id(pdf_id, chunk_number):
    """Generate a repeatable integer ID without using UUID."""

    value = f"{pdf_id}:{chunk_number}"

    hashed_value = hashlib.sha256(
        value.encode("utf-8")
    ).hexdigest()

    return int(hashed_value[:15], 16)



def process_pdf(pdf_id, pdf_path):
    """
    Extract PDF text, create chunks, store text in PostgreSQL,
    and store embeddings plus text payloads in Docker-hosted Qdrant.

    Returns the number of processed chunks.
    """

    if not os.path.isfile(pdf_path):
        raise FileNotFoundError(
            f"PDF file not found: {pdf_path}"
        )

    conn = None
    cursor = None

    text_path = os.path.join(
        os.path.dirname(pdf_path),
        f"text_{pdf_id}.txt",
    )

    try:
        text = Pdf_to_Text(pdf_path, text_path)

        if not text or not text.strip():
            raise ValueError(
                "No text was extracted from the PDF."
            )

        print(f"Parsed text saved to: {text_path}")

        chunks = split_into_chunks(text)

        if not chunks:
            raise ValueError(
                "No text chunks were generated."
            )

        print(f"Generated {len(chunks)} chunks.")

        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT pdf_id
            FROM documents
            WHERE pdf_id = %s
            """,
            (pdf_id,),
        )

        if cursor.fetchone() is None:
            raise ValueError(
                f"PDF ID {pdf_id} does not exist in documents."
            )

            
        vectors = []

        for chunk_number, chunk in enumerate(chunks):
            vector = generate_embedding(chunk)

            vectors.append({
                "chunk_number": chunk_number,
                "text": chunk,
                "vector": vector
            })

        cursor.execute(
            "DELETE FROM chunks WHERE pdf_id=%s",
            (pdf_id,)
        )

        points = []

        for item in vectors:
            cursor.execute(
                """
                INSERT INTO chunks (
                    pdf_id,
                    chunk_number,
                    chunk_text
                )
                VALUES (%s, %s, %s)
                RETURNING chunk_id
                """,
                (pdf_id, item["chunk_number"], item["text"])
            )

            chunk_id = cursor.fetchone()[0]

            point = PointStruct(
                id=generate_point_id(pdf_id, item["chunk_number"]),
                vector=item["vector"],
                payload={
                    "chunk_id": int(chunk_id),
                    "pdf_id": int(pdf_id),
                    "chunk_number": item["chunk_number"],
                    "text": item["text"]
                }
            )

            points.append(point)

            conn.commit()

        print(f"Inserted {len(points)} chunks into PostgreSQL.")



        print(
            f"Stored {len(chunks)} text chunks in PostgreSQL."
        )

        qdrant.delete(
            collection_name=COLLECTION_NAME,
            points_selector=Filter(
                must=[
                    FieldCondition(
                        key="pdf_id",
                        match=MatchValue(value=int(pdf_id)),
                    )
                ]
            ),
            wait=True,
        )

        for start in range(0, len(points), BATCH_SIZE):
            batch = points[start:start + BATCH_SIZE]

            qdrant.upsert(
                collection_name=COLLECTION_NAME,
                points=batch,
                wait=True,
            )

        print(
            f"Stored {len(points)} embeddings in Qdrant."
        )
        print(f"PDF ID {pdf_id} processed successfully.")

        return len(chunks)

    except Exception:
        if conn:
            conn.rollback()

        raise

    finally:
        if cursor:
            cursor.close()

        if conn:
            conn.close()

setup_collection()
