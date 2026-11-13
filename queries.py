import psycopg2
import os
from dotenv import load_dotenv

load_dotenv()
DB_NAME = os.getenv("DB_NAME")
DB_USER = os.getenv("DB_USER")
DB_PASS = os.getenv("DB_PASS")
DB_HOST = os.getenv("DB_HOST")
DB_PORT = os.getenv("DB_PORT")

try:
    conn = psycopg2.connect(
    database= DB_NAME,
    user=DB_USER,
    password=DB_PASS,
    host=DB_HOST,
    port= DB_PORT
    )
    print("database connected succesfully")
except Exception as e:
    print("database connection failed")
    exit()
cur = conn.cursor()

cur.execute(
    """

    CREATE TABLE IF NOT EXISTS login_otps (
    email VARCHAR(255) PRIMARY KEY,
    otp_hash VARCHAR(64) NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
    """
)
conn.commit()

print("The table is created succesfully ")
cur.close()
conn.close()

      
#     CREATE TABLE roles (
#     role_id SERIAL PRIMARY KEY,
#     role_name VARCHAR(50) UNIQUE NOT NULL
#     );


#     CREATE TABLE users (
#     uid SERIAL PRIMARY KEY,
#     role_id INTEGER NOT NULL,
#     email VARCHAR(255) UNIQUE NOT NULL,
#     password VARCHAR(255) NOT NULL,

#     CONSTRAINT fk_user_role
#         FOREIGN KEY (role_id)
#         REFERENCES roles(role_id)
#     );


#     CREATE TABLE documents (
#     pdf_id SERIAL PRIMARY KEY,
#     filename VARCHAR(255) NOT NULL,
#     pdf_path TEXT NOT NULL,
#     uploaded_by INTEGER NOT NULL,
#     uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

#     CONSTRAINT fk_document_uploader
#         FOREIGN KEY (uploaded_by)
#         REFERENCES users(uid)
# );


#     CREATE TABLE chunks (
#     chunk_id SERIAL PRIMARY KEY,
#     pdf_id INTEGER NOT NULL,
#     chunk_number INTEGER NOT NULL,
#     chunk_text TEXT NOT NULL,

#     CONSTRAINT fk_chunk_document
#         FOREIGN KEY (pdf_id)
#         REFERENCES documents(pdf_id)
#         ON DELETE CASCADE
# );

#     CREATE TABLE user_access (
#     access_id SERIAL PRIMARY KEY,
#     pdf_id INTEGER NOT NULL,
#     uid INTEGER NOT NULL,
#     granted_by INTEGER NOT NULL,
#     granted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

#     CONSTRAINT fk_access_document
#         FOREIGN KEY (pdf_id)
#         REFERENCES documents(pdf_id)
#         ON DELETE CASCADE,

#     CONSTRAINT fk_access_user
#         FOREIGN KEY (uid)
#         REFERENCES users(uid)
#         ON DELETE CASCADE,

#     CONSTRAINT fk_access_granted_by
#         FOREIGN KEY (granted_by)
#         REFERENCES users(uid),

#     CONSTRAINT unique_user_pdf
#         UNIQUE (pdf_id, uid)
#         );


#     CREATE TABLE questions (
#     question_id SERIAL PRIMARY KEY,
#     uid INTEGER NOT NULL,
#     pdf_id INTEGER NOT NULL,
#     question TEXT NOT NULL,
#     answer TEXT NOT NULL,
#     asked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

#     CONSTRAINT fk_question_user
#         FOREIGN KEY (uid)
#         REFERENCES users(uid)
#         ON DELETE CASCADE,

#     CONSTRAINT fk_question_document
#         FOREIGN KEY (pdf_id)
#         REFERENCES documents(pdf_id)
#         ON DELETE CASCADE
#     );

#     CREATE TABLE refresh_tokens (
#     token_id SERIAL PRIMARY KEY,
#     uid INTEGER NOT NULL,
#     token_hash VARCHAR(255) NOT NULL,
#     expires_at TIMESTAMP NOT NULL,
#     created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
#     revoked BOOLEAN DEFAULT FALSE,

#     CONSTRAINT fk_refresh_user
#         FOREIGN KEY (uid)
#         REFERENCES users(uid)
#         ON DELETE CASCADE
# );