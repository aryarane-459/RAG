from pydantic import BaseModel, EmailStr, Field
from typing import List

class SignupRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=6, max_length=72)
    role:str

class LoginRequest(BaseModel):
    email: EmailStr
    password: str

class GrantAccessRequest(BaseModel):
    pdf_id: int
    uid: int

class AskRequest(BaseModel):
    pdf_id: int | None = None
    question: str

class AssigRoleRequest(BaseModel):
    uid:int
    role:str
    
class VerifyOTPRequest(BaseModel):
    email: EmailStr
    otp: str = Field(pattern=r"^\d{6}$")

class DatabaseRegisterRequest(BaseModel):
    database_name: str
    db_type: str = "postgresql"
    host: str
    port: int = 5432
    db_name: str
    username: str
    password: str
    assigned_user_ids: List[int] = Field(default_factory=list)


class AskDatabaseRequest(BaseModel):
    database_id: str
    question: str = Field(min_length=1)


class AskDatabaseResponse(BaseModel):
    success: bool
    question: str
    sql_query: str
    results: List[dict] = Field(default_factory=list)
    answer: str
