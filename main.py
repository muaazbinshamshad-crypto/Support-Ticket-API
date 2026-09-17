import os
from datetime import datetime, timedelta, timezone

import psycopg2
from dotenv import load_dotenv
from fastapi import Depends, FastAPI, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt
from pydantic import BaseModel, EmailStr
from pwdlib import PasswordHash


load_dotenv()

app = FastAPI(title="Support Ticket API")


# =========================
# JWT SETTINGS
# =========================

JWT_SECRET_KEY = os.getenv(
    "JWT_SECRET_KEY",
    "change-this-to-a-long-random-secret-key"
)

ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

password_hash = PasswordHash.recommended()
security = HTTPBearer()


# =========================
# DATABASE CONNECTION
# =========================

def get_connection():
    return psycopg2.connect(
        host=os.getenv("DB_HOST"),
        database=os.getenv("DB_NAME"),
        user=os.getenv("DB_USER"),
        password=os.getenv("DB_PASSWORD"),
        port=os.getenv("DB_PORT")
    )


# =========================
# CREATE DATABASE TABLES
# =========================

def create_tables():
    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            email VARCHAR(255) UNIQUE NOT NULL,
            password VARCHAR(255) NOT NULL,
            role VARCHAR(50) NOT NULL DEFAULT 'customer'
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS tickets (
            id SERIAL PRIMARY KEY,
            title VARCHAR(255) NOT NULL,
            description TEXT NOT NULL,
            status VARCHAR(50) NOT NULL DEFAULT 'OPEN',
            priority VARCHAR(50) NOT NULL DEFAULT 'MEDIUM',
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS comments (
            id SERIAL PRIMARY KEY,
            content TEXT NOT NULL,
            ticket_id INTEGER NOT NULL REFERENCES tickets(id) ON DELETE CASCADE,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE
        )
    """)

    connection.commit()
    cursor.close()
    connection.close()

    print("Database tables are ready!")


# =========================
# PASSWORD FUNCTIONS
# =========================

def hash_password(password: str):
    return password_hash.hash(password)


def verify_password(password: str, hashed_password: str):
    return password_hash.verify(password, hashed_password)


# =========================
# JWT FUNCTIONS
# =========================

def create_access_token(user_id: int, email: str, role: str):
    expire = datetime.now(timezone.utc) + timedelta(
        minutes=ACCESS_TOKEN_EXPIRE_MINUTES
    )

    payload = {
        "sub": str(user_id),
        "email": email,
        "role": role,
        "exp": expire
    }

    return jwt.encode(
        payload,
        JWT_SECRET_KEY,
        algorithm=ALGORITHM
    )


def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    token = credentials.credentials

    try:
        payload = jwt.decode(
            token,
            JWT_SECRET_KEY,
            algorithms=[ALGORITHM]
        )

        user_id = payload.get("sub")
        email = payload.get("email")
        role = payload.get("role")

        if user_id is None or email is None or role is None:
            raise HTTPException(
                status_code=401,
                detail="Invalid token"
            )

        return {
            "id": int(user_id),
            "email": email,
            "role": role
        }

    except (JWTError, ValueError):
        raise HTTPException(
            status_code=401,
            detail="Invalid or expired token"
        )


# =========================
# REQUEST MODELS
# =========================

class RegisterRequest(BaseModel):
    email: EmailStr
    password: str


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class TicketCreateRequest(BaseModel):
    title: str
    description: str
    priority: str = "MEDIUM"


class TicketUpdateRequest(BaseModel):
    title: str
    description: str
    status: str
    priority: str


class CommentCreateRequest(BaseModel):
    content: str


# =========================
# STARTUP
# =========================

@app.on_event("startup")
def startup():
    try:
        create_tables()
        print("Support Ticket API connected to PostgreSQL!")
    except Exception as error:
        print("Database error:", error)


# =========================
# HOME
# =========================

@app.get("/")
def home():
    return {
        "message": "Support Ticket API is running!"
    }


# =========================
# REGISTER
# =========================

@app.post("/users/register")
def register(user: RegisterRequest):

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute(
        "SELECT id FROM users WHERE email = %s",
        (user.email,)
    )

    existing_user = cursor.fetchone()

    if existing_user:
        cursor.close()
        connection.close()

        raise HTTPException(
            status_code=400,
            detail="User with this email already exists"
        )

    hashed_password = hash_password(user.password)

    cursor.execute(
        """
        INSERT INTO users (email, password, role)
        VALUES (%s, %s, %s)
        RETURNING id, email, role
        """,
        (
            user.email,
            hashed_password,
            "customer"
        )
    )

    new_user = cursor.fetchone()

    connection.commit()

    cursor.close()
    connection.close()

    return {
        "message": "User registered successfully!",
        "user": {
            "id": new_user[0],
            "email": new_user[1],
            "role": new_user[2]
        }
    }


# =========================
# LOGIN
# =========================

@app.post("/users/login")
def login(user: LoginRequest):

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT id, email, password, role
        FROM users
        WHERE email = %s
        """,
        (user.email,)
    )

    database_user = cursor.fetchone()

    cursor.close()
    connection.close()

    if not database_user:
        raise HTTPException(
            status_code=401,
            detail="Invalid email or password"
        )

    user_id, email, hashed_password, role = database_user

    if not verify_password(user.password, hashed_password):
        raise HTTPException(
            status_code=401,
            detail="Invalid email or password"
        )

    access_token = create_access_token(
        user_id,
        email,
        role
    )

    return {
        "access_token": access_token,
        "token_type": "bearer"
    }


# =========================
# CURRENT USER
# =========================

@app.get("/users/me")
def get_me(current_user=Depends(get_current_user)):
    return current_user


# =========================
# CREATE TICKET
# =========================

@app.post("/tickets")
def create_ticket(
    ticket: TicketCreateRequest,
    current_user=Depends(get_current_user)
):

    title = ticket.title.strip()
    description = ticket.description.strip()
    priority = ticket.priority.upper().strip()

    if not title:
        raise HTTPException(
            status_code=400,
            detail="Ticket title cannot be empty"
        )

    if not description:
        raise HTTPException(
            status_code=400,
            detail="Ticket description cannot be empty"
        )

    if priority not in ["LOW", "MEDIUM", "HIGH"]:
        raise HTTPException(
            status_code=400,
            detail="Priority must be LOW, MEDIUM, or HIGH"
        )

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute(
        """
        INSERT INTO tickets
        (title, description, status, priority, user_id)
        VALUES (%s, %s, %s, %s, %s)
        RETURNING id, title, description, status, priority, user_id
        """,
        (
            title,
            description,
            "OPEN",
            priority,
            current_user["id"]
        )
    )

    new_ticket = cursor.fetchone()

    connection.commit()

    cursor.close()
    connection.close()

    return {
        "id": new_ticket[0],
        "title": new_ticket[1],
        "description": new_ticket[2],
        "status": new_ticket[3],
        "priority": new_ticket[4],
        "user_id": new_ticket[5]
    }


# =========================
# GET ALL USER TICKETS
# =========================

@app.get("/tickets")
def get_tickets(current_user=Depends(get_current_user)):

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT id, title, description, status, priority, user_id
        FROM tickets
        WHERE user_id = %s
        ORDER BY id DESC
        """,
        (current_user["id"],)
    )

    tickets = cursor.fetchall()

    cursor.close()
    connection.close()

    result = []

    for ticket in tickets:
        result.append({
            "id": ticket[0],
            "title": ticket[1],
            "description": ticket[2],
            "status": ticket[3],
            "priority": ticket[4],
            "user_id": ticket[5]
        })

    return {
        "tickets": result
    }


# =========================
# GET SINGLE TICKET
# =========================

@app.get("/tickets/{ticket_id}")
def get_ticket(
    ticket_id: int,
    current_user=Depends(get_current_user)
):

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT id, title, description, status, priority, user_id
        FROM tickets
        WHERE id = %s
        """,
        (ticket_id,)
    )

    ticket = cursor.fetchone()

    cursor.close()
    connection.close()

    if not ticket:
        raise HTTPException(
            status_code=404,
            detail="Ticket not found"
        )

    if ticket[5] != current_user["id"]:
        raise HTTPException(
            status_code=403,
            detail="You do not have permission to access this ticket"
        )

    return {
        "id": ticket[0],
        "title": ticket[1],
        "description": ticket[2],
        "status": ticket[3],
        "priority": ticket[4],
        "user_id": ticket[5]
    }


# =========================
# UPDATE TICKET
# =========================

@app.put("/tickets/{ticket_id}")
def update_ticket(
    ticket_id: int,
    ticket: TicketUpdateRequest,
    current_user=Depends(get_current_user)
):

    title = ticket.title.strip()
    description = ticket.description.strip()
    status = ticket.status.upper().strip()
    priority = ticket.priority.upper().strip()

    if not title:
        raise HTTPException(
            status_code=400,
            detail="Ticket title cannot be empty"
        )

    if not description:
        raise HTTPException(
            status_code=400,
            detail="Ticket description cannot be empty"
        )

    if status not in [
        "OPEN",
        "IN_PROGRESS",
        "RESOLVED",
        "CLOSED"
    ]:
        raise HTTPException(
            status_code=400,
            detail="Status must be OPEN, IN_PROGRESS, RESOLVED, or CLOSED"
        )

    if priority not in ["LOW", "MEDIUM", "HIGH"]:
        raise HTTPException(
            status_code=400,
            detail="Priority must be LOW, MEDIUM, or HIGH"
        )

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT user_id
        FROM tickets
        WHERE id = %s
        """,
        (ticket_id,)
    )

    existing_ticket = cursor.fetchone()

    if not existing_ticket:
        cursor.close()
        connection.close()

        raise HTTPException(
            status_code=404,
            detail="Ticket not found"
        )

    if existing_ticket[0] != current_user["id"]:
        cursor.close()
        connection.close()

        raise HTTPException(
            status_code=403,
            detail="You do not have permission to update this ticket"
        )

    cursor.execute(
        """
        UPDATE tickets
        SET title = %s,
            description = %s,
            status = %s,
            priority = %s
        WHERE id = %s
        RETURNING id, title, description, status, priority, user_id
        """,
        (
            title,
            description,
            status,
            priority,
            ticket_id
        )
    )

    updated_ticket = cursor.fetchone()

    connection.commit()

    cursor.close()
    connection.close()

    return {
        "message": "Ticket updated successfully!",
        "ticket": {
            "id": updated_ticket[0],
            "title": updated_ticket[1],
            "description": updated_ticket[2],
            "status": updated_ticket[3],
            "priority": updated_ticket[4],
            "user_id": updated_ticket[5]
        }
    }


# =========================
# ADD COMMENT
# =========================

@app.post("/tickets/{ticket_id}/comments")
def add_comment(
    ticket_id: int,
    comment: CommentCreateRequest,
    current_user=Depends(get_current_user)
):

    content = comment.content.strip()

    if not content:
        raise HTTPException(
            status_code=400,
            detail="Comment cannot be empty"
        )

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT user_id
        FROM tickets
        WHERE id = %s
        """,
        (ticket_id,)
    )

    ticket = cursor.fetchone()

    if not ticket:
        cursor.close()
        connection.close()

        raise HTTPException(
            status_code=404,
            detail="Ticket not found"
        )

    if ticket[0] != current_user["id"]:
        cursor.close()
        connection.close()

        raise HTTPException(
            status_code=403,
            detail="You do not have permission to comment on this ticket"
        )

    cursor.execute(
        """
        INSERT INTO comments (content, ticket_id, user_id)
        VALUES (%s, %s, %s)
        RETURNING id, content, ticket_id, user_id
        """,
        (
            content,
            ticket_id,
            current_user["id"]
        )
    )

    new_comment = cursor.fetchone()

    connection.commit()

    cursor.close()
    connection.close()

    return {
        "message": "Comment added successfully!",
        "comment": {
            "id": new_comment[0],
            "content": new_comment[1],
            "ticket_id": new_comment[2],
            "user_id": new_comment[3]
        }
    }


# =========================
# GET TICKET COMMENTS
# =========================

@app.get("/tickets/{ticket_id}/comments")
def get_comments(
    ticket_id: int,
    current_user=Depends(get_current_user)
):

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT user_id
        FROM tickets
        WHERE id = %s
        """,
        (ticket_id,)
    )

    ticket = cursor.fetchone()

    if not ticket:
        cursor.close()
        connection.close()

        raise HTTPException(
            status_code=404,
            detail="Ticket not found"
        )

    if ticket[0] != current_user["id"]:
        cursor.close()
        connection.close()

        raise HTTPException(
            status_code=403,
            detail="You do not have permission to view comments on this ticket"
        )

    cursor.execute(
        """
        SELECT id, content, ticket_id, user_id
        FROM comments
        WHERE ticket_id = %s
        ORDER BY id ASC
        """,
        (ticket_id,)
    )

    comments = cursor.fetchall()

    cursor.close()
    connection.close()

    result = []

    for comment in comments:
        result.append({
            "id": comment[0],
            "content": comment[1],
            "ticket_id": comment[2],
            "user_id": comment[3]
        })

    return {
        "comments": result
    }