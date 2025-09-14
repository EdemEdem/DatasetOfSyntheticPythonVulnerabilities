from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import psycopg2

app = FastAPI()

conn = psycopg2.connect(
    host="localhost",
    database="mydb",
    user="myuser",
    password="mypassword"
)

class LoginRequest(BaseModel):
    username: str
    password: str

@app.post("/login")
def login(req: LoginRequest):
    username = req.username
    password = req.password

    cur = conn.cursor()
    query = "SELECT id FROM users WHERE username = %s AND password = %s"
    cur.execute(query, (username, password))
    row = cur.fetchone()
    cur.close()

    if row:
        return {"status": "ok", "user_id": row[0]}
    else:
        raise HTTPException(status_code=401, detail="unauthorized")
