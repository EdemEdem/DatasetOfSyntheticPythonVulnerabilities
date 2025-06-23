# Vulnerable FastAPI shell executor (CWE-78)
# WARNING: This code is intentionally insecure!

import os
from fastapi import FastAPI, Request

app = FastAPI()

@app.post("/run")
async def run_cmd(request: Request):
    # Parse JSON body
    data = await request.json()
    cmd = data.get("cmd", "")
    # Directly invoke shell on unvalidated input
    result = os.popen(cmd).read()
    return {"output": result}
