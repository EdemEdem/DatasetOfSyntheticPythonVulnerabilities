
import os
from fastapi import FastAPI, Request

app = FastAPI()

@app.post("/run")
async def run_cmd(request: Request):
    data = await request.json()
    cmd = data.get("cmd", "")
    result = os.popen(cmd).read()
    return {"output": result}
