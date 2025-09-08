
import subprocess
from fastapi import FastAPI, Request, HTTPException, status

app = FastAPI()

ALLOWED_CMDS = {
    "systeminfo",
    "whoami",
}

@app.post("/run")
async def run_cmd(request: Request):
    data = await request.json()
    cmd = data.get("cmd", "").strip()

    if cmd not in ALLOWED_CMDS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="command not allowed"
        )
    try:
        completed = subprocess.run(
            [cmd],
            check=True,
            capture_output=True,
            text=True
        )
    except subprocess.CalledProcessError as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"command failed: {e}"
        )

    return {"output": completed.stdout}
