# Safe FastAPI shell executor with an allow-list (mitigates CWE-78)

import subprocess
from fastapi import FastAPI, Request, HTTPException, status

app = FastAPI()

# Define which commands are allowed (no arguments, no chaining)
ALLOWED_CMDS = {
    "systeminfo",
    "whoami",
}

@app.post("/run")
async def run_cmd(request: Request):
    # Parse JSON body
    data = await request.json()
    cmd = data.get("cmd", "").strip()

    # Check that the command is exactly one of our allowed commands
    if cmd not in ALLOWED_CMDS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="command not allowed"
        )
    # Safely execute: no shell, args as list
    try:
        completed = subprocess.run(
            [cmd],
            check=True,
            capture_output=True,
            text=True
        )
    except subprocess.CalledProcessError as e:
        # Command existed but failed
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"command failed: {e}"
        )

    # Return stdout
    return {"output": completed.stdout}
