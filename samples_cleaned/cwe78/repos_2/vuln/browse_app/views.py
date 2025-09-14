import subprocess
import os
from django.shortcuts import render

def list_directory(request):
    path = request.GET.get("path", "")
    output = ""
    if path:
        if os.name == "nt":  # Windows
            
            cmd = f"dir {path.replace("/","\\")}"
        else:                # Linux / macOS
            cmd = f"ls -la {path}"

        try:
            output_bytes = subprocess.check_output(cmd, shell=True)
            output = output_bytes.decode("utf-8", errors="ignore")
        except subprocess.CalledProcessError as e:
            output = f"Error listing directory: {e}"
    return render(request, "browse_app/list.html", {
        "path": path,
        "output": output,
    })


