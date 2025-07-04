import subprocess
import os
from django.shortcuts import render

def list_directory(request):
    path = request.GET.get("path", "")
    output = ""
    if path:
        # Build the platform‐specific command
        if os.name == "nt":  # Windows
            
            cmd = f"dir {path.replace("/","\\")}"
        else:                # Linux / macOS
            cmd = f"ls -la {path}"

        try:
            # STILL VULNERABLE to injection on both platforms
            output_bytes = subprocess.check_output(cmd, shell=True)
            output = output_bytes.decode("utf-8", errors="ignore")
        except subprocess.CalledProcessError as e:
            output = f"Error listing directory: {e}"
    return render(request, "browse_app/list.html", {
        "path": path,
        "output": output,
    })


'''import subprocess
from django.http import HttpResponse
from django.shortcuts import render

def list_directory(request):
    """
    Vulnerable view: takes raw 'path' GET parameter and
    passes it directly into a shell ls command.
    """
    path = request.GET.get("path", "")
    output = ""
    if path:
        # OS command injection vulnerability here:
        # shell=True + f-string interpolation
        try:
            output_bytes = subprocess.check_output(f"cmd.exe /c dir {path}", shell=True)
            output = output_bytes.decode("utf-8", errors="ignore")
        except subprocess.CalledProcessError as e:
            output = f"Error listing directory: {e}"
    return render(request, "browse_app/list.html", {
        "path": path,
        "output": output,
    })
'''