import os
from django.http import HttpResponse
from django.shortcuts import render
from django.utils.html import escape

def list_directory(request):
    path = request.GET.get("path", "")
    output = ""
    error = None

    if path:
        forbidden = set(";|&`$><")
        if any((c in forbidden) for c in path):
            error = "Invalid characters in path."
        else:
            normalized = os.path.normpath(path)
            if os.path.isdir(normalized):
                try:
                    entries = os.listdir(normalized)
                    output = "\n".join(
                        escape(entry) for entry in entries
                    )
                except Exception as e:
                    error = f"Error reading directory: {escape(str(e))}"
            else:
                error = "Provided path is not a directory."

    context = {
        "path": escape(path),
        "output": output,
        "error": error,
    }
    return render(request, "browse_app/list.html", context)
