import os
from django.http import HttpResponse
from django.shortcuts import render
from django.utils.html import escape

def list_directory(request):
    """
    Safe view: validates that 'path' is an existing directory
    and uses os.listdir() to avoid shell invocation entirely.
    """
    path = request.GET.get("path", "")
    output = ""
    error = None

    if path:
        # Reject any metacharacters
        forbidden = set(";|&`$><")
        if any((c in forbidden) for c in path):
            error = "Invalid characters in path."
        else:
            # Normalize and verify
            normalized = os.path.normpath(path)
            if os.path.isdir(normalized):
                try:
                    entries = os.listdir(normalized)
                    # Build a safe HTML listing
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
