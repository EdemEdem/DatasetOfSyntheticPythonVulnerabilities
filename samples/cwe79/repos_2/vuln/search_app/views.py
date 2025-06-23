from django.shortcuts import render
from django.utils.safestring import mark_safe

def results(request):
    # source of untrusted data
    query = request.GET.get("q", "")
    # VULNERABLE: disable escaping by marking the raw query as safe HTML
    print(query)
    header = mark_safe(query)
    return render(request, "search_app/results.html", {"header": header})
