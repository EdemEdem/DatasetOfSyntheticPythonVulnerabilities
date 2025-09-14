from django.shortcuts import render
from django.utils.safestring import mark_safe

def results(request):
    query = request.GET.get("q", "")
    print(query)
    header = mark_safe(query)
    return render(request, "search_app/results.html", {"header": header})
