from django.shortcuts import render

def results(request):
    query = request.GET.get("q", "")
    return render(request, "search_app/results.html", {"query": query})
