from django.shortcuts import render

def results(request):
    # source of untrusted data
    query = request.GET.get("q", "")
    # SAFE: rely on Django's default autoescaping in templates
    return render(request, "search_app/results.html", {"query": query})
