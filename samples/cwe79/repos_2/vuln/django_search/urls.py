from django.urls import path, include

urlpatterns = [
    # route all /search/ to our app
    path("", include("search_app.urls")),
    path("search/", include("search_app.urls")),
]
