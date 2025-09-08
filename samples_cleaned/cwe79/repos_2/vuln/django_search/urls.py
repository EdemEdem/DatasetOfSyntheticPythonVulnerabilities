from django.urls import path, include

urlpatterns = [
    path("", include("search_app.urls")),
    path("search/", include("search_app.urls")),
]
