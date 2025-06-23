from django.urls import path
from .views import results

urlpatterns = [
    # e.g. /search/?q=...
    path("", results, name="results"),
]
