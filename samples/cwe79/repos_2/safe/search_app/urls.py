from django.urls import path
from .views import results

urlpatterns = [
    path("", results, name="results"),
]
