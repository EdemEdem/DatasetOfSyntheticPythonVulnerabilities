from django.urls import path
from browse_app.views import list_directory

urlpatterns = [
    path("", list_directory, name="list_directory"),
]
