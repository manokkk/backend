# scanner/urls.py

from django.urls import path
from . import views

urlpatterns = [
    path('scan/', views.perform_scan, name='perform_scan'),  # Use '/scan/' relative to '/api/'
]
