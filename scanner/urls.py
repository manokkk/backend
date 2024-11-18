# scanner/urls.py

from django.urls import path
from . import views
from .views import health_check

urlpatterns = [
      path('health/', health_check, name='health_check'),
    path('scan/', views.perform_scan, name='perform_scan'),  # Use '/scan/' relative to '/api/'
]
