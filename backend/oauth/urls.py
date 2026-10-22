"""Well-known endpoints (outside /api/): JWKS now, authorization server metadata later."""

from django.urls import path

from oauth import views

urlpatterns = [
    path(".well-known/jwks.json", views.jwks, name="jwks"),
]
