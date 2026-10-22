"""OAuth endpoints outside /api/: well-known documents and client registration."""

from django.urls import path

from oauth import views

urlpatterns = [
    path(".well-known/jwks.json", views.jwks, name="jwks"),
    path(
        ".well-known/oauth-authorization-server",
        views.authorization_server_metadata_view,
        name="oauth-authorization-server",
    ),
    path("register", views.register, name="register"),
]
