"""OAuth endpoints outside /api/: well-known documents, client registration, authorization."""

from django.urls import path

from oauth import views
from oauth.server import AUTHORIZE_PATH, REGISTER_PATH, REVOKE_PATH, TOKEN_PATH

urlpatterns = [
    path(".well-known/jwks.json", views.jwks, name="jwks"),
    path(
        ".well-known/oauth-authorization-server",
        views.authorization_server_metadata_view,
        name="oauth-authorization-server",
    ),
    path(REGISTER_PATH.lstrip("/"), views.register, name="register"),
    path(AUTHORIZE_PATH.lstrip("/"), views.authorize, name="authorize"),
    path(TOKEN_PATH.lstrip("/"), views.token, name="token"),
    path(REVOKE_PATH.lstrip("/"), views.revoke, name="revoke"),
]
