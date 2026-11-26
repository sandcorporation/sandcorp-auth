from django.conf import settings
from django.contrib import admin
from django.urls import include, path

from accounts.views import admin_login_redirect
from core.api import api

handler403 = "accounts.views.forbidden"
handler404 = "accounts.views.not_found"
handler500 = "accounts.views.server_error"

urlpatterns = [
    # Before admin.site.urls so it shadows the admin's own login screen.
    path(settings.ADMIN_PATH + "login/", admin_login_redirect),
    path(settings.ADMIN_PATH, admin.site.urls),
    path("api/", api.urls),
    path("", include("accounts.urls")),
    path("", include("oauth.urls")),
]
