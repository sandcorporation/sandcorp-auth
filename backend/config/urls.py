from django.conf import settings
from django.contrib import admin
from django.urls import include, path

from core.api import api

urlpatterns = [
    path(settings.ADMIN_PATH, admin.site.urls),
    path("api/", api.urls),
    path("", include("oauth.urls")),
]
