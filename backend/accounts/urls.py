from django.urls import path

from accounts import views

app_name = "accounts"

urlpatterns = [
    path("", views.home_view, name="home"),
    path("login", views.login_view, name="login"),
    path("login/totp", views.login_totp_view, name="login_totp"),
    path("totp/setup", views.totp_setup_view, name="totp_setup"),
    path("logout", views.logout_view, name="logout"),
]
