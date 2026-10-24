from django.urls import path

from accounts import social_views, views

app_name = "accounts"

urlpatterns = [
    path("", views.home_view, name="home"),
    path("login", views.login_view, name="login"),
    path("login/totp", views.login_totp_view, name="login_totp"),
    path("login/<str:provider>", social_views.social_start, name="social_start"),
    path("login/<str:provider>/callback", social_views.social_callback, name="social_callback"),
    path("signup/confirm", social_views.signup_confirm, name="signup_confirm"),
    path("account/identities", social_views.identities, name="identities"),
    path("account/identities/link/<str:provider>", social_views.link_start, name="identity_link"),
    path(
        "account/identities/<int:identity_id>/unlink",
        social_views.unlink,
        name="identity_unlink",
    ),
    path("totp/setup", views.totp_setup_view, name="totp_setup"),
    path("logout", views.logout_view, name="logout"),
]
