from django.urls import path

from accounts import social_views, terms_views, views

app_name = "accounts"

urlpatterns = [
    path("", views.home_view, name="home"),
    path("login", views.login_view, name="login"),
    path("login/totp", views.login_totp_view, name="login_totp"),
    path("login/<str:provider>", social_views.social_start, name="social_start"),
    path("login/<str:provider>/callback", social_views.social_callback, name="social_callback"),
    path("signup/confirm", social_views.signup_confirm, name="signup_confirm"),
    path("terms", terms_views.terms, name="terms"),
    path("account", social_views.account, name="account"),
    # The old address of the same page (#36), kept so links and bookmarks still work.
    path("account/identities", social_views.account, name="identities"),
    path("account/withdraw", social_views.withdraw, name="withdraw"),
    path("account/email", social_views.set_email, name="account_email"),
    path("account/apps/<int:client_pk>/disconnect", social_views.disconnect, name="app_disconnect"),
    path("account/identities/link/<str:provider>", social_views.link_start, name="identity_link"),
    path(
        "account/identities/<int:identity_id>/unlink",
        social_views.unlink,
        name="identity_unlink",
    ),
    path("totp/setup", views.totp_setup_view, name="totp_setup"),
    path("logout", views.logout_view, name="logout"),
]
