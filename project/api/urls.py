from django.urls import path
from .views import RegisterView, LoginView, UserView, LogoutView, UserChangePasswordView, SendPasswordResetEmailView, UserPasswordResetView

urlpatterns = [
    path('register/', RegisterView.as_view()),
    path('login/', LoginView.as_view()),
    path('user/', UserView.as_view()),
    path('logout/', LogoutView.as_view()),
    path('changepassword/', UserChangePasswordView.as_view()),
    path('send-reset-password-email/', SendPasswordResetEmailView.as_view()),
    path('reset-password/<uid>/<token>/', UserPasswordResetView.as_view()),
]