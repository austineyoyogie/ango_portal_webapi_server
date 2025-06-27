from django.urls import path
from .views import (
        UserRegisterCreate, VerifyUserEmail,
        UserLoginAPIView, UserRegisterDetails,
        RequestPasswordResetEmail,
        PasswordResetConfirmTokenCheckAPI,
        SetNewPasswordAPIView
    )

app_name = 'authentication'

# http://localhost:8000/api/login/
# http://localhost:8000/api/register/

# https://www.valentinog.com/blog/testing-django/

urlpatterns = [
    path('register/', UserRegisterCreate.as_view(), name='register'),
    path('email_verify/', VerifyUserEmail.as_view(), name="email_verify"),
    path('login/', UserLoginAPIView.as_view(), name="login"),
    path('request-reset-email/', RequestPasswordResetEmail.as_view(), name="request-reset-email"),
    path('password-reset/<uidb64>/<token>/', PasswordResetConfirmTokenCheckAPI.as_view(), name="password-reset-confirm"),
    path('request-reset-complete/', SetNewPasswordAPIView.as_view(), name="request-reset-complete"),
    path('details/', UserRegisterDetails.as_view(), name='details'),
]

