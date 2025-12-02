from django.urls import path
from .views import (
    UserRegistrationView,
    UserLoginView,
    ChangePasswordView,
    PasswordResetRequestView,
    PasswordResetConfirmView,
    # UserDetailView,
    DeleteAccountView,
    UserListView,
)

app_name = 'authentication'

urlpatterns = [
    path('register/', UserRegistrationView.as_view(), name='register'),
    path('login/', UserLoginView.as_view(), name='login'),

    path('change-password/', ChangePasswordView.as_view(), name='change-password'),
    path('password-reset/request/', PasswordResetRequestView.as_view(), name='password-reset-request'),
    path('password-reset/confirm/', PasswordResetConfirmView.as_view(), name='password-reset-confirm'),
   
   
    # path('user/', UserDetailView.as_view(), name='user-detail'),
    path('user/delete/', DeleteAccountView.as_view(), name='delete-account'),
    path('users/', UserListView.as_view(), name='user-list'),
]

