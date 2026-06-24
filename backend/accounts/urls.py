from django.urls import path
from .views import RegisterView, LoginView, MFAVerifyView

urlpatterns = [
    path('register/', RegisterView.as_view(), name='register'),
    path('login/', LoginView.as_view(), name='login'),
    path('verify-mfa/', MFAVerifyView.as_view(), name='verify-mfa'),
]
