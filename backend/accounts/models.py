from django.contrib.auth.models import AbstractUser
from django.db import models

class CustomUser(AbstractUser):
    # 'username' is inherited, but we use 'correo' as main ID
    email = models.EmailField(unique=True)
    mfa_enabled = models.BooleanField(default=False)
    mfa_secret = models.TextField(blank=True, null=True)
    
    # Lockout fields
    failed_attempts = models.IntegerField(default=0)
    is_locked = models.BooleanField(default=False)
    lockout_until = models.DateTimeField(blank=True, null=True)

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username']

    def __str__(self):
        return self.email
