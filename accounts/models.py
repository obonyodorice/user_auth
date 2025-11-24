import uuid
from django.db import models
from django.contrib.auth.models import AbstractUser
from django.utils import timezone
from datetime import timedelta
import secrets
from .managers import CustomUserManager

class User(AbstractUser):

    username = None
 
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    email = models.EmailField(unique=True, max_length=255)

    first_name = models.CharField(max_length=150)
    last_name = models.CharField(max_length=150)

    is_active = models.BooleanField(default=True)
    email_verified = models.BooleanField(default=False)

    failed_login_attempts = models.IntegerField(default=0)
    account_locked_until = models.DateTimeField(null=True, blank=True)
    password_changed_at = models.DateTimeField(auto_now_add=True)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    last_login = models.DateTimeField(null=True, blank=True)
    
    objects = CustomUserManager()
    
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['first_name', 'last_name']
    
    class Meta:
        db_table = 'users'
        verbose_name = 'User'
        verbose_name_plural = 'Users'
        ordering = ['-created_at']
    
    def __str__(self):
        return f"{self.email} - {self.get_full_name()}"
    
    def get_full_name(self):
        return f"{self.first_name} {self.last_name}".strip()
    
    def is_account_locked(self):
        """Check if account is currently locked"""
        if self.account_locked_until:
            if timezone.now() < self.account_locked_until:
                return True
            else:
                # Unlock account if lock period has passed
                self.account_locked_until = None
                self.failed_login_attempts = 0
                self.save()
        return False
    
    def lock_account(self, minutes=30):
        """Lock account for specified minutes"""
        self.account_locked_until = timezone.now() + timedelta(minutes=minutes)
        self.save()
    
    def reset_failed_attempts(self):
        """Reset failed login attempts counter"""
        self.failed_login_attempts = 0
        self.account_locked_until = None
        self.save()
    
    def increment_failed_attempts(self):
        """Increment failed login attempts and lock if threshold reached"""
        self.failed_login_attempts += 1
        if self.failed_login_attempts >= 5:
            self.lock_account(30)  # Lock for 30 minutes
        self.save()

class PasswordResetToken(models.Model):
    """Token for password reset"""
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='password_reset_tokens')
    token = models.CharField(max_length=255, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    used = models.BooleanField(default=False)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    
    class Meta:
        db_table = 'password_reset_tokens'
        ordering = ['-created_at']
    
    def __str__(self):
        return f"Password Reset Token for {self.user.email}"
    
    def is_valid(self):
        """Check if token is still valid"""
        return not self.used and timezone.now() < self.expires_at
    
    def mark_as_used(self):
        """Mark token as used"""
        self.used = True
        self.save()
    
    @classmethod
    def generate_token(cls, user, ip_address=None):
        """Generate a new password reset token"""
        token = secrets.token_urlsafe(32)
        expires_at = timezone.now() + timedelta(hours=1)
        return cls.objects.create(
            user=user,
            token=token,
            expires_at=expires_at,
            ip_address=ip_address
        )
