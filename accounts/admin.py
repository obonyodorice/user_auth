from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from django.utils.html import format_html
from django.utils import timezone
from django.db.models import Q
from .models import User, EmailVerificationToken, PasswordResetToken, LoginHistory


@admin.register(User)
class UserAdmin(BaseUserAdmin):
    """Enhanced admin interface for User model"""
    
    list_display = [
        'email', 'full_name_display', 'email_verified_badge',
        'is_active_badge', 'is_staff', 'account_status',
        'last_login', 'created_at'
    ]
    list_filter = [
        'is_active', 'is_staff', 'is_superuser',
        'email_verified', 'phone_verified',
        'created_at', 'last_login'
    ]
    search_fields = ['email', 'first_name', 'last_name', 'phone_number']
    ordering = ['-created_at']
    readonly_fields = [
        'id', 'created_at', 'updated_at', 'last_login',
        'password_changed_at', 'failed_login_attempts',
        'account_locked_until', 'last_login_ip'
    ]
    
    fieldsets = (
        ('Authentication', {
            'fields': ('id', 'email', 'password')
        }),
        ('Personal Information', {
            'fields': (
                'first_name', 'last_name', 'phone_number',
                'date_of_birth', 'profile_picture', 'bio'
            )
        }),
        ('Verification Status', {
            'fields': ('email_verified', 'phone_verified')
        }),
        ('Permissions', {
            'fields': (
                'is_active', 'is_staff', 'is_superuser',
                'groups', 'user_permissions'
            )
        }),
        ('Security Information', {
            'fields': (
                'failed_login_attempts', 'account_locked_until',
                'last_login_ip', 'password_changed_at'
            ),
            'classes': ('collapse',)
        }),
        ('Important Dates', {
            'fields': ('last_login', 'created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )
    
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': (
                'email', 'password1', 'password2',
                'first_name', 'last_name', 'phone_number',
                'is_active', 'is_staff', 'is_superuser'
            ),
        }),
    )
    
    def full_name_display(self, obj):
        """Display full name"""
        return obj.get_full_name()
    full_name_display.short_description = 'Full Name'
    
    def email_verified_badge(self, obj):
        """Display email verification status with badge"""
        if obj.email_verified:
            return format_html(
                '<span style="background-color: #28a745; color: white; '
                'padding: 3px 10px; border-radius: 3px;">✓ Verified</span>'
            )
        return format_html(
            '<span style="background-color: #ffc107; color: black; '
            'padding: 3px 10px; border-radius: 3px;">⚠ Unverified</span>'
        )
    email_verified_badge.short_description = 'Email Status'
    
    def is_active_badge(self, obj):
        """Display active status with badge"""
        if obj.is_active:
            return format_html(
                '<span style="background-color: #28a745; color: white; '
                'padding: 3px 10px; border-radius: 3px;">Active</span>'
            )
        return format_html(
            '<span style="background-color: #dc3545; color: white; '
            'padding: 3px 10px; border-radius: 3px;">Inactive</span>'
        )
    is_active_badge.short_description = 'Status'
    
    def account_status(self, obj):
        """Display account lock status"""
        if obj.is_account_locked():
            time_left = obj.account_locked_until - timezone.now()
            minutes = int(time_left.total_seconds() / 60)
            return format_html(
                '<span style="background-color: #dc3545; color: white; '
                'padding: 3px 10px; border-radius: 3px;">🔒 Locked ({} min)</span>',
                minutes
            )
        elif obj.failed_login_attempts > 0:
            return format_html(
                '<span style="background-color: #ffc107; color: black; '
                'padding: 3px 10px; border-radius: 3px;">⚠ {} Failed</span>',
                obj.failed_login_attempts
            )
        return format_html(
            '<span style="background-color: #28a745; color: white; '
            'padding: 3px 10px; border-radius: 3px;">✓ Good</span>'
        )
    account_status.short_description = 'Security'
    
    actions = [
        'verify_email', 'unverify_email',
        'activate_users', 'deactivate_users',
        'unlock_accounts', 'reset_failed_attempts'
    ]
    
    def verify_email(self, request, queryset):
        """Verify selected users' emails"""
        updated = queryset.update(email_verified=True)
        self.message_user(request, f'{updated} user(s) email verified.')
    verify_email.short_description = 'Verify email for selected users'
    
    def unverify_email(self, request, queryset):
        """Unverify selected users' emails"""
        updated = queryset.update(email_verified=False)
        self.message_user(request, f'{updated} user(s) email unverified.')
    unverify_email.short_description = 'Unverify email for selected users'
    
    def activate_users(self, request, queryset):
        """Activate selected users"""
        updated = queryset.update(is_active=True)
        self.message_user(request, f'{updated} user(s) activated.')
    activate_users.short_description = 'Activate selected users'
    
    def deactivate_users(self, request, queryset):
        """Deactivate selected users"""
        updated = queryset.update(is_active=False)
        self.message_user(request, f'{updated} user(s) deactivated.')
    deactivate_users.short_description = 'Deactivate selected users'
    
    def unlock_accounts(self, request, queryset):
        """Unlock selected user accounts"""
        updated = queryset.update(
            account_locked_until=None,
            failed_login_attempts=0
        )
        self.message_user(request, f'{updated} account(s) unlocked.')
    unlock_accounts.short_description = 'Unlock selected accounts'
    
    def reset_failed_attempts(self, request, queryset):
        """Reset failed login attempts"""
        updated = queryset.update(failed_login_attempts=0)
        self.message_user(request, f'Failed attempts reset for {updated} user(s).')
    reset_failed_attempts.short_description = 'Reset failed login attempts'


@admin.register(EmailVerificationToken)
class EmailVerificationTokenAdmin(admin.ModelAdmin):
    """Admin interface for Email Verification Tokens"""
    
    list_display = [
        'user_email', 'token_preview', 'status_badge',
        'created_at', 'expires_at', 'time_remaining'
    ]
    list_filter = ['used', 'created_at', 'expires_at']
    search_fields = ['user__email', 'token']
    readonly_fields = ['id', 'user', 'token', 'created_at', 'expires_at', 'used']
    ordering = ['-created_at']
    
    def user_email(self, obj):
        """Display user email"""
        return obj.user.email
    user_email.short_description = 'User Email'
    user_email.admin_order_field = 'user__email'
    
    def token_preview(self, obj):
        """Display truncated token"""
        return f"{obj.token[:20]}..."
    token_preview.short_description = 'Token'
    
    def status_badge(self, obj):
        """Display token status with badge"""
        if obj.used:
            return format_html(
                '<span style="background-color: #6c757d; color: white; '
                'padding: 3px 10px; border-radius: 3px;">Used</span>'
            )
        elif obj.is_valid():
            return format_html(
                '<span style="background-color: #28a745; color: white; '
                'padding: 3px 10px; border-radius: 3px;">Valid</span>'
            )
        else:
            return format_html(
                '<span style="background-color: #dc3545; color: white; '
                'padding: 3px 10px; border-radius: 3px;">Expired</span>'
            )
    status_badge.short_description = 'Status'
    
    def time_remaining(self, obj):
        """Display time remaining until expiration"""
        if obj.used:
            return "N/A (Used)"
        
        time_left = obj.expires_at - timezone.now()
        if time_left.total_seconds() <= 0:
            return "Expired"
        
        hours = int(time_left.total_seconds() / 3600)
        minutes = int((time_left.total_seconds() % 3600) / 60)
        return f"{hours}h {minutes}m"
    time_remaining.short_description = 'Time Left'
    
    def has_add_permission(self, request):
        """Disable manual token creation"""
        return False
    
    actions = ['mark_as_used', 'delete_expired_tokens']
    
    def mark_as_used(self, request, queryset):
        """Mark selected tokens as used"""
        updated = queryset.update(used=True)
        self.message_user(request, f'{updated} token(s) marked as used.')
    mark_as_used.short_description = 'Mark selected tokens as used'
    
    def delete_expired_tokens(self, request, queryset):
        """Delete expired tokens"""
        expired = queryset.filter(
            Q(expires_at__lt=timezone.now()) | Q(used=True)
        )
        count = expired.count()
        expired.delete()
        self.message_user(request, f'{count} expired/used token(s) deleted.')
    delete_expired_tokens.short_description = 'Delete expired/used tokens'


@admin.register(PasswordResetToken)
class PasswordResetTokenAdmin(admin.ModelAdmin):
    """Admin interface for Password Reset Tokens"""
    
    list_display = [
        'user_email', 'token_preview', 'status_badge',
        'ip_address', 'created_at', 'expires_at', 'time_remaining'
    ]
    list_filter = ['used', 'created_at', 'expires_at']
    search_fields = ['user__email', 'token', 'ip_address']
    readonly_fields = [
        'id', 'user', 'token', 'created_at',
        'expires_at', 'used', 'ip_address'
    ]
    ordering = ['-created_at']
    
    def user_email(self, obj):
        """Display user email"""
        return obj.user.email
    user_email.short_description = 'User Email'
    user_email.admin_order_field = 'user__email'
    
    def token_preview(self, obj):
        """Display truncated token"""
        return f"{obj.token[:20]}..."
    token_preview.short_description = 'Token'
    
    def status_badge(self, obj):
        """Display token status with badge"""
        if obj.used:
            return format_html(
                '<span style="background-color: #6c757d; color: white; '
                'padding: 3px 10px; border-radius: 3px;">Used</span>'
            )
        elif obj.is_valid():
            return format_html(
                '<span style="background-color: #28a745; color: white; '
                'padding: 3px 10px; border-radius: 3px;">Valid</span>'
            )
        else:
            return format_html(
                '<span style="background-color: #dc3545; color: white; '
                'padding: 3px 10px; border-radius: 3px;">Expired</span>'
            )
    status_badge.short_description = 'Status'
    
    def time_remaining(self, obj):
        """Display time remaining until expiration"""
        if obj.used:
            return "N/A (Used)"
        
        time_left = obj.expires_at - timezone.now()
        if time_left.total_seconds() <= 0:
            return "Expired"
        
        minutes = int(time_left.total_seconds() / 60)
        return f"{minutes} min"
    time_remaining.short_description = 'Time Left'
    
    def has_add_permission(self, request):
        """Disable manual token creation"""
        return False
    
    actions = ['mark_as_used', 'delete_expired_tokens']
    
    def mark_as_used(self, request, queryset):
        """Mark selected tokens as used"""
        updated = queryset.update(used=True)
        self.message_user(request, f'{updated} token(s) marked as used.')
    mark_as_used.short_description = 'Mark selected tokens as used'
    
    def delete_expired_tokens(self, request, queryset):
        """Delete expired tokens"""
        expired = queryset.filter(
            Q(expires_at__lt=timezone.now()) | Q(used=True)
        )
        count = expired.count()
        expired.delete()
        self.message_user(request, f'{count} expired/used token(s) deleted.')
    delete_expired_tokens.short_description = 'Delete expired/used tokens'


@admin.register(LoginHistory)
class LoginHistoryAdmin(admin.ModelAdmin):
    """Admin interface for Login History"""
    
    list_display = [
        'user_email', 'success_badge', 'ip_address',
        'login_time', 'logout_time', 'session_duration'
    ]
    list_filter = ['success', 'login_time', 'logout_time']
    search_fields = ['user__email', 'ip_address', 'user_agent']
    readonly_fields = [
        'id', 'user', 'ip_address', 'user_agent',
        'login_time', 'logout_time', 'success'
    ]
    ordering = ['-login_time']
    date_hierarchy = 'login_time'
    
    def user_email(self, obj):
        """Display user email"""
        return obj.user.email
    user_email.short_description = 'User Email'
    user_email.admin_order_field = 'user__email'
    
    def success_badge(self, obj):
        """Display success status with badge"""
        if obj.success:
            return format_html(
                '<span style="background-color: #28a745; color: white; '
                'padding: 3px 10px; border-radius: 3px;">✓ Success</span>'
            )
        return format_html(
            '<span style="background-color: #dc3545; color: white; '
            'padding: 3px 10px; border-radius: 3px;">✗ Failed</span>'
        )
    success_badge.short_description = 'Status'
    
    def session_duration(self, obj):
        """Calculate and display session duration"""
        if obj.logout_time and obj.login_time:
            duration = obj.logout_time - obj.login_time
            hours = int(duration.total_seconds() / 3600)
            minutes = int((duration.total_seconds() % 3600) / 60)
            return f"{hours}h {minutes}m"
        elif obj.success:
            return "Still active"
        return "N/A"
    session_duration.short_description = 'Duration'
    
    def has_add_permission(self, request):
        """Disable manual history creation"""
        return False
    
    def has_change_permission(self, request, obj=None):
        """Make login history read-only"""
        return False
    
    actions = ['delete_old_records']
    
    def delete_old_records(self, request, queryset):
        """Delete login records older than 90 days"""
        from datetime import timedelta
        cutoff_date = timezone.now() - timedelta(days=90)
        old_records = LoginHistory.objects.filter(login_time__lt=cutoff_date)
        count = old_records.count()
        old_records.delete()
        self.message_user(request, f'{count} old login record(s) deleted.')
    delete_old_records.short_description = 'Delete records older than 90 days'


# Customize admin site header and title
admin.site.site_header = "User Authentication Admin"
admin.site.site_title = "Auth Admin Portal"
admin.site.index_title = "Welcome to Authentication Management"