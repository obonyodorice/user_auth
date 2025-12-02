from rest_framework.throttling import AnonRateThrottle

class PasswordResetRateThrottle(AnonRateThrottle):
    """
    Limits the rate of password reset requests to prevent abuse.
    Allows 3 requests per hour for anonymous users.
    """
    scope = 'password_reset'
    
    def get_cache_key(self, request, view):
        """
        Use email address as the cache key for more precise throttling
        """
        if request.data.get('email'):
            email = request.data.get('email', '').lower()
            return f'throttle_password_reset_{email}'
        
        # Fall back to IP-based throttling if no email provided
        return super().get_cache_key(request, view)