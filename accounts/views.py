from rest_framework import status, permissions
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.authtoken.models import Token
from django.contrib.auth import login, logout
from django.utils import timezone
from django.core.mail import send_mail
from django.conf import settings
from django.db import transaction

from .models import User, EmailVerificationToken, PasswordResetToken, LoginHistory
from .serializers import (
    UserRegistrationSerializer,
    UserLoginSerializer,
    UserSerializer,
    ChangePasswordSerializer,
    PasswordResetRequestSerializer,
    PasswordResetConfirmSerializer,
    EmailVerificationSerializer,
    UserUpdateSerializer
)


def get_client_ip(request):

    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip


def send_verification_email(user, token):

    verification_url = f"{settings.FRONTEND_URL}/verify-email/{token.token}"
    subject = "Verify Your Email Address"
    message = f"""
    Hello {user.first_name},
    
    Thank you for registering! Please verify your email address by clicking the link below:
    
    {verification_url}
    
    This link will expire in 24 hours.
    
    If you didn't register for this account, please ignore this email.
    
    Best regards,
    The Team
    """
    
    send_mail(
        subject,
        message,
        settings.DEFAULT_FROM_EMAIL,
        [user.email],
        fail_silently=False,
    )


def send_password_reset_email(user, token):

    reset_url = f"{settings.FRONTEND_URL}/reset-password/{token.token}"
    subject = "Password Reset Request"
    message = f"""
    Hello {user.first_name},
    
    You requested to reset your password. Click the link below to proceed:
    
    {reset_url}
    
    This link will expire in 1 hour.
    
    If you didn't request this, please ignore this email and your password will remain unchanged.
    
    Best regards,
    The Team
    """
    
    send_mail(
        subject,
        message,
        settings.DEFAULT_FROM_EMAIL,
        [user.email],
        fail_silently=False,
    )


class UserRegistrationView(APIView):

    permission_classes = [permissions.AllowAny]
    
    def post(self, request):
        serializer = UserRegistrationSerializer(data=request.data)
        
        if serializer.is_valid():
            with transaction.atomic():
                user = serializer.save()
                
                token = EmailVerificationToken.generate_token(user)
               
                try:
                    send_verification_email(user, token)
                except Exception as e:
                    print(f"Error sending verification email: {e}")
              
                auth_token, _ = Token.objects.get_or_create(user=user)
                
                return Response({
                    'message': 'Registration successful! Please check your email to verify your account.',
                    'user': UserSerializer(user).data,
                    'token': auth_token.key
                }, status=status.HTTP_201_CREATED)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class UserLoginView(APIView):

    permission_classes = [permissions.AllowAny]
    
    def post(self, request):
        serializer = UserLoginSerializer(data=request.data)
        
        if serializer.is_valid():
            user = serializer.validated_data['user']
            user.reset_failed_attempts()
            
            user.last_login = timezone.now()
            user.last_login_ip = get_client_ip(request)
            user.save()

            LoginHistory.objects.create(
                user=user,
                ip_address=get_client_ip(request),
                user_agent=request.META.get('HTTP_USER_AGENT', ''),
                success=True
            )
         
            login(request, user)
          
            token, _ = Token.objects.get_or_create(user=user)
            
            return Response({
                'message': 'Login successful!',
                'user': UserSerializer(user).data,
                'token': token.key
            }, status=status.HTTP_200_OK)
     
        email = request.data.get('email', '').lower()
        try:
            user = User.objects.get(email=email)
            LoginHistory.objects.create(
                user=user,
                ip_address=get_client_ip(request),
                user_agent=request.META.get('HTTP_USER_AGENT', ''),
                success=False
            )
        except User.DoesNotExist:
            pass
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class UserLogoutView(APIView):

    permission_classes = [permissions.IsAuthenticated]
    
    def post(self, request):
    
        latest_login = LoginHistory.objects.filter(
            user=request.user,
            logout_time__isnull=True,
            success=True
        ).first()
        
        if latest_login:
            latest_login.logout_time = timezone.now()
            latest_login.save()

        try:
            request.user.auth_token.delete()
        except Exception:
            pass

        logout(request)
        
        return Response({
            'message': 'Logout successful!'
        }, status=status.HTTP_200_OK)


class ChangePasswordView(APIView):

    permission_classes = [permissions.IsAuthenticated]
    
    def post(self, request):
        serializer = ChangePasswordSerializer(
            data=request.data,
            context={'request': request}
        )
        
        if serializer.is_valid():
            user = request.user
            user.set_password(serializer.validated_data['new_password'])
            user.password_changed_at = timezone.now()
            user.save()
            Token.objects.filter(user=user).delete()
            token = Token.objects.create(user=user)

            try:
                send_mail(
                    'Password Changed Successfully',
                    f'Hello {user.first_name},\n\nYour password was successfully changed.\n\n'
                    f'If you did not make this change, please contact support immediately.',
                    settings.DEFAULT_FROM_EMAIL,
                    [user.email],
                    fail_silently=False,
                )
            except Exception as e:
                print(f"Error sending password change email: {e}")
            
            return Response({
                'message': 'Password changed successfully!',
                'token': token.key
            }, status=status.HTTP_200_OK)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class PasswordResetRequestView(APIView):

    permission_classes = [permissions.AllowAny]
    
    def post(self, request):
        serializer = PasswordResetRequestSerializer(data=request.data)
        
        if serializer.is_valid():
            email = serializer.validated_data['email']
            
            try:
                user = User.objects.get(email=email)

                token = PasswordResetToken.generate_token(
                    user,
                    ip_address=get_client_ip(request)
                )
                
                try:
                    send_password_reset_email(user, token)
                except Exception as e:
                    print(f"Error sending password reset email: {e}")
                
            except User.DoesNotExist:
                pass
            
            return Response({
                'message': 'If an account exists with this email, a password reset link has been sent.'
            }, status=status.HTTP_200_OK)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class PasswordResetConfirmView(APIView):

    permission_classes = [permissions.AllowAny]
    
    def post(self, request):
        serializer = PasswordResetConfirmSerializer(data=request.data)
        
        if serializer.is_valid():
            token = serializer.validated_data['token_obj']
            user = token.user
            
            user.set_password(serializer.validated_data['new_password'])
            user.password_changed_at = timezone.now()
            user.reset_failed_attempts()
            user.save()
            token.mark_as_used()
            Token.objects.filter(user=user).delete()
            
            try:
                send_mail(
                    'Password Reset Successful',
                    f'Hello {user.first_name},\n\nYour password was successfully reset.\n\n'
                    f'If you did not make this change, please contact support immediately.',
                    settings.DEFAULT_FROM_EMAIL,
                    [user.email],
                    fail_silently=False,
                )
            except Exception as e:
                print(f"Error sending password reset confirmation email: {e}")
            
            return Response({
                'message': 'Password reset successful! You can now login with your new password.'
            }, status=status.HTTP_200_OK)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class EmailVerificationView(APIView):

    permission_classes = [permissions.AllowAny]
    
    def post(self, request):
        serializer = EmailVerificationSerializer(data=request.data)
        
        if serializer.is_valid():
            token = serializer.validated_data['token']
            user = token.user
 
            user.email_verified = True
            user.save()

            token.mark_as_used()

            try:
                send_mail(
                    'Welcome! Email Verified',
                    f'Hello {user.first_name},\n\nYour email has been verified successfully!\n\n'
                    f'You now have full access to your account.',
                    settings.DEFAULT_FROM_EMAIL,
                    [user.email],
                    fail_silently=False,
                )
            except Exception as e:
                print(f"Error sending welcome email: {e}")
            
            return Response({
                'message': 'Email verified successfully!'
            }, status=status.HTTP_200_OK)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class ResendVerificationEmailView(APIView):

    permission_classes = [permissions.IsAuthenticated]
    
    def post(self, request):
        user = request.user
        
        if user.email_verified:
            return Response({
                'message': 'Email is already verified.'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        token = EmailVerificationToken.generate_token(user)
    
        try:
            send_verification_email(user, token)
            return Response({
                'message': 'Verification email sent successfully!'
            }, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({
                'error': 'Failed to send verification email. Please try again later.'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class UserDetailView(APIView):

    permission_classes = [permissions.IsAuthenticated]
    
    def get(self, request):
        serializer = UserSerializer(request.user)
        return Response(serializer.data, status=status.HTTP_200_OK)
    
    def put(self, request):
        serializer = UserUpdateSerializer(
            request.user,
            data=request.data,
            partial=True
        )
        
        if serializer.is_valid():
            serializer.save()
            return Response({
                'message': 'Profile updated successfully!',
                'user': UserSerializer(request.user).data
            }, status=status.HTTP_200_OK)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class DeleteAccountView(APIView):

    permission_classes = [permissions.IsAuthenticated]
    
    def delete(self, request):
        user = request.user
        
        # Option 1: Soft delete (deactivate account)
        user.is_active = False
        user.save()
        
        # Option 2: Hard delete (uncomment to use)
        # user.delete()
    
        logout(request)
        
        return Response({
            'message': 'Account deactivated successfully.'
        }, status=status.HTTP_200_OK)


class UserListView(APIView):

    permission_classes = [permissions.IsAdminUser]
    
    def get(self, request):
        users = User.objects.all()
        serializer = UserSerializer(users, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)