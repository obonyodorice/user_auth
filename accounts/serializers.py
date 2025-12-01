from rest_framework import serializers
from django.contrib.auth import authenticate
from django.contrib.auth.password_validation import validate_password
from .models import User, PasswordResetToken


class UserRegistrationSerializer(serializers.ModelSerializer):
    
    password = serializers.CharField(
        write_only=True,
        required=True,
        validators=[validate_password],
        style={'input_type': 'password'}
    )
    password_confirm = serializers.CharField(
        write_only=True,
        required=True,
        style={'input_type': 'password'}
    )
    
    class Meta:
        model = User
        fields = [
            'email', 'password', 'password_confirm',
            'first_name', 'last_name',
        
        ]
        extra_kwargs = {
            'first_name': {'required': True},
            'last_name': {'required': True},
        }
    
    def validate(self, attrs):

        if attrs['password'] != attrs['password_confirm']:
            raise serializers.ValidationError({
                "password_confirm": "Password fields didn't match."
            })
        return attrs
    
    def validate_email(self, value):
       
        if User.objects.filter(email=value.lower()).exists():
            raise serializers.ValidationError("A user with this email already exists.")
        return value.lower()
    
    def create(self, validated_data):
    
        validated_data.pop('password_confirm')
        user = User.objects.create_user(**validated_data)
        return user


class UserLoginSerializer(serializers.Serializer):
    
    email = serializers.EmailField(required=True)
    password = serializers.CharField(
        required=True,
        write_only=True,
        style={'input_type': 'password'}
    )
    
    def validate(self, attrs):
      
        email = attrs.get('email', '').lower()
        password = attrs.get('password')
        
        if email and password:
         
            try:
                user = User.objects.get(email=email)
            except User.DoesNotExist:
                raise serializers.ValidationError("Invalid email or password.")
            
            if user.is_account_locked():
                raise serializers.ValidationError(
                    "Account is temporarily locked due to multiple failed login attempts. "
                    "Please try again later."
                )
        
            if not user.is_active:
                raise serializers.ValidationError("This account has been deactivated.")
          
            user = authenticate(username=email, password=password)
            
            if not user:

                try:
                    failed_user = User.objects.get(email=email)
                    failed_user.increment_failed_attempts()
                except User.DoesNotExist:
                    pass
                raise serializers.ValidationError("Invalid email or password.")
            
            attrs['user'] = user
        else:
            raise serializers.ValidationError("Must include 'email' and 'password'.")
        
        return attrs


class UserSerializer(serializers.ModelSerializer):
    
    full_name = serializers.CharField(source='get_full_name', read_only=True)
    
    class Meta:
        model = User
        fields = [
            'id', 'email', 'first_name', 'last_name', 'full_name',
            'email_verified', 'is_active',
            'created_at', 'last_login'
        ]
        read_only_fields = [
            'id', 'email', 'email_verified',
            'is_active', 'created_at', 'last_login'
        ]


class ChangePasswordSerializer(serializers.Serializer):
    
    old_password = serializers.CharField(
        required=True,
        write_only=True,
        style={'input_type': 'password'}
    )
    new_password = serializers.CharField(
        required=True,
        write_only=True,
        validators=[validate_password],
        style={'input_type': 'password'}
    )
    new_password_confirm = serializers.CharField(
        required=True,
        write_only=True,
        style={'input_type': 'password'}
    )
    
    def validate_old_password(self, value):
  
        user = self.context['request'].user
        if not user.check_password(value):
            raise serializers.ValidationError("Old password is incorrect.")
        return value
    
    def validate(self, attrs):

        if attrs['new_password'] != attrs['new_password_confirm']:
            raise serializers.ValidationError({
                "new_password_confirm": "New password fields didn't match."
            })
        
        if attrs['old_password'] == attrs['new_password']:
            raise serializers.ValidationError({
                "new_password": "New password must be different from old password."
            })
        
        return attrs


class PasswordResetRequestSerializer(serializers.Serializer):
    
    email = serializers.EmailField(required=True)
    
    def validate_email(self, value):
  
        try:
            User.objects.get(email=value.lower())
        except User.DoesNotExist:
         
            pass
        return value.lower()


class PasswordResetConfirmSerializer(serializers.Serializer):
    
    token = serializers.CharField(required=True)
    new_password = serializers.CharField(
        required=True,
         write_only=True,
        validators=[validate_password],
        style={'input_type': 'password'}
    )
    new_password_confirm = serializers.CharField(
        required=True,
        write_only=True,
        style={'input_type': 'password'}
    )
    
    def validate(self, attrs):
        """Validate password confirmation and token"""
        if attrs['new_password'] != attrs['new_password_confirm']:
            raise serializers.ValidationError({
                "new_password_confirm": "Password fields didn't match."
            })
        
        try:
            token = PasswordResetToken.objects.get(token=attrs['token'])
            if not token.is_valid():
                raise serializers.ValidationError({
                    "token": "Invalid or expired token."
                })
            attrs['token_obj'] = token
        except PasswordResetToken.DoesNotExist:
            raise serializers.ValidationError({
                "token": "Invalid token."
            })
        
        return attrs


class UserUpdateSerializer(serializers.ModelSerializer):
    
    class Meta:
        model = User
        fields = [
            'first_name', 'last_name'
        ]
