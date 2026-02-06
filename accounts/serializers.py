from rest_framework import serializers
from django.contrib.auth.password_validation import validate_password
from .models import User, Profile

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'email', 'username', 'first_name', 'last_name']
        read_only_fields = ['id']


class ProfileSerializer(serializers.ModelSerializer):
    user = UserSerializer(read_only=True)
    
    class Meta:
        model = Profile
        fields = [
            'id', 'user', 'full_name', 'email', 'phone', 'bio', 
            'location', 'interests', 'profile_picture', 
            'created_at', 'updated_at'
        ]
        read_only_fields = ['id', 'created_at', 'updated_at']


class SignupSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, min_length=6)
    password_confirm = serializers.CharField(write_only=True)
    full_name = serializers.CharField(write_only=True, required=False, allow_blank=True, allow_null=True)
    interests = serializers.ListField(child=serializers.CharField(), required=False, allow_empty=True, default=list)
    year_in_college = serializers.CharField(write_only=True, required=False, allow_blank=True, allow_null=True)
    
    class Meta:
        model = User
        fields = ['email', 'password', 'password_confirm', 'full_name', 'interests', 'year_in_college']
    
    def validate(self, attrs):
        password = attrs.get('password')
        password_confirm = attrs.get('password_confirm')
        
        if not password:
            raise serializers.ValidationError({"password": "Password is required."})
        if not password_confirm:
            raise serializers.ValidationError({"password_confirm": "Password confirmation is required."})
        if password != password_confirm:
            raise serializers.ValidationError({"password_confirm": "Password fields didn't match."})
        if len(password) < 6:
            raise serializers.ValidationError({"password": "Password must be at least 6 characters long."})
        
        return attrs
    
    def validate_email(self, value):
        if User.objects.filter(email=value).exists():
            raise serializers.ValidationError("A user with this email already exists.")
        return value
    
    def create(self, validated_data):
        password_confirm = validated_data.pop('password_confirm', None)
        full_name = validated_data.pop('full_name', None) or None
        interests = validated_data.pop('interests', []) or []
        if not isinstance(interests, list):
            interests = []
        year_in_college = validated_data.pop('year_in_college', None) or None
        
        user = User.objects.create_user(
            email=validated_data['email'],
            password=validated_data['password'],
            username=validated_data.get('username', validated_data['email'].split('@')[0])
        )
        
        # Create profile
        Profile.objects.create(
            user=user,
            email=user.email,
            full_name=full_name,
            interests=interests,
        )
        
        return user


class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)
