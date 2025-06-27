from abc import ABC

from django.db import models
from django.contrib import auth
from rest_framework import serializers
from rest_framework.exceptions import AuthenticationFailed
from ango_portal_server.authentication.models import UserRegister as User
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.encoding import smart_str, force_str, smart_bytes, DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.utils.baseconv import BASE16_ALPHABET
from rest_framework import generics, status

# OOP => https://www.freecodecamp.org/news/object-oriented-programming-in-python/

class UserRegisterSerializer(serializers.ModelSerializer):
    password = models.CharField(max_length=255, null=True, blank=True)

    class Meta:
        model = User
        fields = ['user_name', 'email', 'first_name', 'last_name',
                  'mobile_number', 'is_verified', 'is_staff', 'password']
        extra_kwargs = {'password': {'write_only': True}}

    def validate(self, attrs):
        email = attrs.get('email', '')
        user_name = attrs.get('user_name', '')
        if not user_name.isalnum():
            raise serializers.ValidationError('The username should not contain: %s' % user_name)
        return super().validate(attrs)

    def create(self, validated_data):
        password = validated_data.pop('password', None)
        instance = self.Meta.model(**validated_data)
        if password is not None:
            instance.set_password(password)
        instance.is_active = False
        instance.is_superuser = False
        instance.save()
        return instance


class UserLoginSerializer(serializers.ModelSerializer):
    #user_name = serializers.CharField(max_length=255, min_length=6, read_only=True)
    email = serializers.EmailField(max_length=45, min_length=6)
    password = serializers.CharField(max_length=255, min_length=6, write_only=True)
    token = serializers.SerializerMethodField()

    class Meta:
        model = User
        fields = ['email', 'password', 'token']

    @staticmethod
    def get_token(obj):
        user = User.objects.get(email=obj['email'])
        return {
            'fullName': user.get_full_name(),
            'access': user.tokens()['access'],
            'refresh': user.tokens()['refresh']
        }

    def validate(self, attrs):
        email = attrs.get('email', '')
        password = attrs.get('password', '')
        user = auth.authenticate(email=email, password=password)
        if not user:
            raise AuthenticationFailed({'error': 'Invalid credentials, or have you activate your account?.'})
        if not user.is_verified:
            raise AuthenticationFailed({'error': 'Email is not verified.'})
        return {
            'email': user.email,
            'user_name': user.user_name,
            'token': user.tokens
        }
        return super().validate(attrs)

class EmailVerificationSerializer(serializers.ModelSerializer):
    token = serializers.CharField(max_length=255)

    class Meta:
        model = User
        fields = ['token']


class ResetPasswordEmailRequestSerializer(serializers.Serializer):
    email = serializers.EmailField(max_length=45)

    class Meta:
        fields = ['email']


class SetNewPasswordSerializer(serializers.Serializer):
    password = serializers.CharField(max_length=68, min_length=6, write_only=True)
    token = serializers.CharField(min_length=1, write_only=True)
    uidb64 = serializers.CharField(min_length=1, write_only=True)

    class Meta:
        fields = ['password', 'token', 'uidb64']

    def validate(self, attrs):
        try:
            password = attrs.get('password')
            token = attrs.get('token')
            uidb64 = attrs.get('uidb64')

            user_id = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(id=user_id)

            if not PasswordResetTokenGenerator().check_token(user, token):
                raise AuthenticationFailed('The reset linked is invalid', status.HTTP_401_UNAUTHORIZED)
            user.set_password(password)
            user.save()
            return user

        except Exception as e:
            raise AuthenticationFailed('The reset linked is invalid', status.HTTP_401_UNAUTHORIZED)
        return super().validate(attrs)
