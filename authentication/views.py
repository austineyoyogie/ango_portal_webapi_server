from django.utils import timezone
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework import generics, status
from django.conf import settings
from django.urls import reverse
from django.contrib.sites.shortcuts import get_current_site
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.utils.encoding import smart_str, force_str, smart_bytes, DjangoUnicodeDecodeError
from django.http import HttpResponseRedirect, Http404, HttpResponse

from .serializers import (UserRegisterSerializer, EmailVerificationSerializer,
                          UserLoginSerializer, ResetPasswordEmailRequestSerializer,
                          SetNewPasswordSerializer)
from ango_portal_server.authentication.models import UserRegister as User
from ango_portal_server.authentication.renderers import UserRenderer
from ango_portal_server.authentication.utils import SendUtil

import jwt



# npx create-react-app clients

'''
HOW TO HANDLE EXCEPTIONS 
==========================
rom rest_framework.views import APIView
from rest_framework.response import Response

class ItemDetailView(APIView):
    def get(self, request, item_id):
        try:
            item = Item.objects.get(pk=item_id)
            return Response({'name': item.name, 'quantity': item.quantity})
        except Item.DoesNotExist:
            return Response({'error': 'Item not found.'}, status=404)
'''


class UserRegisterCreate(generics.GenericAPIView):
    serializer_class = UserRegisterSerializer
    renderer_classes = (UserRenderer,)

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid(raise_exception=True):
            serializer.save()
            user_data = serializer.data
            if user_data:
                user = User.objects.get(email=user_data['email'])
                token = RefreshToken.for_user(user).access_token

                #current_site = get_current_site(request).domain
                # reletiveLink = reverse('authentication:email_verify')
                # absurl = 'http://' + current_site + reletiveLink + "?token=" + str(token)
                # email_body = 'Hi ' + user.user_name + ' Use link below to verify your email \n' + absurl
                # data = {'email_body': email_body, 'to_email': user.email, 'email_subject': 'Verify your email'}

                # SendUtil.send_email(data)
                return Response(user_data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class VerifyUserEmail(generics.GenericAPIView):
    serializer_class = EmailVerificationSerializer

    def get(self, request):
        token = request.GET.get('token')
        try:
            payload = jwt.decode(token, settings.SECRET_KEY, algorithms=["HS256"])
            user = User.objects.get(id=payload['user_id'])
            if not user.is_verified:
                user.is_active = True
                user.is_verified = True
                user.is_staff = True
                user.save()
            return Response({'email': 'Account successfully activated'}, status=status.HTTP_200_OK)
        except jwt.ExpiredSignatureError as identifier:
            return Response({'error': 'Account activation expired'}, status=status.HTTP_400_BAD_REQUEST)
        except jwt.exceptions.DecodeError as identifier:
            return Response({'error': 'Invalid response token'}, status=status.HTTP_400_BAD_REQUEST)


class UserLoginAPIView(generics.GenericAPIView):
    serializer_class = UserLoginSerializer
    now = timezone.now()

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid(raise_exception=True):
            user_data = serializer.data
            if user_data:
                user = User.objects.get(email=user_data['email'])
                user.last_login = timezone.now()
                user.save()
                return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class RequestPasswordResetEmail(generics.GenericAPIView):
    serializer_class = ResetPasswordEmailRequestSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid(raise_exception=True):
            email = request.data['email']
            try:
                exists = User.user_obj.get_queryset().find_by_email(email=email)
            except:
                raise Http404
            if not exists:
                return Response({'error': 'With that email does not exists.'}, status=status.HTTP_400_BAD_REQUEST)
            else:
                user = User.objects.get(email=email)
                uidb64 = urlsafe_base64_encode(smart_bytes(user.id))
                token = PasswordResetTokenGenerator().make_token(user)
                current_site = get_current_site(request=request).domain

                # Don't send email now because of front end development

                # reletiveLink = reverse('authentication:password-reset-confirm', kwargs={'uidb64': uidb64, 'token': token})
                # absurl = 'http://' + current_site + reletiveLink
                # email_body = 'Hello, \n Use link below to reset your password \n' + absurl
                # data = {'email_body': email_body, 'to_email': user.email, 'email_subject': 'Reset your password'}

                # SendUtil.send_email(data)

            return Response({'success': 'We have sent you a link to reset your password.'}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class PasswordResetConfirmTokenCheckAPI(generics.GenericAPIView):
    serializer_class = SetNewPasswordSerializer

    def get(self, request, uidb64, token):
        try:
            user_id = smart_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(id=user_id)
            print("User: ", user)
            if not PasswordResetTokenGenerator().check_token(user, token):
                return Response({'error': 'Token is not valid, please request a new token.'},
                                status=status.HTTP_401_UNAUTHORIZED)
            return Response({'success': True, 'message': 'Credentials Valid', 'uidb64': uidb64, 'token': token}, status=status.HTTP_202_ACCEPTED)

        except DjangoUnicodeDecodeError as identifier:
            if not PasswordResetTokenGenerator().check_token(user, token):
                return Response({'error': 'Token is not valid, please request a new token.'}, status=status.HTTP_401_UNAUTHORIZED)


# http://localhost:8000/api/password-reset/Mg/aldo9p-4f692fba45b637e8c165c7fa05933e2b/
class SetNewPasswordAPIView(generics.GenericAPIView):
    serializer_class = SetNewPasswordSerializer

    def patch(self, request):
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid(raise_exception=True):
            return Response({'success': True, 'message': 'Password reset successful'}, status=status.HTTP_200_OK)
        return Response({'error': 'Password reset error.'}, status=status.HTTP_401_UNAUTHORIZED)


class UserRegisterDetails(generics.ListCreateAPIView):
    queryset = User.objects.all()
    serializer_class = UserRegisterSerializer
