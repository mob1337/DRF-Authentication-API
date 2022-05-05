from django.shortcuts import render
from rest_framework.views import APIView
from .serializers import UserSerializer, UserChangePasswordSerializer, SendPasswordResetEmailSerializer, UserPasswordResetSerializer
from .models import MyUser
from rest_framework.response import Response
from rest_framework.exceptions import AuthenticationFailed
import jwt
import datetime
from rest_framework import status

# Create your views here.
class RegisterView(APIView):
    def post(self, request):
        serializer = UserSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(serializer.data)

class LoginView(APIView):
    def post(self, request):
        email = request.data['email']
        password = request.data['password']
        user = MyUser.objects.filter(email=email).first()
        if user is None:
            raise AuthenticationFailed('User not found!')
        if not user.check_password(password):
            raise AuthenticationFailed('Incorrect password!')
        payload = {
            'id': user.id,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=60),
            'iat': datetime.datetime.utcnow()
        }
        token = jwt.encode(payload, 'secret', algorithm='HS256')#.decode('utf-8')
        token_decode=jwt.decode(token,'secret',algorithms=['HS256'])
        response = Response()
        response.set_cookie(key='jwt', value=token)   # You can do expires=datetime.utcnow()+timedelta(days=2)
        response.data = {
            'jwt': token,
            'data':token_decode
        }
        return response

class UserView(APIView):
    def get(self, request):
        token = request.COOKIES.get('jwt')
        if not token:
            raise AuthenticationFailed('Unauthenticated!')
        try:
            payload = jwt.decode(token, 'secret', algorithms=['HS256'])
        except jwt.ExpiredSignatureError:
            raise AuthenticationFailed('Unauthenticated!')
        user = MyUser.objects.filter(id=payload['id'])#.first()
        serializer = UserSerializer(user[0])
        # There are 3 ways of doins this-----  
        # user = MyUser.objects.filter(id=payload['id']).first()
        # user = MyUser.objects.get(id=payload['id'])
        # user = MyUser.objects.filter(id=payload['id']).first()  and then user[0]
        # filter() is returning a queryset of objects
        return Response(serializer.data)

class LogoutView(APIView):
    def post(self, request):
        response = Response()
        response.delete_cookie('jwt')
        response.data = {
            'message': 'success'
        }
        return response

class UserChangePasswordView(APIView):
    def post(self, request):
        token = request.COOKIES.get('jwt')
        if not token:
            raise AuthenticationFailed('Unauthenticated!')
        try:
            payload = jwt.decode(token, 'secret', algorithms=['HS256'])
        except jwt.ExpiredSignatureError:
            raise AuthenticationFailed('Unauthenticated!')
        user = MyUser.objects.filter(id=payload['id'])
        serializer = UserChangePasswordSerializer(data = request.data, context = {'user':user[0]})
        serializer.is_valid(raise_exception = True)
        
        # Logout when password is changed
        response = Response()
        response.delete_cookie('jwt')
        response.data = {
            'message': 'Password changed successfully and logged out',
            'status' : status.HTTP_200_OK
        }
        return response

# Code for generating password reset link
class SendPasswordResetEmailView(APIView):
    def post(self, request, format = None):
        serializer = SendPasswordResetEmailSerializer(data = request.data)
        serializer.is_valid(raise_exception = True)
        return Response({'msg':'Password reset email has been sent. Please check your email'}, status = status.HTTP_200_OK)


class UserPasswordResetView(APIView):
    def post(self, request, uid, token, format=None):
        serializer = UserPasswordResetSerializer(data = request.data, context = {'uid':uid, 'token':token})
        serializer.is_valid(raise_exception = True)
        return Response({'msg':'Password reset successfully'}, status = status.HTTP_200_OK)