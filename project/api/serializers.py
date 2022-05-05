from asyncore import read
from rest_framework import serializers
from .models import Profile, MyUser

from django.utils.encoding import smart_str, force_bytes, DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from rest_framework.exceptions import ValidationError

from .utils import Util


class ProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = Profile
        fields = ['id', 'docfile']


class UserSerializer(serializers.ModelSerializer):
    files = ProfileSerializer(many=True, read_only=True)
    class Meta:
        model = MyUser
        fields = ['id', 'name', 'email', 'password', 'files']
        extra_kwargs = {
            'password': {'write_only': True}
        }

    def create(self, validated_data):     # Overriding... For more info read source code of serializers.ModelSerializer.create()
        password = validated_data.pop('password', None)
        instance = self.Meta.model(**validated_data)
        if password is not None:
            instance.set_password(password)
        instance.save()
        return instance

class UserChangePasswordSerializer(serializers.Serializer):
    password = serializers.CharField(max_length = 50, style = {'input_type':'password'}, write_only = True)
    password2 = serializers.CharField(max_length = 50, style = {'input_type':'password'}, write_only = True)
    class Meta:
        fields = ['password', 'password2']

    def validate(self, data):
        password = data.get('password')
        password2 = data.get('password2')
        user = self.context.get('user')
        if password != password2:
            raise serializers.ValidationError("Password & Confirm password does not match")
        user.set_password(password)
        user.save()
        return data

class SendPasswordResetEmailSerializer(serializers.Serializer):
    email = serializers.EmailField(max_length = 255)
    class Meta:
        fields = ['email']

    def validate(self, data):
        email = data.get('email')
        if MyUser.objects.filter(email = email).exists():
            user = MyUser.objects.get(email = email)
            # Code to send email
            uid = urlsafe_base64_encode(force_bytes(user.id))   # this encode method takes bytes as param, hence force_bytes()
            token = PasswordResetTokenGenerator().make_token(user)
            # To set expiry date of token or link, write   PASSWORD_RESET_TIMEOUT = 900   in settings.py, ie user has to reset password within 15 min

            # Generate link by combining uid & token 
            link = 'http://localhost:3000/api/user/reset/' + uid + '/' + token
            print(link, "kkk")
            # Send email 
            # First we have to do some config in settings.py
            # After editing utils.py
            body = 'Click the following link to reset your password \n' + link
            data = {
                'subject':'Reset your password',
                'body': body,
                'to_email': user.email
            }
            Util.send_email(data)
            # Make sure to turn ON less secure app access in gmail security settings
            return data
        else:
            raise ValidationError('You are not a registered user')

# Code for setting new password using reset link sent on your email
class UserPasswordResetSerializer(serializers.Serializer):
    password = serializers.CharField(max_length = 255, style = {'input_type':'password'}, write_only = True)
    password2 = serializers.CharField(max_length = 255, style = {'input_type':'password'}, write_only = True)
    class Meta:
        fields = ['password', 'password2']

    def validate(self, data):
        try:    # Because sometimes people try to decode unicode
            password = data.get('password')
            password2 = data.get('password2')
            uid = self.context.get('uid')   # It is encoded, so need to decode it
            token = self.context.get('token')
            if password != password2:
                raise serializers.ValidationError("Password & Confirm password does not match")
            id = smart_str(urlsafe_base64_decode(uid))    # smart_str() to convert to string
            user = MyUser.objects.get(id = id)
            if not PasswordResetTokenGenerator().check_token(user, token):
                raise ValidationError('Token is not valid or has expired')
            user.set_password(password)
            user.save()
            return data

        except DjangoUnicodeDecodeError as identifier:
            PasswordResetTokenGenerator().check_token(user, token)
            raise ValidationError('Token is not valid or has expired')