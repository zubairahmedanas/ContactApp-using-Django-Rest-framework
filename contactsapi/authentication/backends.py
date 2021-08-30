from datetime import datetime, timedelta

import jwt
from django.conf import settings
from django.contrib.auth.models import User
from rest_framework import authentication, exceptions


class JWTAuthentication(authentication.BaseAuthentication):
    def authenticate(self, request):
        auth_data = authentication.get_authorization_header(request)
        if not auth_data:
            return None
        prefix, token = auth_data.decode('utf-8').split(' ')
        dt = datetime.now() + timedelta(days=2)
        try:
            payload = jwt.decode(token, settings.JWT_SECRET_KEY, dt)
            user = User.objects.get(usrename=payload['username'])
            return user, token
        except jwt.DecodeError:
            raise exceptions.AuthenticationFailed('Your Token Is Invalid')
        except jwt.ExpiredSignature:
            raise exceptions.AuthenticationFailed('Your Token Is Expired')
        return super().authenticate(request)
