from rest_framework import serializers
from django.contrib.auth.models import User


class UserSerializer(serializers.ModelSerializer):
    password = serializers.CharField(max_length=60, min_length=4, write_only=True)
    email = serializers.EmailField(max_length=255, min_length=4)
    first_name = serializers.CharField(max_length=60, min_length=2)
    last_name = serializers.CharField(max_length=60, min_length=2)

    class Meta:
        model = User
        fields = ['username', 'first_name', 'last_name', 'email', 'password']

    def validate(self, attrs):
        if User.objects.filter(email=attrs['email']).exists():
            email = attrs.get('email', ' ')
            raise serializers.ValidationError(
                {'email', 'Email already exist'})
        return super().validate(attrs)

    def create(self, validated_data):
        return User.objects.create_user(**validated_data)


class LoginSerializer(serializers.ModelSerializer):
    password = serializers.CharField(max_length=60, min_length=4, write_only=True)
    username = serializers.CharField(max_length=60, min_length=2)

    class Meta:
        model = User
        fields = ['username', 'password']
