from django.shortcuts import render
from rest_framework import permissions

from rest_framework.generics import ListCreateAPIView, RetrieveUpdateDestroyAPIView
from .models import Contact
from .serializers import ContactSerializer


class ContactList(ListCreateAPIView):
    serializer_class = ContactSerializer
    permission_classes = permissions.IsAuthenticated,

    def perform_create(self, serializer):
        serializer.save(owner=self.request.user)

    def get_queryset(self):
        return Contact.objects.filter(owner=self.request.user)


class ContactDetail(RetrieveUpdateDestroyAPIView):
    serializer_class = ContactSerializer
    lookup_field = "id"

    def perform_create(self, serializer):
        serializer.save(owner=self.request.user)

    def get_queryset(self):
        return Contact.objects.filter(owner=self.request.user)
