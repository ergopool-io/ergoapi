import os

import requests
from django.conf import settings
from django.shortcuts import render
from django.views import View
from rest_framework import viewsets, mixins, status
from rest_framework.response import Response

from Api import serializers
from Api.util import validation_proof

ACCOUNTING = getattr(settings, "ACCOUNTING_URL", "http://127.0.0.1:8000")


class AccountView(View):
    def get(self, request, public_key=""):
        url = os.path.join(ACCOUNTING, "dashboard/")
        if public_key:
            url += public_key + "/"
        try:
            content = requests.get(url).json()
            user_content = content.get("users", {}).get(public_key, {})
        except:
            content, user_content = {}, {}
        return render(request, 'dashboard.html', {
            'public_key': public_key,
            "content": content,
            "user_content": user_content
        })


class ShareView(viewsets.GenericViewSet,
                mixins.CreateModelMixin):
    serializer_class = serializers.ShareSerializer

    def get_queryset(self):
        return None

    def perform_create(self, serializer):
        share = serializer.validated_data
        # TODO first validate this share
        result = {
            "miner": share.get("pk"),
            "share": share.get("w"),
            "status": 2
        }
        url = os.path.join(ACCOUNTING, "shares/")
        response = requests.post(url, json=result)
        print(response.content)


class HeaderView(viewsets.GenericViewSet,
                 mixins.CreateModelMixin):
    serializer_class = serializers.ProofSerializer

    def get_queryset(self):
        return None

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.data
        validation = validation_proof(
            pk=data.get("pk"),
            msg_pre_image_base16=data.get("msg_pre_image"),
            leaf=data.get("leaf"),
            levels_encoded=data.get("levels")
        )
        headers = self.get_success_headers(serializer.data)
        return Response(validation, status=status.HTTP_201_CREATED, headers=headers)


class Transaction(viewsets.GenericViewSet,
                  mixins.CreateModelMixin):
    def get_queryset(self):
        return None
