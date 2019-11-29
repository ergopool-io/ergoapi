import os

import requests
from django.conf import settings
from django.shortcuts import render
from django.views import View
from rest_framework import viewsets, mixins
from Api.models import *
from Api import serializers

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
                mixins.ListModelMixin,
                mixins.CreateModelMixin):
    queryset = NoModel.objects.all()
    serializer_class = serializers.ShareSerializer

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

