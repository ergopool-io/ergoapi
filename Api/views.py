import os

import requests
from django.conf import settings
from django.shortcuts import render
from django.views import View
from rest_framework import viewsets, mixins, status
from rest_framework.response import Response
from rest_framework import filters
from rest_framework.authentication import SessionAuthentication
from rest_framework.permissions import IsAuthenticated
from django.shortcuts import get_object_or_404

from Api import serializers
from Api.models import Block, Configuration, DEFAULT_KEY_VALUES
from Api.util import validation_proof, validation_block, node_request

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

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        share = serializer.validated_data
        result = validation_block(
            pk=share.get("pk").lower(),
            n=share.get("nonce"),
            w=share.get("w"),
            d=share.get("d")
        )
        url = os.path.join(ACCOUNTING, "shares/")
        response = requests.post(url, json={
            "miner": result.get("public_key"),
            "share": result.get("share"),
            "status": result.get("status"),
        }).json()
        headers = self.get_success_headers(serializer.data)
        return Response(response, status=status.HTTP_201_CREATED, headers=headers)


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
            pk=data.get("pk").lower(),
            msg_pre_image_base16=data.get("msg_pre_image"),
            leaf=data.get("leaf"),
            levels_encoded=data.get("levels")
        )
        headers = self.get_success_headers(serializer.data)
        return Response(validation, status=status.HTTP_201_CREATED, headers=headers)


class TransactionView(viewsets.GenericViewSet, mixins.CreateModelMixin):
    serializer_class = serializers.TransactionSerializer

    def get_queryset(self):
        return None

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        pk = serializer.validated_data.get('pk', "")
        transaction = serializer.validated_data.get('transaction', {})
        block = Block.objects.filter(public_key=pk).first()
        if not block:
            block = Block(public_key=pk)
        block.tx_id = transaction.get("id")
        block.save()
        headers = self.get_success_headers(serializer.data)
        return Response(serializer.data, status=status.HTTP_201_CREATED, headers=headers)


class ConfigurationViewSet(viewsets.GenericViewSet,
                           mixins.CreateModelMixin,
                           mixins.ListModelMixin):
    # For session authentication
    authentication_classes = [SessionAuthentication]
    # For token authentication
    permission_classes = (IsAuthenticated,)
    serializer_class = serializers.ConfigurationSerializer
    queryset = Configuration.objects.all()
    filter_backends = (filters.SearchFilter,)
    search_fields = ('key', 'value',)

    def perform_create(self, serializer, *args, **kwargs):
        """
        we override the perform_create to create a new configuration
        or update an existing configuration.
        :param serializer:
        :param args:
        :param kwargs:
        :return:
        """
        key = serializer.validated_data['key']
        value = serializer.validated_data['value']
        configurations = Configuration.objects.filter(key=key)
        if not configurations:
            serializer.save()
        else:
            configuration = Configuration.objects.get(key=key)
            configuration.value = value
            configuration.save()


class ConfigurationValueViewSet(viewsets.GenericViewSet):
    """
    View set for api /config/value/
    Handel list and get method
    """
    serializer_class = serializers.ConfigurationValueSerializer

    def get_queryset(self):
        return None

    def list(self, request, *args, **kwargs):
        return self.get_response()

    @staticmethod
    def get_response():
        config = Configuration.objects.all()
        result = DEFAULT_KEY_VALUES
        for x in config.values_list('key', flat=True):
            result[x] = config.get(key=x).value
        reward = int(result['REWARD'] * result['REWARD_FACTOR'] * pow(10, 9))
        data_node = node_request('wallet/addresses', {'accept': 'application/json', 'api_key': settings.API_KEY})
        if data_node['status'] == 'External Error':
            return data_node
        else:
            wallet_address = data_node.get('response')[0]
        return Response({
            'reward': reward,
            'wallet_address': wallet_address,
            'pool_difficulty_factor': result['POOL_DIFFICULTY_FACTOR']
        })
