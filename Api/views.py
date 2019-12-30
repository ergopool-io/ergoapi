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
import logging

from Api import serializers
from Api.models import Block, Configuration, DEFAULT_KEY_VALUES
from Api.utils.general import General

ACCOUNTING = getattr(settings, "ACCOUNTING_URL")

logger = logging.getLogger(__name__)


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
        pass

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        share = serializer.validated_data
        url = os.path.join(ACCOUNTING, "shares/")
        response = requests.post(url, json={
            "miner": share.get("pk"),
            "share": share.get("share"),
            "status": share.get("status"),
            "difficulty": share.get("difficulty"),
            "transaction_id": share.get("tx_id"),
            "block_height": share.get("headers_height"),
        }).json()
        headers = self.get_success_headers(serializer.data)
        return Response(response, status=status.HTTP_201_CREATED, headers=headers)


class HeaderView(viewsets.GenericViewSet,
                 mixins.CreateModelMixin):
    serializer_class = serializers.ProofSerializer

    def get_queryset(self):
        return None

    def perform_create(self, serializer):
        pass


class TransactionView(viewsets.GenericViewSet, mixins.CreateModelMixin):
    serializer_class = serializers.TransactionSerializer

    def get_queryset(self):
        return None

    def perform_create(self, serializer):
        pass

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        share = serializer.validated_data
        headers = self.get_success_headers(serializer.data)
        # Check if block would have existed update tx_id else set public_key of miner then set tx_id.
        block = Block.objects.filter(public_key=share.get("pk")).first()
        if not block:
            block = Block(public_key=share.get("pk"))
        block.tx_id = share.get("tx_id")
        block.save()
        logger.info('Saved or updated the block for pk {}'.format(share.get('pk')))
        return Response({'message': share.get("message")}, status=status.HTTP_201_CREATED, headers=headers)


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
        data_node = General.node_request('wallet/addresses', {'accept': 'application/json', 'api_key': settings.API_KEY})
        if data_node['status'] == '400':
            return data_node
        else:
            wallet_address = data_node.get('response')[0]
        return Response({
            'reward': reward,
            'wallet_address': wallet_address,
            'pool_difficulty_factor': result['POOL_DIFFICULTY_FACTOR']
        })


class DashboardView(viewsets.GenericViewSet,
                    mixins.ListModelMixin,
                    mixins.RetrieveModelMixin):

    def get_queryset(self):
        return None

    def list(self, request, *args, **kwargs):
        return self.get_response(request)

    def retrieve(self, request, *args, **kwargs):
        return self.get_response(request, kwargs.get("pk").lower())

    def get_response(self, request, pk=None):
        """
        Returns information for this round of shares.
        In the response, there is total shares count of this round and information about each miner balances.
        If the pk is set in url parameters, then information is just about that miner.
        :param request:
        :param pk:
        :return:
        """
        url = os.path.join(ACCOUNTING, "dashboard/")
        try:
            response = requests.get(url + pk).json() if pk else requests.get(url).json()
            return Response(response, status=status.HTTP_200_OK)
        except requests.exceptions.RequestException as e:
            logger.error('Can not resolve response from Accounting for pk {}'.format(pk))
            logger.error(e)
            response = {'message': "Internal Server Error"}
            return Response(response, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

