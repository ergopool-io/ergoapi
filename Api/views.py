import os
from pydoc import locate

import requests
from django.conf import settings
from django.shortcuts import render
from django.views import View
from rest_framework import viewsets, mixins, status
from rest_framework.response import Response
from rest_framework import filters
from rest_framework.authentication import SessionAuthentication, TokenAuthentication
from rest_framework.permissions import IsAuthenticated
import logging
from urllib.parse import urljoin, urlencode, urlparse, parse_qsl, urlunparse

from Api import serializers
from Api.models import Block, Configuration, CONFIGURATION_DEFAULT_KEY_VALUE, CONFIGURATION_KEY_CHOICE, CONFIGURATION_KEY_TO_TYPE
from Api.serializers import ConfigurationSerializer
from Api.utils.general import General
from Api.tasks import ValidateShareTask

ACCOUNTING = getattr(settings, "ACCOUNTING_URL")
ACCOUNTING_HOST = getattr(settings, "ACCOUNTING_HOST")

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

    def create(self, request, *args, **kwargs):
        data = request.data
        if not isinstance(data, list):
            data = [data]
        if len(data) > Configuration.objects.SHARE_CHUNK_SIZE:
            return Response({
                "status": "error",
                "message": "too big chunk"
            }, status=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE)
        serializer = self.get_serializer(data=data, many=True)
        serializer.is_valid(raise_exception=True)
        shares = serializer.validated_data
        response = []
        for share in shares:
            print(share)
            url = os.path.join(ACCOUNTING, "shares/")
            response.append(requests.post(url, json={
                "miner": share.get("pk"),
                "share": share.get("share"),
                "status": share.get("status"),
                "difficulty": share.get("difficulty"),
                "transaction_id": share.get("tx_id"),
                "block_height": share.get("headers_height"),
            }).json())
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

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        share = serializer.validated_data
        headers = self.get_success_headers(serializer.data)
        # Check if block would have existed update tx_id else set public_key of miner then set tx_id.
        block = Block.objects.filter(public_key=share.get("pk").lower()).first()
        if not block:
            block = Block(public_key=share.get("pk").lower())
        block.tx_id = share.get("tx_id")
        block.save()
        logger.info('Saved or updated the block for pk {}'.format(share.get('pk')))
        return Response({'message': share.get("message")}, status=status.HTTP_201_CREATED, headers=headers)


class ConfigurationViewSet(viewsets.GenericViewSet,
                           mixins.CreateModelMixin,
                           mixins.ListModelMixin):
    # For session authentication
    authentication_classes = [SessionAuthentication, TokenAuthentication]
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
        if key in [x[0] for x in CONFIGURATION_KEY_CHOICE]:
            val_type = CONFIGURATION_KEY_TO_TYPE[key]
            try:
                locate(val_type)(value)

            except:
                return

            configurations = Configuration.objects.filter(key=key)
            if not configurations:
                serializer.save()
            else:
                configuration = Configuration.objects.get(key=key)
                configuration.value = value
                configuration.save()

        try:
            if key in serializer.accounting_choices:
                requests.post(urljoin(ACCOUNTING, 'conf/'), data={'key': key, 'value': value})

        except requests.exceptions.RequestException:
            logger.critical('Could not connect to accounting!')

    def list(self, request, *args, **kwargs):
        """
        overrides list method to return list of key: value instead of list of dicts
        """
        configs = dict(CONFIGURATION_DEFAULT_KEY_VALUE)
        for conf in Configuration.objects.all():
            val_type = CONFIGURATION_KEY_TO_TYPE[conf.key]
            configs[conf.key] = locate(val_type)(conf.value)

        res = None
        try:
            res = requests.get(urljoin(ACCOUNTING, 'conf/'))

        except requests.exceptions.RequestException:
            logger.critical('Could not connect to accounting!')

        if res and res.status_code == status.HTTP_200_OK:
            res = res.json()
            for key, value in res.items():
                configs[key] = value

        return Response(configs, status=status.HTTP_200_OK)


class ConfigurationValueViewSet(viewsets.GenericViewSet,
                                mixins.ListModelMixin,
                                mixins.RetrieveModelMixin):
    """
    View set for api /config/value/
    Handel list and get method
    """
    serializer_class = serializers.ConfigurationValueSerializer

    def get_queryset(self):
        return None

    def list(self, request, *args, **kwargs):
        return Response(self.get_response())

    def retrieve(self, request, *args, **kwargs):
        return Response(self.get_response(kwargs.get("pk").lower()))

    @staticmethod
    def get_response(pk=None):
        """
        get configuration for json.
        :param pk: if this parameter set return list miner specific configuration otherwise return general configuration
        :return: a json contain all configuration
        """
        result = dict(CONFIGURATION_DEFAULT_KEY_VALUE)
        config = Configuration.objects.all()
        for x in config.values_list('key', flat=True):
            val_type = CONFIGURATION_KEY_TO_TYPE[x]
            result[x] = locate(val_type)(config.get(key=x).value)

        PRECISION = Configuration.objects.REWARD_FACTOR_PRECISION
        REWARD = round((result['TOTAL_REWARD'] / 1e9) * result['REWARD_FACTOR'], PRECISION)
        REWARD = int(REWARD * 1e9)
        data_node = General.node_request('wallet/addresses', {'accept': 'application/json', 'api_key': settings.API_KEY})
        if data_node['status'] == '400':
            return data_node
        else:
            wallet_address = data_node.get('response')[0]
        return {
            'reward': REWARD,
            'wallet_address': wallet_address,
            'pool_base_factor': result['POOL_BASE_FACTOR'],
            'max_chunk_size': result['SHARE_CHUNK_SIZE'],
        }


class ValidationView(viewsets.GenericViewSet, mixins.CreateModelMixin):
    serializer_class = serializers.ValidationSerializer

    def create(self, request, *args, **kwargs):
        data = request.data
        if len(data['shares']) > Configuration.objects.SHARE_CHUNK_SIZE:
            return Response({
                "status": "error",
                "message": "too big chunk"
            }, status=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE)
        serializer = self.get_serializer(data=data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data
        logger.debug("Tasks run for validate shares")
        for share in data['shares']:
            ValidateShareTask.delay(data['pk'], share.get('w'), share.get('nonce'), share.get('d'),
                                    data['proof']['msg'], data['transaction']['tx_id'])
        return Response({'status': 'OK'}, status=status.HTTP_200_OK)


def builder_viewset(method, options):
    """
    A function for build a class viewset and add functions for method according to allowed method
    :param method: methods that allowed this api ex:(GET, POST, PUT, OPTIONS, DELETE)
    :param options: options of api accounting
    :return: a class viewset that inheritance viewsets.GenericViewSet
    """
    def list_method(self, request, *args, **kwargs):
        accounting_api = self.get_uri()
        try:
            response = requests.get(accounting_api)
        except requests.exceptions.RequestException as e:
            logger.error('Can not resolve response from Accounting')
            logger.error(e)
            response = {'message': "Internal Server Error"}
            return Response(response, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        result = modify_pagination(request, response.json())
        return Response(result, status=response.status_code)

    def retrieve(self, request, *args, **kwargs):
        pk = None
        if 'pk' in kwargs:
            pk = kwargs.get("pk").lower()
        accounting_api = self.get_uri()
        try:
            response = requests.get(urljoin(accounting_api, pk))
        except requests.exceptions.RequestException as e:
            logger.error('Can not resolve response from Accounting')
            logger.error(e)
            response = {'message': "Internal Server Error"}
            return Response(response, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        result = modify_pagination(request, response.json())
        return Response(result, status=response.status_code)

    def update(self, request, *args, **kwargs):
        pk = None
        if 'pk' in kwargs:
            pk = kwargs.get("pk").lower()
        accounting_api = self.get_uri()
        try:
            response = requests.put(urljoin(accounting_api, pk), request.data) if pk else requests.put(accounting_api,
                                                                                                         request.data)
        except requests.exceptions.RequestException as e:
            logger.error('Can not resolve response from Accounting')
            logger.error(e)
            response = {'message': "Internal Server Error"}
            return Response(response, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        result = modify_pagination(request, response.json())
        return Response(result, status=response.status_code)

    def create(self, request, *args, **kwargs):
        pk = None
        if 'pk' in kwargs:
            pk = kwargs.get("pk").lower()
        accounting_api = self.get_uri()
        try:
            response = requests.post(urljoin(accounting_api, pk), request.data) if pk else requests.post(accounting_api,
                                                                                                         request.data)
        except requests.exceptions.RequestException as e:
            logger.error('Can not resolve response from Accounting')
            logger.error(e)
            response = {'message': "Internal Server Error"}
            return Response(response, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        result = modify_pagination(request, response.json())
        return Response(result, status=response.status_code)

    def delete(self, request, *args, **kwargs):
        pk = None
        if 'pk' in kwargs:
            pk = kwargs.get("pk").lower()
        accounting_api = self.get_uri()
        try:
            response = requests.delete(urljoin(accounting_api, pk)) if pk else requests.delete(accounting_api)
        except requests.exceptions.RequestException as e:
            logger.error('Can not resolve response from Accounting')
            logger.error(e)
            response = {'message': "Internal Server Error"}
            return Response(response, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        result = modify_pagination(request, response.json())
        return Response(result, status=response.status_code)

    def modify_pagination(request, result):
        if 'next' in result:
            if result['next']:
                pagination = list(urlparse(result['next']))
                url_parts = list(urlparse(request.build_absolute_uri()))
                pagination[1] = url_parts[1]
                pagination[2] = url_parts[2]
                result['next'] = urlunparse(pagination)
        if 'previous' in result:
            if result['previous']:
                pagination = list(urlparse(result['previous']))
                url_parts = list(urlparse(request.build_absolute_uri()))
                pagination[1] = url_parts[1]
                pagination[2] = url_parts[2]
                result['previous'] = urlunparse(pagination)
        return result

    class ProxyView(viewsets.GenericViewSet):
        """
        A Simple View set class for apis of accounting service
        """
        serializer_class = serializers.builder_serializer(options)

        def get_queryset(self):
            """
            Create url with query_params of request for send to accounting
            :return: url (str)
            """
            query = dict()
            # Create url for send to explorer and set limit for get blocks.
            for param in self.request.query_params:
                value = self.request.query_params.get(param)
                query[param] = value
            return query

        def get_uri(self):
            """
            Create uri for request to accounting service
            :return:
            """
            # Get Query_param url
            queryset = dict(self.get_queryset())
            # Create url for request to accounting service
            base = urljoin(ACCOUNTING, self.basename + '/')
            # if Query_param have format remove that because don't have send this param to accounting
            if 'format' in queryset:
                queryset.pop('format')
            # Append query_param end of url for call accounting service
            url_parts = list(urlparse(base))
            query = dict(parse_qsl(url_parts[4]))
            query.update(queryset)
            url_parts[4] = urlencode(query)
            accounting_api = urlunparse(url_parts)

            return accounting_api

    # Set functions to class ProxyView according to Allow method in api accounting headers
    if 'GET' in method:
        setattr(ProxyView, 'list', list_method)
        setattr(ProxyView, 'retrieve', retrieve)

    if 'POST' in method:
        setattr(ProxyView, 'create', create)

    if 'PUT' in method:
        setattr(ProxyView, 'update', update)

    if 'DELETE' in method:
        setattr(ProxyView, 'delete', delete)

    return ProxyView
