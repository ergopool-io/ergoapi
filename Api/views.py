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
import urllib.parse as urlparse
from urllib.parse import urljoin, urlencode
from django.http import HttpResponse
# import lxml.html as LH
from Api import serializers
from Api.models import Block, Configuration, DEFAULT_KEY_VALUES
from Api.utils.general import General

ACCOUNTING = getattr(settings, "ACCOUNTING_URL")
ACCOUNTING_HOST = getattr(settings, "ACCOUNTING_HOST")
PREFIX_ACCOUNTING_API = getattr(settings, "PREFIX_ACCOUNTING_API")

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


class ProxyView(viewsets.GenericViewSet, mixins.CreateModelMixin):
    serializer_class = serializers.ProxySerializer

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

    def list(self, request, *args, **kwargs):
        return self.get_response(request)

    def retrieve(self, request, *args, **kwargs):
        pk = kwargs.get("pk").lower()
        return self.get_response(request, pk)

    def get_response(self, request, pk=None):
        """
        Returns accounting response.
        :param request:
        :param pk:
        :return:
        """
        base = urljoin(ACCOUNTING, self.basename + '/')
        queryset = self.get_queryset()
        url_parts = list(urlparse.urlparse(base))
        query = dict(urlparse.parse_qsl(url_parts[4]))
        query.update(queryset)
        url_parts[4] = urlencode(query)
        url = urlparse.urlunparse(url_parts)

        try:
            header = dict(request._request.headers)
            header['Host'] = ACCOUNTING_HOST
            header.pop('Content-Length')

            response = requests.get(urljoin(url, pk), headers=header) if pk else requests.get(url, headers=header)
            html = response.content
            # TODO : pars html with package below
            #  https://stackoverflow.com/questions/19357506/python-find-html-tags-and-replace-their-attributes
            # root = LH.fromstring(html)
            # for el in root.iter('a'):
            #     el.attrib['href'] = el.attrib['href']
            #     print(el.attrib['href'])
            cookies = list(response.cookies).pop() if list(response.cookies) else None
            # Set content and status code from accounting response
            http_response = HttpResponse(response.content, status=response.status_code)
            # Set header from response accounting
            not_allowed = ['Connection', 'Keep-Alive', 'Proxy-Authenticate', 'Proxy-Authorization', 'TE',
                     'Transfer-Encoding', 'Upgrade']
            for head in response.headers:
                if head not in not_allowed:
                    http_response.__setitem__(str(head), str(response.headers[head]))
            # Set cookies from response of accounting
            if cookies:
                http_response.set_cookie(cookies.name if hasattr(cookies, 'name') else "",
                                         cookies.value if hasattr(cookies, 'value') else "",
                                         cookies.max_age if hasattr(cookies, 'max_age') else None,
                                         cookies.expires if hasattr(cookies, 'expires') else None,
                                         cookies.path if hasattr(cookies, 'path') else "/",
                                         cookies.domain if hasattr(cookies, 'domain') else None,
                                         cookies.secure if hasattr(cookies, 'secure') else False,
                                         cookies.httponly if hasattr(cookies, 'httponly') else False,
                                         cookies._rest.get('SameSite') if hasattr(cookies, '_rest') and
                                                                          cookies._rest.get('SameSite') else None)
            return http_response

        except requests.exceptions.RequestException as e:
            logger.error('Can not resolve response from Accounting')
            logger.error(e)
            response = {'message': "Internal Server Error"}
            return Response(response, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

