import logging
from urllib.parse import urljoin

import requests
from django.conf import settings
from rest_framework import viewsets, mixins, status
from rest_framework.response import Response
from rest_framework.views import APIView

from Api import serializers
from Api.tasks import ValidateShareTask
from Api.utils.general import General, modify_pagination

ACCOUNTING = getattr(settings, "ACCOUNTING_URL")
ACCOUNTING_HOST = getattr(settings, "ACCOUNTING_HOST")
SHARE_CHUNK_SIZE = getattr(settings, "SHARE_CHUNK_SIZE", 10)


logger = logging.getLogger(__name__)


class ConfigurationValueViewSet(viewsets.GenericViewSet,
                                mixins.ListModelMixin,
                                mixins.RetrieveModelMixin):
    """
    View set for api /config/value/
    Handel list and get method
    """
    serializer_class = serializers.ConfigurationValueSerializer

    def list(self, request, *args, **kwargs):
        return Response(self.get_response(request.configs))

    def retrieve(self, request, *args, **kwargs):
        return Response(self.get_response(request.configs, pk=kwargs.get("pk").lower()))

    @staticmethod
    def get_response(configs, pk=None):
        """
        get configuration for json.
        :param pk: if this parameter set return list miner specific configuration otherwise return general configuration
        :return: a json contain all configuration
        """
        PRECISION = configs.REWARD_FACTOR_PRECISION
        REWARD = round((configs.TOTAL_REWARD / 1e9) * configs.REWARD_FACTOR, PRECISION)
        REWARD = int(REWARD * 1e9)
        data_node = General.node_request('wallet/addresses',
                                         {'accept': 'application/json', 'api_key': settings.API_KEY})
        if data_node['status'] == '400':
            return data_node
        else:
            wallet_address = data_node.get('response')[0]
        return {
            'reward': REWARD,
            'wallet_address': wallet_address,
            'pool_base_factor': configs.POOL_BASE_FACTOR,
            'max_chunk_size': SHARE_CHUNK_SIZE,
        }


class ValidationView(viewsets.GenericViewSet, mixins.CreateModelMixin):
    serializer_class = serializers.ValidationSerializer

    def create(self, request, *args, **kwargs):
        configs = request.configs
        data = request.data
        if len(data.get('shares', [])) > SHARE_CHUNK_SIZE:
            return Response({
                "status": "error",
                "message": "too big chunk"
            }, status=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE)

        logger.info('received a share chunk of size {}.'.format(len(data.get('shares', []))))
        serializer = self.get_serializer(data=data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data
        # Get ip of the client that send request
        client_ip = request.META.get('HTTP_X_REAL_IP')

        for share in data.get('shares', []):
            ValidateShareTask.delay(data['pk'],
                                    share.get('w'),
                                    share.get('nonce'),
                                    share.get('d'),
                                    data['proof']['msg'],
                                    data['transaction']['id'],
                                    data['proof']['block'],
                                    data['addresses'],
                                    client_ip,
                                    configs.POOL_BASE_FACTOR)

        logger.info("tasks created for each share.")
        return Response({'status': 'OK'}, status=status.HTTP_200_OK)


class DefaultView(APIView):
    """
    sends every api requests that is not previously matched to accounting.
    """
    def send_request(self, request, url, method_name):
        client_ip = request.META.get('REMOTE_ADDR', '')
        request_headers = dict(request.headers)
        request_headers = {key.lower(): val for key, val in request_headers.items()}
        headers = {'source-ip': client_ip}
        to_add_headers = ['cookie', 'authorization']
        for item in to_add_headers:
            if item in request_headers.keys():
                headers.update({item: request_headers[item]})

        method = getattr(requests, method_name)
        response = None
        try:
            response = method(urljoin(ACCOUNTING, url + '/'), data=request.data,
                              headers=headers, params=dict(request.query_params))
            try:
                result = modify_pagination(request, response.json())
                return Response(result, status=response.status_code)

            except:
                return Response(response.json(), status=response.status_code)

        except:
            if response:
                logger.critical('Could not connect to accounting!, {}, {}'.format(response, response.content))
            else:
                logger.critical('Could not connect to accounting!, {}'.format(response))
            return Response({'message': 'could not connect to accounting!'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def get(self, request, url=None):
        return self.send_request(request, url, 'get')

    def post(self, request, url=None):
        return self.send_request(request, url, 'post')

    def options(self, request, url=None, **kwargs):
        return self.send_request(request, url, 'options')

    def delete(self, request, url=None):
        return self.send_request(request, url, 'delete')

    def put(self, request, url=None):
        return self.send_request(request, url, 'put')

    def patch(self, request, url=None):
        return self.send_request(request, url, 'patch')
