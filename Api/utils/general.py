import json
import logging
from hashlib import blake2b
from urllib.parse import urljoin, urlparse, urlunparse

import requests

from ErgoApi.settings import NODE_ADDRESS, API_KEY, ACCOUNTING_URL

logger = logging.getLogger(__name__)


class General:
    @staticmethod
    def blake(data, kind='byte'):
        """
        Function for get hash from a string
        :param data: string
        :param kind: string hex or type
        :return: byte array or hex
        """
        return blake2b(data, digest_size=32).hexdigest() if kind == "hex" else blake2b(data, digest_size=32).digest()

    @staticmethod
    def node_request(api, header=None, data=None, params=None, request_type="get"):
        """
        Function for request to node
        :param api: string
        :param header: dict
        :param data: For request post use this
        :param request_type: For select ypt of request get or post
        :param params: query string
        :return: response of request
        """
        if header is None:
            header = {
                'accept': 'application/json',
                'content-type': 'application/json',
                'api_key': API_KEY
            }

        try:
            # check allowed methods
            if request_type not in ['get', 'post', 'put', 'patch', 'option']:
                return {"status": "error", "response": "invalid request type"}
            # requests kwargs generated
            kwargs = {"headers": header}
            # append data to kwargs if exists
            if data:
                kwargs["data"] = json.dumps(data)
            if params:
                kwargs["params"] = params
            # call requests method according to request_type
            response = getattr(requests, request_type)(urljoin(NODE_ADDRESS, api), **kwargs)
            response_json = response.json()
            # check status code 2XX range is success
            return {
                "response": response_json,
                "status": "success" if 200 <= response.status_code <= 299 else "External Error"
            }
        except requests.exceptions.RequestException as e:
            logger.error("Can not resolve response from node")
            logger.error(e)
            response = {'status': 'error', 'message': 'Can not resolve response from node'}
            raise Exception(response)


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


class LazyConfiguration:
    def __init__(self):
        self.configs = None

    def get_configuration(self):
        if self.configs is None:
            res = requests.get(urljoin(ACCOUNTING_URL, 'conf/'))
            self.configs = res.json()

    def __getattr__(self, item):
        if self.configs is None:
            self.get_configuration()

        if item not in self.configs.keys():
            return super().__getattribute__(item)

        return self.configs[item]

