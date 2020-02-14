from urllib.parse import urljoin, urlparse, urlunparse

from ErgoApi.settings import NODE_ADDRESS
from hashlib import blake2b
import requests
import logging
import json

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
    def node_request(api, header, data=None, request_type="get"):
        """
        Function for request to node
        :param api: string
        :param header: dict
        :param data: For request post use this
        :param request_type: For select ypt of request get or post
        :return: response of request
        """
        try:
            # check allowed methods
            if request_type not in ['get', 'post', 'put', 'patch', 'option']:
                return {"status": "error", "response": "invalid request type"}
            # requests kwargs generated
            kwargs = {"headers": header}
            # append data to kwargs if exists
            if data:
                kwargs["data"] = json.dumps(data)
            # call requests method according to request_type
            response = getattr(requests, request_type)(urljoin(NODE_ADDRESS, api), **kwargs)
            response_json = response.json()
            # check status code 2XX range is success
            return {
                "response": response_json,
                "status": "success" if 200 <= response.status_code <= 299 else
                ("Not Found" if response.status_code == 404 else "External Error")
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
