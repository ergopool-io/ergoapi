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
            output = dict()
            if request_type == "get":
                response = requests.get(NODE_ADDRESS + api, headers=header)
                json_response = response.json()
                if not response.status_code == 200:
                    output = {'response': json_response, 'status': 'External Error'}
                else:
                    output = {'response': json_response, 'status': 'success'}
            elif request_type == "post":
                response = requests.post(NODE_ADDRESS + api, json.dumps(data), headers=header)
                json_response = response.json()
                if not response.status_code == 200:
                    output = {'response': json_response, 'status': 'External Error'}
                else:
                    output = {'response': json_response, 'status': 'success'}
            return output
        except requests.exceptions.RequestException as e:
            logger.error("Can not resolve response from node")
            logger.error(e)
            response = {'status': 'error',
                        'message': 'Can not resolve response from node'}
            raise Exception(response)
