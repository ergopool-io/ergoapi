from ErgoApi.settings import NODE_ADDRESS
from hashlib import blake2b
import requests
import logging


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
    def node_request(api, header):
        """
        Function for request to node
        :param api: string
        :param header: dict
        :return: response of request
        """
        try:
            response = requests.get(NODE_ADDRESS + api, headers=header)
            response = response.json()
            json = {'response': response, 'status': 'success'}
            return json
        except requests.exceptions.RequestException as e:
            logging.error(e)
            logging.error("Can not resolve response from node")
            response = {'status': 'error',
                        'message': 'Can not resolve response from node'}
            raise Exception(response)
