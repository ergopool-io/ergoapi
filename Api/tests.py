import json
import struct
from codecs import decode
from hashlib import blake2b
from unittest.mock import patch, call
from urllib.parse import urljoin

from django.test import Client
from django.test.testcases import TransactionTestCase, TestCase
from rest_framework.exceptions import ValidationError

from Api.serializers import ValidateProofSerializer, ValidationShareSerializer
from Api.utils.header import HeaderWithoutPow, HeaderSerializer, Reader, Writer
from Api.utils.share import ValidateShare
from ErgoApi import settings
from ErgoApi.settings import ACCOUNTING_URL, VERIFIER_ADDRESS


class ConfigurationValueApiTest(TransactionTestCase):
    """
    Test class for Configuration API
    This class has 3 test function based on 3 following general situations:
    1) using http 'get' method to retrieve a list of existing configurations
    """
    reset_sequences = True
    default_configs = {
        'POOL_BASE_FACTOR': 1000,
        'TOTAL_REWARD': int(67.5e9),
        "REWARD_FACTOR_PRECISION": 2,
        'REWARD_FACTOR': 0.96296297,
        'SHARE_CHUNK_SIZE': 10,
        'THRESHOLD_HEIGHT': 10,
        'THRESHOLD_TIMESTAMP': 120000
    }

    returned_configs = None

    def mocked_node_request(*args, **kwargs):
        """
        mock function node_request for urls wallet/addresses'
        """
        if args[0] == "wallet/addresses":
            return {
                "status": "success",
                "response": ["3WwYLP3oDYogUc8x9BbcnLZvpVqT5Zc77RHjoy19PyewAJMy9aDM"]
            }

    def mocked_requests_get(*args, **kwargs):
        """
        mock function requests.get
        """

        class MockResponse:
            def __init__(self, json_data, status_code):
                self.json_data = json_data
                self.status_code = status_code

            def json(self):
                return self.json_data

        url = args[0]

        if url == urljoin(ACCOUNTING_URL, 'conf/'):
            return MockResponse(ConfigurationValueApiTest.returned_configs, 200)

    @patch("requests.get", side_effect=mocked_requests_get)
    @patch("Api.utils.general.General.node_request", side_effect=mocked_node_request)
    def test_configuration_api_get_method_list_with_default(self, mock, mock2):
        """
        In this scenario we want to test the functionality of Configuration value API when
        it is called by a http 'get' or 'list' method.
        For the above purpose first we delete all object in database for that check if an object there isn't in the
         database set default value
        we send a http 'get' method to retrieve a list of them.
        We expect that the status code of response be '200 ok' and
        the json format of response be as below .
        :return:
        """
        # response of API /config/value should be this
        configs = dict(ConfigurationValueApiTest.default_configs)
        PRECISION = configs['REWARD_FACTOR_PRECISION']
        REWARD = round((configs['TOTAL_REWARD'] / 1e9) * configs['REWARD_FACTOR'], PRECISION)
        REWARD = int(REWARD * 1e9)
        result = {
            "reward": REWARD,
            "wallet_address": "3WwYLP3oDYogUc8x9BbcnLZvpVqT5Zc77RHjoy19PyewAJMy9aDM",
            "pool_base_factor": ConfigurationValueApiTest.default_configs['POOL_BASE_FACTOR'],
            "max_chunk_size": 10,
        }
        # send a http 'get' request to the configuration endpoint
        ConfigurationValueApiTest.returned_configs = configs
        response = self.client.get('/api/config/value/')
        # check the status of the response
        self.assertEqual(response.status_code, 200)
        # check the content of the response
        self.assertEqual(response.json(), result)

    @patch("requests.get", side_effect=mocked_requests_get)
    @patch("Api.utils.general.General.node_request", side_effect=mocked_node_request)
    def test_configuration_api_get_method_list(self, mock, mock2):
        """
        In this scenario we want to test the functionality of Configuration API when
        it is called by a http 'get' method.
        For the above purpose first we create some configurations in the database and then
        we send a http 'get' method to retrieve a list of them.
        We expect that the status code of response be '200 ok' and
        the json format of response be as below .
        :return:
        """
        # Create Objects configuration in database
        configs = dict(ConfigurationValueApiTest.default_configs)
        configs['TOTAL_REWARD'] = int(40e9)
        configs['REWARD_FACTOR'] = 1
        configs['POOL_BASE_FACTOR'] = 1
        # response of API /config/value should be this
        result = {
            "reward": int(40e9),
            "wallet_address": "3WwYLP3oDYogUc8x9BbcnLZvpVqT5Zc77RHjoy19PyewAJMy9aDM",
            "pool_base_factor": 1,
            "max_chunk_size": settings.SHARE_CHUNK_SIZE,
        }

        # send a http 'get' request to the configuration endpoint
        ConfigurationValueApiTest.returned_configs = configs
        response = self.client.get('/api/config/value/')
        # check the status of the response
        self.assertEqual(response.status_code, 200)
        # check the content of the response
        self.assertEqual(response.json(), result)

    @patch("requests.get", side_effect=mocked_requests_get)
    @patch("Api.utils.general.General.node_request", side_effect=mocked_node_request)
    def test_configuration_api_get_method_pk(self, mock, mock2):
        """
        In this scenario we want to test the functionality of Configuration API when
        it is called by a http 'get' method with custom pk.
        For the above purpose first we create some configurations in the database and then
        we send a http 'get' method to retrieve a list of them.
        We expect that the status code of response be '200 ok' and
        the json format of response be as below .
        :return:
        """
        # Create Objects configuration in database
        configs = dict(ConfigurationValueApiTest.default_configs)
        configs['TOTAL_REWARD'] = int(40e9)
        configs['REWARD_FACTOR'] = 1
        configs['POOL_BASE_FACTOR'] = 1
        # response of API /config/value should be this
        result = {
            "reward": int(40e9),
            "wallet_address": "3WwYLP3oDYogUc8x9BbcnLZvpVqT5Zc77RHjoy19PyewAJMy9aDM",
            "pool_base_factor": 1,
            "max_chunk_size": settings.SHARE_CHUNK_SIZE,
        }

        # send a http 'get' request to the configuration endpoint
        ConfigurationValueApiTest.returned_configs = configs
        pk = "thisisatestpk"
        response = self.client.get('/api/config/value/' + pk + "/")
        # check the status of the response
        self.assertEqual(response.status_code, 200)
        # check the content of the response
        self.assertEqual(response.json(), result)


class TestValidateShare(TransactionTestCase):
    reset_sequences = True
    default_configs = {
        'POOL_BASE_FACTOR': 1000,
        'TOTAL_REWARD': int(67.5e9),
        "REWARD_FACTOR_PRECISION": 2,
        'REWARD_FACTOR': 0.96296297,
        'SHARE_CHUNK_SIZE': 10,
        'THRESHOLD_HEIGHT': 10,
        'THRESHOLD_TIMESTAMP': 120000
    }

    returned_configs = None

    def mocked_requests_get(*args, **kwargs):
        """
        mock function requests.get
        """

        class MockResponse:
            def __init__(self, json_data, status_code):
                self.json_data = json_data
                self.status_code = status_code

            def json(self):
                return self.json_data

        url = args[0]

        if url == urljoin(ACCOUNTING_URL, 'conf/'):
            return MockResponse(TestProofValidate.returned_configs, 200)

    def mocked_node_request(*args, **kwargs):
        """
        mock function node_request for urls and 'info'
        """
        if args[0] == "info":
            return {
                "status": "success",
                "response": {
                    "difficulty": TestValidateShare.default_configs['POOL_BASE_FACTOR']
                }
            }

    def mocked_account_request(*args, **kwargs):
        """
        mock function __save_share for send share to accounting
        """
        return {"status": "ok"}

    def mocked_node_request_status_valid(*args, **kwargs):
        """
        mock function node_request for urls 'mining/candidate and 'info'
        """
        if args[0] == "info":
            return {
                "status": "success",
                "response": {
                    "headersHeight": 41496,
                    "difficulty": TestValidateShare.default_configs['POOL_BASE_FACTOR'] * pow(10, 8)
                }
            }

    @patch("requests.get", side_effect=mocked_requests_get)
    @patch("Api.utils.share.ValidateShare.save_share", side_effect=mocked_account_request)
    @patch("Api.utils.general.General.node_request", side_effect=mocked_node_request)
    def test_status_solved_lesX(self, mock_node, accounting_mock, mock):
        """
        Solution
        Check that d < b and left == right for a share solved.
        """

        share = {
            "pk": "03cd07843e1f7e25407eda2369ad644854e532e381ab30d6488970e0b87d060d16",
            "w": "0370b32976a9bc37654e6b34390c8dd30d3dc44c3f52e9421cc4ec31ef6a1bca4c",
            "nonce": "00000237d4e1e20c",
            "d": 46242367293113109317096091884217605312791141894953570819396709798327,
            "msg": "fc0ecfe7a0559c556cb5fe25dd9259e5b548a33502be0c474cd581f77f0acb89",
            "tx_id": "53c538c7f7fcc79e2980ce41ac65ddf9d3db979a9aeeccd9b46d8e81a8a291d5",
            "block": {
                "height": 41496,
                "parent": "46062b27d06c1155898ce2a04db6686a84af710135e87dfb89eaac4a32b58a48",
                "next": ["c6f36cf7ea4a5acd51f74e021f697606e455f0b1376d95c7a102578a7a8bdb03"]
            },
            "addresses": {
                "miner": "test",
                "lock": "test",
                "withdraw": "test"
            },
            "client_ip": '127.0.0.1'
        }

        configs = dict(TestProofValidate.default_configs)
        TestProofValidate.returned_configs = configs

        to_hash = share['w'] + share['nonce'] + str(share['d'])
        pow_identity = blake2b(to_hash.encode('utf-8'), digest_size=32).hexdigest()

        block = ValidateShare()
        block.validate(share['pk'], share['w'], share['nonce'], share['d'], share['msg'], share['tx_id'],
                       share['block'], share['addresses'], share['client_ip'])
        accounting_mock.assert_has_calls([call({
            'miner': '03cd07843e1f7e25407eda2369ad644854e532e381ab30d6488970e0b87d060d16',
            'share': 'a8794c0719bbe03afe6ff4926d56d59aeb3c2438d7396b7c4c4fd5aa064288df',
            'status': 'solved',
            "pow_identity": pow_identity,
            'difficulty': 1,
            'transaction_id': '53c538c7f7fcc79e2980ce41ac65ddf9d3db979a9aeeccd9b46d8e81a8a291d5',
            'block': {
                'height': 41496,
                'parent': '46062b27d06c1155898ce2a04db6686a84af710135e87dfb89eaac4a32b58a48',
                'next': ['c6f36cf7ea4a5acd51f74e021f697606e455f0b1376d95c7a102578a7a8bdb03']
            },
            "addresses": {
                "miner": "test",
                "lock": "test",
                "withdraw": "test"
            },
            "client_ip": '127.0.0.1'
        })])

    @patch("requests.get", side_effect=mocked_requests_get)
    @patch("Api.utils.share.ValidateShare.save_share", side_effect=mocked_account_request)
    @patch("Api.utils.general.General.node_request", side_effect=mocked_node_request_status_valid)
    def test_status_valid(self, mock_node, accounting_mock, mock):
        """
        Solution
        Check that d < b and left == right for a share solved.
        """

        share = {
            "pk": "03cd07843e1f7e25407eda2369ad644854e532e381ab30d6488970e0b87d060d16",
            "w": "0370b32976a9bc37654e6b34390c8dd30d3dc44c3f52e9421cc4ec31ef6a1bca4c",
            "nonce": "00000237d4e1e20c",
            "d": 46242367293113109317096091884217605312791141894953570819396709798327,
            "msg": "fc0ecfe7a0559c556cb5fe25dd9259e5b548a33502be0c474cd581f77f0acb89",
            "tx_id": "53c538c7f7fcc79e2980ce41ac65ddf9d3db979a9aeeccd9b46d8e81a8a291d5",
            "block": {
                "height": 1234,
                "parent": "46062b27d06c1155898ce2a04db6686a84af710135e87dfb89eaac4a32b58a48",
                "next": ["c6f36cf7ea4a5acd51f74e021f697606e455f0b1376d95c7a102578a7a8bdb03"],
                "path": '-1'
            },
            "addresses": {
                "miner": "test",
                "lock": "test",
                "withdraw": "test"
            },
            "client_ip": '127.0.0.1'
        }

        configs = dict(TestProofValidate.default_configs)
        TestProofValidate.returned_configs = configs

        block = ValidateShare()
        block.validate(share['pk'], share['w'], share['nonce'], share['d'], share['msg'], share['tx_id'],
                       share['block'], share['addresses'], share['client_ip'])
        accounting_mock.assert_has_calls([call({
            'miner': '03cd07843e1f7e25407eda2369ad644854e532e381ab30d6488970e0b87d060d16',
            'share': 'a8794c0719bbe03afe6ff4926d56d59aeb3c2438d7396b7c4c4fd5aa064288df',
            'status': 'valid',
            'difficulty': pow(10, 8),
            "block": {
                "height": 1234,
                "parent": "46062b27d06c1155898ce2a04db6686a84af710135e87dfb89eaac4a32b58a48",
                "next": ["c6f36cf7ea4a5acd51f74e021f697606e455f0b1376d95c7a102578a7a8bdb03"],
                "path": '-1'
            },
            "addresses": {
                "miner": "test",
                "lock": "test",
                "withdraw": "test"
            },
            "client_ip": '127.0.0.1',
            'pow_identity': 'e1945de077147d2473522e724f35f9188c5797e879b695fb969b1292a15fb21f'
        })])

    @patch("requests.get", side_effect=mocked_requests_get)
    @patch("Api.utils.share.ValidateShare.save_share", side_effect=mocked_account_request)
    @patch("Api.utils.general.General.node_request", side_effect=mocked_node_request)
    def test_status_invalid(self, mock_setting, accounting_mock, mock):
        """
         Solution
         Check that d > POOL_DIFFICULTY or left != right for a share invalid.
         """
        mock_setting.POOL_DIFFICULTY = 125792089237316195423570985008687907852837564279074904382605163141518161494337

        share = {
            "pk": "0354043bd5f16526b0184e6521a0bd462783f8B178db37ec034328a23fed4855a9",
            "w": "03b783831ab40435c02bf0b3225890540b9689db3c93d4b0bdb32e5a837f281438",
            "nonce": "0000000000400ee0",
            "d": 99693760199151170059172331486081907352237598845267005513376026899853403721406,
            "msg": "f548e38f716e90f52078880c7cdc5a81e27676b26b9b9251b5539e6b1df2ffb5",
            "tx_id": "53c538c7f7fcc79e2980ce41ac65ddf9d3db979a9aeeccd9b46d8e81a8a291d5",
            "block": {
                "parent": "46062b27d06c1155898ce2a04db6686a84af710135e87dfb89eaac4a32b58a48",
                "next": ["c6f36cf7ea4a5acd51f74e021f697606e455f0b1376d95c7a102578a7a8bdb03"]
            },
            "addresses": {
                "miner": "test",
                "lock": "test",
                "withdraw": "test"
            },
            "client_ip": '127.0.0.1'
        }

        configs = dict(TestProofValidate.default_configs)
        TestProofValidate.returned_configs = configs

        block = ValidateShare()
        block.validate(share['pk'], share['w'], share['nonce'], share['d'], share['msg'], share['tx_id'],
                       share['block'], share['addresses'], share['client_ip'])
        # check status for this block is invalid
        accounting_mock.assert_has_calls([call({
            'miner': '0354043bd5f16526b0184e6521a0bd462783f8B178db37ec034328a23fed4855a9',
            'share': '45826fc44e975ce98100580a0164e8599c71344e8863d9dae493b01e88325329',
            "status": "invalid",
            'difficulty': 1,
            "client_ip": '127.0.0.1'
        })])

    def test_type_input_d_str(self):
        block = ValidationShareSerializer()
        output = block.validate_d("46242367293113109317096091884217605312791141894953570819396709798327")
        self.assertEqual(output, 46242367293113109317096091884217605312791141894953570819396709798327)

    def test_type_input_d_invalid(self):
        block = ValidationShareSerializer()
        # check Raise exception
        with self.assertRaises(ValidationError):
            block.validate_d("462?2367293113109317096091884217605312791141894953570819396709798327")

    def test_ec_point_start_byte_2(self):
        block = ValidateShare()
        output = block._ValidateShare__ec_point(
            decode("0254043bd5f16526b0184e6521a0bd462783f8B178db37ec034328a23fed4855a9", "hex"))
        self.assertEqual(output['value'].x,
                         38001759640178464358233514318285492856403682368769743827942002958530733692329)
        self.assertEqual(output['value'].y,
                         47862723537995571517279590967139629780302343405661481110647004256081707204458)

    def test_ec_point_start_byte_except_2_3(self):
        block = ValidateShare()
        # check Raise exception
        with self.assertRaises(ValidationError):
            block._ValidateShare__ec_point(
                decode("0454043bd5f16526b0184e6521a0bd462783f8B178db37ec034328a23fed4855a9", "hex"))

    def test_gen_indexes(self):
        """
        input function gen_indexes is concat array-bytes of msg and nonce
        """
        msg = "cfc5f330a71a99616453b18e572ee06a7e045e0c2f6cf35ce7d490572ec7a2ac".encode("ascii")
        nonce = "000000058B1CE60D".encode("ascii")
        block = ValidateShare()
        output = block._ValidateShare__gen_indexes(msg + nonce)
        self.assertEqual(output, [54118084, 29803733, 46454084, 13976688, 21262480, 7376957, 9452803, 3998647, 17020853,
                                  62371271, 62244663, 29833011, 53949362, 53719676, 62029037, 41741671, 15558442,
                                  23538307, 53117732, 42149055, 52740024, 12564581, 62416135, 6620933, 17237427,
                                  50705181, 28515596, 52235322, 17578593, 3826135, 39966521, 30882246])

    def test_gen_element(self):
        """
        input function gen_element is message, pk, w, member of output gen_indexes
        """
        msg = "cfc5f330a71a99616453b18e572ee06a7e045e0c2f6cf35ce7d490572ec7a2ac".encode("ascii")
        p1 = "02385E11D92F8AC74155878EE318B8A0FC4FC1FDA9D1D48A5EC34778F55DF01C6C".encode("ascii")
        p2 = "02600D9BEEE35425E5C467A4295D49EDAEF15E22C8B2EF7E916A9BE30EC7DA3B65".encode("ascii")
        out_gen_indexes = 54118084
        block = ValidateShare()
        output = block._ValidateShare__gen_element(msg, p1, p2, struct.pack(">I", out_gen_indexes))
        self.assertEqual(output, 1442183731460476782005370820367939156210879287829514232459313282341328232038)

    @patch("requests.get", side_effect=mocked_requests_get)
    @patch("Api.utils.share.ValidateShare.save_share", side_effect=mocked_account_request)
    @patch("Api.utils.general.General.node_request", side_effect=mocked_node_request)
    def test_status_invalid_wrong_input(self, mock_node, accounting_mock, mock):
        """
         Test for input wrong, params not hex and in this test, we must get status invalid for a public_key.
         """
        share = {
            "pk": "0354043bd5f16526b0184e6521a0bd462783f8b178db37ec034328a23fed4855a9",
            "w": "1",
            "nonce": "1",
            "d": 1,
            "msg": "f548e38f716e90f52078880c7cdc5a81e27676b26b9b9251b5539e6b1df2ffb5",
            "tx_id": "53c538c7f7fcc79e2980ce41ac65ddf9d3db979a9aeeccd9b46d8e81a8a291d5",
            'block': {
                "parent": "46062b27d06c1155898ce2a04db6686a84af710135e87dfb89eaac4a32b58a48",
                "next": ["c6f36cf7ea4a5acd51f74e021f697606e455f0b1376d95c7a102578a7a8bdb03"]
            },
            "addresses": {
                "miner": "test",
                "lock": "test",
                "withdraw": "test"
            },
            "client_ip": '127.0.0.1'
        }

        configs = dict(TestProofValidate.default_configs)
        TestProofValidate.returned_configs = configs

        block = ValidateShare()
        block.validate(share['pk'], share['w'], share['nonce'], share['d'], share['msg'], share['tx_id'],
                       share['block'], share['addresses'], share["client_ip"])
        accounting_mock.assert_has_calls([call({
            'miner': '0354043bd5f16526b0184e6521a0bd462783f8b178db37ec034328a23fed4855a9',
            'share': '2e2c55ba14e05fa1291621afd5611f8a828f5b0dfeea6e8c7724327bba47a7ef',
            "status": "invalid",
            'difficulty': 1,
            "client_ip": '127.0.0.1'
        })])


class TestProofValidate(TransactionTestCase):
    reset_sequences = True
    default_configs = {
        'POOL_BASE_FACTOR': 1000,
        'TOTAL_REWARD': int(67.5e9),
        "REWARD_FACTOR_PRECISION": 2,
        'REWARD_FACTOR': 0.96296297,
        'SHARE_CHUNK_SIZE': 10,
        'THRESHOLD_HEIGHT': 10,
        'THRESHOLD_TIMESTAMP': 120000
    }

    returned_configs = None

    def mocked_node_request(*args, **kwargs):
        """
        mock function node_request for urls 'info', '/blocks/lastHeaders/', '/blocks/at/'and '/blocks/chainSlice'
        """
        if args[0] == "info":
            return {
                "status": "success",
                "response": {
                    "headersHeight": 40670,
                    "difficulty": 5942804479
                }
            }
        elif args[0] == "/blocks/lastHeaders/1":
            return {
                "status": "success",
                "response": [{
                    "headersHeight": 40670,
                    "difficulty": 5942804479,
                    "timestamp": 1574114138065
                }]
            }
        elif args[0] == "/blocks/at/40671":
            return {
                "status": "success",
                "response": ["c6f36cf7ea4a5acd51f74e021f697606e455f0b1376d95c7a102578a7a8bdb03"]
            }
        elif "/blocks/chainSlice?fromHeight" in args[0]:
            return {
                "status": "success",
                "response": [{
                    "id": "e845c88d5044b0f427ac15a444b172e4eb7b3c13ce321a33bc49b8521fff53e8",
                    "height": 40661
                }, {
                    "id": "12ddb75ecc751dd02d481e3f7d7d758d2c00ff5060973ff74babb6a09a8a4df6",
                    "height": 40662
                }, {
                    "id": "032cd8177c7d8133d04ec5d88e724830b0b74f980b99a90ff011f4856fd3088d",
                    "height": 40663
                }, {
                    "id": "46062b27d06c1155898ce2a04db6686a84af710135e87dfb89eaac4a32b58a48",
                    "height": 40670
                }]
            }

    def mocked_node_request_invalid_difficulty(*args, **kwargs):
        """
        mock function node_request for urls and 'info'
        """
        if args[0] == "info":
            return {
                "status": "success",
                "response": {
                    "headersHeight": 40670,
                    "difficulty": 111567634401280
                }
            }
        elif args[0] == "/blocks/lastHeaders/1":
            return {
                "status": "success",
                "response": [{
                    "headersHeight": 40670,
                    "difficulty": 111467634401280,
                    "timestamp": 1574114138065
                }]
            }

    def mocked_requests_get(*args, **kwargs):
        """
        mock function requests.get
        """

        class MockResponse:
            def __init__(self, json_data, status_code):
                self.json_data = json_data
                self.status_code = status_code

            def json(self):
                return self.json_data

        url = args[0]

        if url == urljoin(ACCOUNTING_URL, 'conf/'):
            return MockResponse(TestProofValidate.returned_configs, 200)

    @patch("requests.get", side_effect=mocked_requests_get)
    @patch("Api.utils.general.General.node_request", side_effect=mocked_node_request)
    def test_valid(self, mock_node, mock):
        """
        In this scenario we want to test a valid proof.
        send a valid data to function validate from proof serializer and want to get status valid and message
         The proof is valid.
        :return:
        """
        proof_data = {
            "pk": "0354043bd5f16526b0184e6521a0bd462783f8b178db37ec034328a23fed4855a9",
            "msg_pre_image": "0146062b27d06c1155898ce2a04db6686a84af710135e87dfb89eaac4a32b58a4872011e52944ffdcd5e7f745ba14df4487ce8cf30f9b02a2be0c5a1096f8b612c190194448af0d8c9ae2170a7d970f621d18707dc4c2d5e9ec168adb1895e5cbbc555853afe04d0a87819523798e4db5f1b75fd43512cf76c5a3ce5eb8527725e12d1c3f9e0eb2db112e2d742dc71c6aa2df4b35fec85d8c28f6dc954796f3f95c308721e60cc9505016238dfbd02000000",
            "leaf": "53c538c7f7fcc79e2980ce41ac65ddf9d3db979a9aeeccd9b46d8e81a8a291d5",
            "levels": ["01c9a7e42a405a771add3b28b2538731577322930648b08ef4e5fd98854c064a7a"]
        }
        configs = dict(TestProofValidate.default_configs)
        TestProofValidate.returned_configs = configs
        # Create object from class ValidateProofSerializer and call function validate for validation Proof
        proof = ValidateProofSerializer()
        response = proof.validate(proof_data)
        # check the content of the response
        self.assertEqual(response['msg'], 'dc56c734a2956a640bc4efe00c3b5fa5b9cd7337cd086f2ab735e71402a44668')
        self.assertEqual(response['block'], {
            "height": 40671,
            "parent": "46062b27d06c1155898ce2a04db6686a84af710135e87dfb89eaac4a32b58a48",
            "next": ["c6f36cf7ea4a5acd51f74e021f697606e455f0b1376d95c7a102578a7a8bdb03"],
            "path": '4'
        })
        self.assertEqual(response['message'], 'The proof is valid.')
        self.assertEqual(response['status'], 'valid')

    @patch("requests.get", side_effect=mocked_requests_get)
    @patch("Api.utils.general.General.node_request", side_effect=mocked_node_request)
    def test_invalid(self, mock_node, mock):
        """
        In this scenario we want to test a invalid proof leaf_hash != txs_root.
        send a invalid data to function validate from proof serializer and want to get status invalid and message
         The proof is invalid.
        :return:
        """
        proof_data = {
            "pk": "0354043bd5f16526b0184e6521a0bd462783f8b178db37ec034328a23fed4855a9",
            "msg_pre_image": "0146062b27d06c1155898ce2a04db6686a84af710135e87dfb89eaac4a32b58a4872011e52944ffdcd5e7f745ba14df4487ce8cf30f9b02a2be0c5a1096f8b612c190194448af0d8c9ae2170a7d970f621d18707dc4c2d5e9ec168adb1895e5cbbc555853afe04d0a87819523798e4db5f1b75fd43512cf76c5a3ce5eb8527725e12d1c3f9e0eb2db112e2d742dc71c6aa2df4b35fec85d8c28f6dc954796f3f95c308721e60cc9505016238dfbd02000000",
            "leaf": "53c538c7f7fcc79e2980ce41ac65ddf9d3db979a9aeeccd9b46d8e81a8a291d5",
            "levels": ["00c9a7e42a405a771add3b28b2538731577322930648b08ef4e5fd98854c064a7a"]
        }
        configs = dict(TestProofValidate.default_configs)
        TestProofValidate.returned_configs = configs
        # Create object from class ValidateProofSerializer and call function validate for validation Proof
        proof = ValidateProofSerializer()
        # check Raise exception
        with self.assertRaises(ValidationError):
            proof.validate(proof_data)

    @patch("requests.get", side_effect=mocked_requests_get)
    @patch("Api.utils.general.General.node_request", side_effect=mocked_node_request_invalid_difficulty)
    def test_invalid_difficulty(self, mock_node, mock):
        """
        In this scenario we want to test a invalid proof leaf_hash != txs_root.
        send a invalid data to function validate from proof serializer and want to get status invalid and message
         The proof is invalid.
        :return:
        """
        proof_data = {
            "pk": "0354043bd5f16526b0184e6521a0bd462783f8b178db37ec034328a23fed4855a9",
            "msg_pre_image": "0146062b27d06c1155898ce2a04db6686a84af710135e87dfb89eaac4a32b58a4872011e52944ffdcd5e7f745ba14df4487ce8cf30f9b02a2be0c5a1096f8b612c190194448af0d8c9ae2170a7d970f621d18707dc4c2d5e9ec168adb1895e5cbbc555853afe04d0a87819523798e4db5f1b75fd43512cf76c5a3ce5eb8527725e12d1c3f9e0eb2db112e2d742dc71c6aa2df4b35fec85d8c28f6dc954796f3f95c308721e60cc9505016238dfbd02000000",
            "leaf": "53c538c7f7fcc79e2980ce41ac65ddf9d3db979a9aeeccd9b46d8e81a8a291d5",
            "levels": ["00c9a7e42a405a771add3b28b2538731577322930648b08ef4e5fd98854c064a7a"]
        }
        configs = dict(TestProofValidate.default_configs)
        TestProofValidate.returned_configs = configs
        # Create object from class ValidateProofSerializer and call function validate for validation Proof
        proof = ValidateProofSerializer()
        # check Raise exception
        with self.assertRaises(ValidationError):
            proof.validate(proof_data)


class TestValidation(TransactionTestCase):
    reset_sequences = True
    default_configs = {
        'POOL_BASE_FACTOR': 1000,
        'TOTAL_REWARD': int(67.5e9),
        "REWARD_FACTOR_PRECISION": 2,
        'REWARD_FACTOR': 0.96296297,
        'SHARE_CHUNK_SIZE': 10,
        'THRESHOLD_HEIGHT': 10,
        'THRESHOLD_TIMESTAMP': 120000
    }

    returned_configs = None

    def mocked_node_request(*args, **kwargs):
        """
        mock function node_request for urls 'info', 'transactions/check', 'wallet/addresses', '/blocks/lastHeaders/',
         '/blocks/chainSlice', '/blocks/at/' and 'utils/ergoTreeToAddress/'
        """
        if args[0] == "transactions/check":
            return {
                "status": "success",
                "response": "7fdfae7a85ad26ffc838d7c6042cbfc67781e83bc846c9d652f1023dc795e30e"
            }
        elif args[0] == "wallet/addresses":
            return {
                "status": "success",
                "response": ["3WwYLP3oDYogUc8x9BbcnLZvpVqT5Zc77RHjoy19PyewAJMy9aDM"]
            }
        elif "script/addressToTree/3WwYLP3oDYogUc8x9BbcnLZvpVqT5Zc77RHjoy19PyewAJMy9aDM" in args[0]:
            return {
                "status": "success",
                "response": {
                    "tree": "0008cd0314d842b4a3dd0d3c4ecda472365b07f2f61f723f61113db131f3fdaab02df1e6"
                }
            }
        elif args[0] == "info":
            return {
                "status": "success",
                "response": {
                    "headersHeight": 40670,
                    "difficulty": 3888644095
                }
            }
        elif args[0] == "/blocks/lastHeaders/1":
            return {
                "status": "success",
                "response": [{
                    "headersHeight": 40670,
                    "difficulty": 3888644095,
                    "timestamp": 1574114138065
                }]
            }
        elif args[0] == "/blocks/at/97666":
            return {
                "status": "success",
                "response": ["c6f36cf7ea4a5acd51f74e021f697606e455f0b1376d95c7a102578a7a8bdb03"]
            }
        elif "/blocks/chainSlice?fromHeight" in args[0]:
            return {
                "status": "success",
                "response": [{
                    "id": "e845c88d5044b0f427ac15a444b172e4eb7b3c13ce321a33bc49b8521fff53e8",
                    "height": 40661
                }, {
                    "id": "12ddb75ecc751dd02d481e3f7d7d758d2c00ff5060973ff74babb6a09a8a4df6",
                    "height": 40662
                }, {
                    "id": "032cd8177c7d8133d04ec5d88e724830b0b74f980b99a90ff011f4856fd3088d",
                    "height": 40663
                }, {
                    "id": "d3a0ee8c30a4243efced2d3927fc760ae102670f1d7328ee48cd3a2954e08bd2",
                    "height": 40670
                }]
            }

    def mocked_node_request_invalid(*args, **kwargs):
        """
        mock function node_request for urls 'info', 'transactions/check', 'wallet/addresses', '/blocks/lastHeaders/',
         '/blocks/chainSlice', '/blocks/at/' and 'utils/ergoTreeToAddress/'
        """
        if args[0] == "transactions/check":
            return {
                "status": "success",
                "response": "1fdfae7a85ad26ffc838d7c6042cbfc67781e83bc846c9d652f1023dc795e30e"
            }
        elif args[0] == "wallet/addresses":
            return {
                "status": "success",
                "response": ["3WwYLP3oDYogUc8x9BbcnLZvpVqT5Zc77RHjoy19PyewAJMy9aDM"]
            }
        elif "script/addressToTree/3WwYLP3oDYogUc8x9BbcnLZvpVqT5Zc77RHjoy19PyewAJMy9aDM" in args[0]:
            return {
                "status": "success",
                "response": {
                    "tree": "0008cd0314d842b4a3dd0d3c4ecda472365b07f2f61f723f61113db131f3fdaab02df1e6"
                }
            }
        elif args[0] == "info":
            return {
                "status": "success",
                "response": {
                    "headersHeight": 40670,
                    "difficulty": 3888644095
                }
            }
        elif args[0] == "/blocks/lastHeaders/1":
            return {
                "status": "success",
                "response": [{
                    "headersHeight": 40670,
                    "difficulty": 3888644095,
                    "timestamp": 1574114138065
                }]
            }
        elif args[0] == "/blocks/at/97666":
            return {
                "status": "success",
                "response": ["c6f36cf7ea4a5acd51f74e021f697606e455f0b1376d95c7a102578a7a8bdb03"]
            }
        elif "/blocks/chainSlice?fromHeight" in args[0]:
            return {
                "status": "success",
                "response": [{
                    "id": "e845c88d5044b0f427ac15a444b172e4eb7b3c13ce321a33bc49b8521fff53e8",
                    "height": 40661
                }, {
                    "id": "12ddb75ecc751dd02d481e3f7d7d758d2c00ff5060973ff74babb6a09a8a4df6",
                    "height": 40662
                }, {
                    "id": "032cd8177c7d8133d04ec5d88e724830b0b74f980b99a90ff011f4856fd3088d",
                    "height": 40663
                }, {
                    "id": "d3a0ee8c30a4243efced2d3927fc760ae102670f1d7328ee48cd3a2954e08bd2",
                    "height": 40670
                }]
            }

    def mocked_requests_get_wrong_id(*args, **kwargs):
        """
        mock function requests.get
        """

        class MockResponse:
            def __init__(self, json_data, status_code):
                self.json_data = json_data
                self.status_code = status_code

            def json(self):
                return self.json_data

        url = args[0]

        if url == urljoin(VERIFIER_ADDRESS, 'address_to_pk'):
            return MockResponse({
                'success': True,
                'id': '02385E11D92F8AC74155878EE318B8A0FC4FC1FDA9D1D48A5EC34778F55DF01C6C',
            }, 200)

        if url == urljoin(ACCOUNTING_URL, 'conf/'):
            return MockResponse(TestValidation.returned_configs, 200)

        if url == urljoin(VERIFIER_ADDRESS, 'get_id'):
            return MockResponse({
                'success': True,
                'id': 'wrong_id'
            }, 200)

    def mocked_requests_get_wrong_pk(*args, **kwargs):
        """
        mock function requests.get
        """

        class MockResponse:
            def __init__(self, json_data, status_code):
                self.json_data = json_data
                self.status_code = status_code

            def json(self):
                return self.json_data

        url = args[0]

        if url == urljoin(VERIFIER_ADDRESS, 'address_to_pk'):
            return MockResponse({
                'success': True,
                'id': 'wrong pk',
            }, 200)

        if url == urljoin(ACCOUNTING_URL, 'conf/'):
            return MockResponse(TestValidation.returned_configs, 200)

    def mocked_requests_get(*args, **kwargs):
        """
        mock function requests.get
        """

        class MockResponse:
            def __init__(self, json_data, status_code):
                self.json_data = json_data
                self.status_code = status_code

            def json(self):
                return self.json_data

        url = args[0]

        if url == urljoin(VERIFIER_ADDRESS, 'address_to_pk'):
            return MockResponse({
                'success': True,
                'id': '02385E11D92F8AC74155878EE318B8A0FC4FC1FDA9D1D48A5EC34778F55DF01C6C',
            }, 200)

        if url == urljoin(ACCOUNTING_URL, 'conf/'):
            return MockResponse(TestValidation.returned_configs, 200)

        if url == urljoin(VERIFIER_ADDRESS, 'get_id'):
            return MockResponse({
                'success': True,
                'id': kwargs['json']['id']
            }, 200)

    def mocked_node_request_block_mined(*args, **kwargs):
        """
        mock function node_request for urls 'transactions/check', 'wallet/addresses' and 'utils/ergoTreeToAddress/'
        """
        if args[0] == "transactions/check":
            return {
                "status": "External Error",
                "response": {
                    "detail": "blah blah every input of the transaction should be in utxo blah blah"
                }
            }
        elif args[0] == "wallet/addresses":
            return {
                "status": "success",
                "response": ["3WwYLP3oDYogUc8x9BbcnLZvpVqT5Zc77RHjoy19PyewAJMy9aDM"]
            }
        elif "script/addressToTree/3WwYLP3oDYogUc8x9BbcnLZvpVqT5Zc77RHjoy19PyewAJMy9aDM" in args[0]:
            return {
                "status": "success",
                "response": {
                    "tree": "0008cd0314d842b4a3dd0d3c4ecda472365b07f2f61f723f61113db131f3fdaab02df1e6"
                }
            }
        elif args[0] == "info":
            return {
                "status": "success",
                "response": {
                    "headersHeight": 40670,
                    "difficulty": 3888644095
                }
            }
        elif args[0] == "/blocks/lastHeaders/1":
            return {
                "status": "success",
                "response": [{
                    "headersHeight": 40670,
                    "difficulty": 3888644095,
                    "timestamp": 1574114138065
                }]
            }
        elif args[0] == "/blocks/at/97666":
            return {
                "status": "success",
                "response": ["c6f36cf7ea4a5acd51f74e021f697606e455f0b1376d95c7a102578a7a8bdb03"]
            }
        elif "/blocks/chainSlice?fromHeight" in args[0]:
            return {
                "status": "success",
                "response": [{
                    "id": "e845c88d5044b0f427ac15a444b172e4eb7b3c13ce321a33bc49b8521fff53e8",
                    "height": 40661
                }, {
                    "id": "12ddb75ecc751dd02d481e3f7d7d758d2c00ff5060973ff74babb6a09a8a4df6",
                    "height": 40662
                }, {
                    "id": "032cd8177c7d8133d04ec5d88e724830b0b74f980b99a90ff011f4856fd3088d",
                    "height": 40663
                }, {
                    "id": "d3a0ee8c30a4243efced2d3927fc760ae102670f1d7328ee48cd3a2954e08bd2",
                    "height": 40670
                }]
            }

        elif "blocks/chainSlice" in args[0]:
            return {
                "status": "success",
                "response": [{
                    "extensionId": "03f9fb64f0705614d9a0808024a440736cfb0277825b1d691c020c28da0d7d4b",
                    "difficulty": "3888644096",
                    "votes": "040000",
                    "timestamp": 1580688457671,
                    "size": 283,
                    "stateRoot": "0e561c78728bef60886c020b96b28fb6f9e1feddfe148fc14e4998d684605df914",
                    "height": 97956,
                    "nBits": 83945416,
                    "version": 1,
                    "id": "5c9d34a3fd6d691580ff3e1f9beca9b047ab13ef349d99e7d43639db624994cf",
                    "adProofsRoot": "f253c40e3012e647b157909b0ae7c0cba21e791638cec5fce499ce7c1a86ef32",
                    "transactionsRoot": "f20e33850506170ba21258a0f16784e85ef6943ba5cd9e7838ba12d2a2895281",
                    "extensionHash": "0e89a57d29a428567c48c9152a3c86197f46f94c09171968cff7e8f3f908873e",
                    "powSolutions": {
                        "pk": "0354efc32652cad6cf1231be987afa29a686af30b5735995e3ce51339c4d0ca380",
                        "w": "0361346c34a7eab4284862be86d290462b36888b7441caed7013de31ec21398ed5",
                        "n": "000005d8c17b7c2b",
                        "d": 29096729143384357727218333975771617924424631306711899957319626220230
                    },
                    "adProofsId": "d88e1873ca16ebdf52bd7205e1e0912711acce7d0bfdb350db5c4a400e8f5447",
                    "transactionsId": "299ac89bbcd51245167a495d19772df2ad5fdd3f07414e63e237d9b636a58f36",
                    "parentId": "7e0bb35f8bb090888f743203bc3102dca6d21514d48da1be9c318e0220072ff0"
                }]
            }

    def mocked_node_request_external_error_needs_custom_context(*args, **kwargs):
        """
        mock function node_request for urls 'transactions/check', 'wallet/addresses' and 'utils/ergoTreeToAddress/'
        """
        if args[0] == "transactions/check":
            return {
                "status": "External Error",
                "response": {
                    "detail": "blah blah scripts of all transaction inputs should pass verification blah blah"
                }
            }

        elif args[0] == "wallet/addresses":
            return {
                "status": "success",
                "response": ["3WwYLP3oDYogUc8x9BbcnLZvpVqT5Zc77RHjoy19PyewAJMy9aDM"]
            }
        elif "script/addressToTree/3WwYLP3oDYogUc8x9BbcnLZvpVqT5Zc77RHjoy19PyewAJMy9aDM" in args[0]:
            return {
                "status": "success",
                "response": {
                    "tree": "0008cd0314d842b4a3dd0d3c4ecda472365b07f2f61f723f61113db131f3fdaab02df1e6"
                }
            }
        elif args[0] == "info":
            return {
                "status": "success",
                "response": {
                    "headersHeight": 40670,
                    "difficulty": 3888644095
                }
            }
        elif args[0] == "/blocks/lastHeaders/1":
            return {
                "status": "success",
                "response": [{
                    "headersHeight": 40670,
                    "difficulty": 3888644095,
                    "timestamp": 1574114138065
                }]
            }
        elif args[0] == "/blocks/at/97666":
            return {
                "status": "success",
                "response": ["c6f36cf7ea4a5acd51f74e021f697606e455f0b1376d95c7a102578a7a8bdb03"]
            }
        elif "/blocks/chainSlice?fromHeight" in args[0]:
            return {
                "status": "success",
                "response": [{
                    "id": "e845c88d5044b0f427ac15a444b172e4eb7b3c13ce321a33bc49b8521fff53e8",
                    "height": 40661
                }, {
                    "id": "12ddb75ecc751dd02d481e3f7d7d758d2c00ff5060973ff74babb6a09a8a4df6",
                    "height": 40662
                }, {
                    "id": "032cd8177c7d8133d04ec5d88e724830b0b74f980b99a90ff011f4856fd3088d",
                    "height": 40663
                }, {
                    "id": "d3a0ee8c30a4243efced2d3927fc760ae102670f1d7328ee48cd3a2954e08bd2",
                    "height": 40670
                }]
            }

    def mocked_requests_post_verified(*args, **kwargs):
        """
        mock function requests.get
        """

        class MockResponse:
            def __init__(self, json_data, status_code):
                self.json_data = json_data
                self.status_code = status_code

            def json(self):
                return self.json_data

        url = args[0]
        if url == urljoin(VERIFIER_ADDRESS, 'verify'):
            return MockResponse({
                'success': True,
                'verified': True,
            }, 200)

    def mocked_requests_post_not_verified(*args, **kwargs):
        """
        mock function requests.get
        """

        class MockResponse:
            def __init__(self, json_data, status_code):
                self.json_data = json_data
                self.status_code = status_code

            def json(self):
                return self.json_data

        url = args[0]
        if url == urljoin(VERIFIER_ADDRESS, 'verify'):
            return MockResponse({
                'success': True,
                'verified': False,
            }, 200)

    @patch("requests.get", side_effect=mocked_requests_get)
    @patch("Api.tasks.ValidateShareTask.delay")
    @patch("Api.utils.general.General.node_request", side_effect=mocked_node_request)
    def test_post_valid(self, mock_node, mock_task, mock3):
        """
        In this scenario we want to test the functionality of Validation API when
        it is called by a http "post" method.
        we send a http "post" method for check data of validation,
        We expect that the status code of response be "200 ok" and output OK
        :return:
        """
        configs = dict(TestValidation.default_configs)
        # Get data input
        with open("Api/data_testing/data_input_validation_valid.json", "r") as read_file:
            data_input = json.load(read_file)
        # response of API /api/validation/ should be this
        result = {
            "status": "OK"
        }
        # send a http "post" request to the Validation endpoint
        TestValidation.returned_configs = configs
        response = self.client.post("/api/validation/", data=data_input, content_type="application/json")
        # check the status of the response
        self.assertEqual(response.status_code, 200)
        # check the content of the response
        self.assertEqual(response.json(), result)

    @patch("requests.get", side_effect=mocked_requests_get)
    @patch("Api.tasks.ValidateShareTask.delay")
    @patch("Api.utils.general.General.node_request", side_effect=mocked_node_request_block_mined)
    @patch("Api.utils.header.Writer.get_bytes")
    def test_post_valid_block_mined(self, pow_mock, mock_node, mock_task, mock3):
        """
        the block is mined but it is valid since msg_pre_image matches the mined block
        """
        configs = dict(TestValidation.default_configs)
        # Get data input
        with open("Api/data_testing/data_input_validation_valid.json", "r") as read_file:
            data_input = json.load(read_file)

        pow_mock.return_value = decode(data_input['proof']['msg_pre_image'], 'hex')
        # response of API /api/validation/ should be this
        result = {
            "status": "OK"
        }
        # send a http "post" request to the Validation endpoint
        TestValidation.returned_configs = configs
        response = self.client.post("/api/validation/", data=data_input, content_type="application/json")
        # check the status of the response
        self.assertEqual(response.status_code, 200)
        # check the content of the response
        self.assertEqual(response.json(), result)

    @patch("requests.get", side_effect=mocked_requests_get)
    @patch("Api.tasks.ValidateShareTask.delay")
    @patch("Api.utils.general.General.node_request", side_effect=mocked_node_request_block_mined)
    @patch("Api.utils.header.Writer.get_bytes")
    def test_post_invalid_block_mined(self, pow_mock, mock_node, mock_task, mock3):
        """
        the block is mined but it is not valid since msg_pre_image does not match the mined block
        """
        configs = dict(TestValidation.default_configs)
        # Get data input
        with open("Api/data_testing/data_input_validation_valid.json", "r") as read_file:
            data_input = json.load(read_file)

        pow_mock.return_value = decode('ABAA', 'hex')
        # send a http "post" request to the Validation endpoint
        TestValidation.returned_configs = configs
        response = self.client.post("/api/validation/", data=data_input, content_type="application/json")
        # check the status of the response
        self.assertEqual(response.status_code, 400)

    @patch("requests.get", side_effect=mocked_requests_get_wrong_pk)
    @patch("Api.tasks.ValidateShareTask.delay")
    @patch("Api.utils.general.General.node_request", side_effect=mocked_node_request)
    def test_post_pk_not_match(self, mock_node, mock_task, mock3):
        """
        all ok but miner pk does not match with miner address
        """
        configs = dict(TestValidation.default_configs)
        # Get data input
        with open("Api/data_testing/data_input_validation_valid.json", "r") as read_file:
            data_input = json.load(read_file)
        # send a http "post" request to the Validation endpoint
        TestValidation.returned_configs = configs
        response = self.client.post("/api/validation/", data=data_input, content_type="application/json")
        # check the status of the response
        self.assertEqual(response.status_code, 400)

    @patch("requests.get", side_effect=mocked_requests_get)
    @patch("requests.post", side_effect=mocked_requests_post_not_verified)
    @patch("Api.tasks.ValidateShareTask.delay")
    @patch("Api.utils.general.General.node_request",
           side_effect=mocked_node_request_external_error_needs_custom_context)
    def test_post_invalid_with_custom_verify(self, mock_node, mock_task, verifier, mock3):
        """
        transaction not verified with node and custom verifier
        :return:
        """
        configs = dict(TestValidation.default_configs)
        # Get data input
        with open("Api/data_testing/data_input_validation_valid.json", "r") as read_file:
            data_input = json.load(read_file)
        # response of API /api/validation/ should be this
        # send a http "post" request to the Validation endpoint
        TestValidation.returned_configs = configs
        response = self.client.post("/api/validation/", data=data_input, content_type="application/json")
        # check the status of the response
        self.assertEqual(response.status_code, 400)

    @patch("requests.get", side_effect=mocked_requests_get)
    @patch("requests.post", side_effect=mocked_requests_post_verified)
    @patch("Api.tasks.ValidateShareTask.delay")
    @patch("Api.utils.general.General.node_request",
           side_effect=mocked_node_request_external_error_needs_custom_context)
    def test_post_valid_with_custom_verify(self, mock_node, mock_task, verifier, mock3):
        """
        transaction was not verified with node but was ok by custom verifier
        :return:
        """
        configs = dict(TestValidation.default_configs)
        # Get data input
        with open("Api/data_testing/data_input_validation_valid.json", "r") as read_file:
            data_input = json.load(read_file)
        # response of API /api/validation/ should be this
        result = {
            "status": "OK"
        }
        # send a http "post" request to the Validation endpoint
        TestValidation.returned_configs = configs
        response = self.client.post("/api/validation/", data=data_input, content_type="application/json")
        # check the status of the response
        self.assertEqual(response.status_code, 200)
        # check the content of the response
        self.assertEqual(response.json(), result)

    @patch("requests.get", side_effect=mocked_requests_get_wrong_id)
    @patch("requests.post", side_effect=mocked_requests_post_verified)
    @patch("Api.tasks.ValidateShareTask.delay")
    @patch("Api.utils.general.General.node_request",
           side_effect=mocked_node_request_external_error_needs_custom_context)
    def test_post_valid_with_custom_verify_id_not_match(self, mock_node, mock_task, verifier, mock3):
        """
        transaction was not verified with node but was ok by custom verifier
        real id of transaction mismatch with transaction[id]
        :return:
        """
        configs = dict(TestValidation.default_configs)
        # Get data input
        with open("Api/data_testing/data_input_validation_valid.json", "r") as read_file:
            data_input = json.load(read_file)
        # send a http "post" request to the Validation endpoint
        TestValidation.returned_configs = configs
        response = self.client.post("/api/validation/", data=data_input, content_type="application/json")
        # check the status of the response
        self.assertEqual(response.status_code, 400)

    @patch("requests.get", side_effect=mocked_requests_get)
    @patch("Api.utils.general.General.node_request", side_effect=mocked_node_request_invalid)
    def test_post_invalid(self, mock_node, mock2):
        """
        In this scenario we want to test the functionality of Validation API when
        it is called by a http "post" method.
        we send a http "post" method for check data of validation,
        We expect that the status code of response be "400" and output OK
        :return:
        """
        configs = dict(TestValidation.default_configs)
        # Get data input
        with open("Api/data_testing/data_input_validation_invalid.json", "r") as read_file:
            data_input = json.load(read_file)
        # response of API /api/validation/ should be this
        # send a http "post" request to the Validation endpoint
        TestValidation.returned_configs = configs
        response = self.client.post("/api/validation/", data=data_input, content_type="application/json")
        # check the status of the response
        self.assertEqual(response.status_code, 400)

    @patch("requests.get", side_effect=mocked_requests_get)
    def test_post_invalid_number_chunk(self, mock):
        """
        In this scenario we want to test the functionality of Validation API when the share parameters bigger than
         SHARE_CHUNK_SIZE
        we send a http "post" method for check data of validation,
        We expect that the status code of response be "413" and message 'too big chunk'
        :return:
        """
        configs = dict(TestValidation.default_configs)
        configs['SHARE_CHUNK_SIZE'] = 1
        # Get data input
        with open("Api/data_testing/data_input_validation_invalid_chunk.json", "r") as read_file:
            data_input = json.load(read_file)
        res_shares = []
        rep_share = json.dumps(data_input['shares'][0])
        for i in range(settings.SHARE_CHUNK_SIZE - 1):
            res_shares.append(json.loads(rep_share))
        data_input['shares'] += res_shares
        # response of API /api/validation/ should be this
        result = {
            "status": "error",
            "message": "too big chunk"
        }
        TestValidation.returned_configs = configs
        # send a http "post" request to the Validation endpoint
        response = self.client.post("/api/validation/", data=data_input, content_type="application/json")
        # check the status of the response
        self.assertEqual(response.status_code, 413)
        # check the content of the response
        self.assertEqual(response.json(), result)


class TestHeaderSerializer(TestCase):
    """
    Test class for test serializer and parser header
    """

    def test_serialize_header(self):
        """
        In this test want serialize header (msg_pre_image).
        :return:
        """
        w = Writer()
        # create header
        h = HeaderWithoutPow(version=1,
                             parent_id="3c1560b4904f0ebbb31a73c99e1cc8df80ff888777074160dcd758b59e77cf13",
                             ad_proofs_root="983b5ebefc4928a587ef9c1510974fb4d266d2b03d0805129880fc321bfc327a",
                             transactions_root="1b48e7eef3d01f917143bd9844fae4e7e80c54745c24679b098ec6145060b682",
                             state_root="5ec18382a0b034d27b6c452ffd4329491108771a4fb240a06a82f40692e6e46113",
                             timestamp=1578501266616,
                             extension_root="e583611a2f4bd48e06453d9e01057c4d7849b6d1bebdfee6e5687d274bd77e1c",
                             n_bits=50394721,
                             height=80000,
                             votes="000000")
        # serialize header
        HeaderSerializer.serialize_without_pow(header=h, writer=w)
        msg_pre_image = "013c1560b4904f0ebbb31a73c99e1cc8df80ff888777074160dcd758b59e77cf13983b5ebefc4928a587ef9c1510974fb4d266d2b03d0805129880fc321bfc327a1b48e7eef3d01f917143bd9844fae4e7e80c54745c24679b098ec6145060b6825ec18382a0b034d27b6c452ffd4329491108771a4fb240a06a82f40692e6e46113b8b987b0f82de583611a2f4bd48e06453d9e01057c4d7849b6d1bebdfee6e5687d274bd77e1c0300f66180f104000000"
        self.assertEqual(decode(msg_pre_image, 'hex'), w.get_bytes())

    def test_parse_header(self):
        """
        In this test want to parse header (msg_pre_image) get information of header
        (version, parentId, ADProofsRoot, transactionsRoot, stateRoot, timestamp, extensionRoot, nBits, height, votes)
         and validate difficulty
        """
        # header
        msg_pre_image = "013c1560b4904f0ebbb31a73c99e1cc8df80ff888777074160dcd758b59e77cf13983b5ebefc4928a587ef9c1510974fb4d266d2b03d0805129880fc321bfc327a1b48e7eef3d01f917143bd9844fae4e7e80c54745c24679b098ec6145060b6825ec18382a0b034d27b6c452ffd4329491108771a4fb240a06a82f40692e6e46113b8b987b0f82de583611a2f4bd48e06453d9e01057c4d7849b6d1bebdfee6e5687d274bd77e1c0300f66180f104000000"
        # Information of header that we expect

        version = 1
        parent_id = "3c1560b4904f0ebbb31a73c99e1cc8df80ff888777074160dcd758b59e77cf13"
        ad_proofs_root = "983b5ebefc4928a587ef9c1510974fb4d266d2b03d0805129880fc321bfc327a"
        transactions_root = "1b48e7eef3d01f917143bd9844fae4e7e80c54745c24679b098ec6145060b682"
        state_root = "5ec18382a0b034d27b6c452ffd4329491108771a4fb240a06a82f40692e6e46113"
        timestamp = 1578501266616
        extension_root = "e583611a2f4bd48e06453d9e01057c4d7849b6d1bebdfee6e5687d274bd77e1c"
        n_bits = 50394721
        height = 80000
        votes = "000000"
        # Create Reader
        r = Reader(decode(msg_pre_image, 'hex'))
        # Get information of header
        header = HeaderSerializer.parse_without_pow(r)
        # Check information of header
        self.assertEqual(version.to_bytes(1, 'little'), header.version)
        self.assertEqual(decode(parent_id, 'hex'), header.parentId)
        self.assertEqual(decode(ad_proofs_root, 'hex'), header.ADProofsRoot)
        self.assertEqual(decode(transactions_root, 'hex'), header.transactionsRoot)
        self.assertEqual(decode(state_root, 'hex'), header.stateRoot)
        self.assertEqual(timestamp, header.timestamp)
        self.assertEqual(decode(extension_root, 'hex'), header.extensionRoot)
        self.assertEqual(n_bits, header.nBits)
        self.assertEqual(height, header.height)
        self.assertEqual(decode(votes, 'hex'), header.votes)
        # Check difficulty
        self.assertEqual(header.decode_nbits, 63073)


class TestProxyView(TestCase):

    class MockResponse:
        def __init__(self, json_data, status_code):
            self.json_data = json_data
            self.status_code = status_code
            self.content = json_data

        def json(self):
            return self.json_data

    def mocked_requests_methods_json(*args, **kwargs):
        """
        mock function requests.get
        """

        return TestProxyView.MockResponse({}, 200)

    def mocked_requests_methods_content(*args, **kwargs):
        return TestProxyView.MockResponse("this is a test content", 200)

    def setUp(self):
        self.client = Client()

    @patch("requests.get", side_effect=mocked_requests_methods_json)
    def test_get_method_proxy(self, mocked_get):
        """
        call proxy view with a get request. method must call according api method.
        :return:
        """
        self.client.get("/api/accounting/test/view/")
        self.assertTrue(mocked_get.called_with("/accounting/test/view/"))

    @patch("requests.get", side_effect=mocked_requests_methods_content)
    def test_get_method_proxy_no_json(self, mocked_get):
        """
        call proxy view with a get request. method must call according api method.
        content is not json
        :return:
        """
        self.client.get("/api/accounting/test/view/")
        self.assertTrue(mocked_get.called_with("/accounting/test/view/"))

    @patch("requests.post", side_effect=mocked_requests_methods_json)
    def test_post_method_proxy(self, mocked_get):
        """
        call proxy view with a post request. method must call according api method.
        :return:
        """
        self.client.post("/api/accounting/test/view/")
        self.assertTrue(mocked_get.called_with("/accounting/test/view/"))

    @patch("requests.put", side_effect=mocked_requests_methods_json)
    def test_put_method_proxy(self, mocked_get):
        """
        call proxy view with a put request. method must call according api method.
        :return:
        """
        self.client.put("/api/accounting/test/view/")
        self.assertTrue(mocked_get.called_with("/accounting/test/view/"))

    @patch("requests.patch", side_effect=mocked_requests_methods_json)
    def test_patch_method_proxy(self, mocked_get):
        """
        call proxy view with a patch request. method must call according api method.
        :return:
        """
        self.client.patch("/api/accounting/test/view/")
        self.assertTrue(mocked_get.called_with("/accounting/test/view/"))

    @patch("requests.options", side_effect=mocked_requests_methods_json)
    def test_options_method_proxy(self, mocked_get):
        """
        call proxy view with a options request. method must call according api method.
        :return:
        """
        self.client.options("/api/accounting/test/view/")
        self.assertTrue(mocked_get.called_with("/accounting/test/view/"))

    @patch("requests.delete", side_effect=mocked_requests_methods_json)
    def test_delete_method_proxy(self, mocked_get):
        """
        call proxy view with a options request. method must call according api method
        :return:
        """
        self.client.delete("/api/accounting/test/view/")
        self.assertTrue(mocked_get.called_with("/accounting/test/view/"))


class TestGeneratePath(TestCase):
    default_configs = {
        'POOL_BASE_FACTOR': 1000,
        'TOTAL_REWARD': int(67.5e9),
        "REWARD_FACTOR_PRECISION": 2,
        'REWARD_FACTOR': 0.96296297,
        'SHARE_CHUNK_SIZE': 10,
        'THRESHOLD_HEIGHT': 10,
        'THRESHOLD_TIMESTAMP': 120000
    }

    def mocked_requests_get(*args, **kwargs):
        """
        mock function requests.get
        """

        class MockResponse:
            def __init__(self, json_data, status_code):
                self.json_data = json_data
                self.status_code = status_code

            def json(self):
                return self.json_data

        url = args[0]

        if url == urljoin(ACCOUNTING_URL, 'conf/'):
            return MockResponse(TestGeneratePath.default_configs, 200)

        elif 'stats/forks' in url:
            return MockResponse(json.load(open('Api/data_testing/path_forks.json', 'r')), 200)

    def mocked_node_request(*args, **kwargs):
        """
        mock function node_request for urls 'info', '/blocks/lastHeaders/', '/blocks/at/'and '/blocks/chainSlice'
        """
        url = args[0]
        if "/blocks/chainSlice?fromHeight" in url:
            slice = json.load(open("Api/data_testing/path_chain_slice.json", "r"))
            return {
                "status": "success",
                "response": slice
            }

        if "/blocks/at/109201" == url:
            return {
                "status": "success",
                "response": [
                    'a', 'b', '4f12421001ebec488c916d65868bba04db117e5cd76026fe0e524b083798ac41',
                    'c', 'd'
                ]
            }

        if "/blocks/at/109200" == url:
            return {
                "status": "success",
                "response": [
                    'a', 'fffffffff1ebec488c916d65868bba04db117e5cd76026fe0e524b083798ac41',
                    'c', 'd'
                ]
            }

        return {
            "status": "success",
            "response": []
        }

    def setUp(self) -> None:
        self.CUR_HEIGHT = 109208

    @patch("Api.utils.general.General.node_request", side_effect=mocked_node_request)
    @patch("requests.get", side_effect=mocked_requests_get)
    def test_on_main_chain(self, request_mock, node_mock):
        """
        the provided block is on the main chain, it is 3 block away, should return only one number
        """
        proofSerializer = ValidateProofSerializer()
        parent_id = '7b0e7e7d3ce503b86201674b071700a2b8a398e9cbfd02e1b853089f119eb342'
        res = proofSerializer.generate_path(parent_id, self.CUR_HEIGHT)
        self.assertEqual(res, '4')

    @patch("Api.utils.general.General.node_request", side_effect=mocked_node_request)
    @patch("requests.get", side_effect=mocked_requests_get)
    def test_on_fork_one_away(self, request_mock, node_mock):
        """
        the provided block is on a fork, it is 1 block away in that fork, should return 3 numbers
        """
        proofSerializer = ValidateProofSerializer()
        parent_id = '4f12421001ebec488c916d65868bba04db117e5cd76026fe0e524b083798ac41'
        res = proofSerializer.generate_path(parent_id, self.CUR_HEIGHT)
        self.assertEqual(res, '3,3,1')

    @patch("Api.utils.general.General.node_request", side_effect=mocked_node_request)
    @patch("requests.get", side_effect=mocked_requests_get)
    def test_on_fork_4_away(self, request_mock, node_mock):
        """
        the provided block is on a fork, it is 4 block away in that fork, should return 3 numbers
        """
        proofSerializer = ValidateProofSerializer()
        parent_id = 'fffffffff1ebec488c916d65868bba04db117e5cd76026fe0e524b083798ac41'
        res = proofSerializer.generate_path(parent_id, self.CUR_HEIGHT)
        self.assertEqual(res, '2,2,4')

    @patch("Api.utils.general.General.node_request", side_effect=mocked_node_request)
    @patch("requests.get", side_effect=mocked_requests_get)
    def test_not_exists(self, request_mock, node_mock):
        """
        provided block does not exist on forks and main chain
        """
        proofSerializer = ValidateProofSerializer()
        parent_id = 'invalid_id'
        res = proofSerializer.generate_path(parent_id, self.CUR_HEIGHT)
        self.assertEqual(res, '-1')


