import struct
from codecs import decode
from pydoc import locate
from unittest.mock import patch, call
from urllib.parse import urljoin

from django.contrib.auth.models import User
from django.test.client import RequestFactory
from django.test.testcases import TransactionTestCase, TestCase
from rest_framework.exceptions import ValidationError
from rest_framework.test import APIClient

from Api.models import Block, CONFIGURATION_KEY_CHOICE, Configuration, CONFIGURATION_DEFAULT_KEY_VALUE, \
    CONFIGURATION_KEY_TO_TYPE
from Api.serializers import ShareSerializer
from ErgoApi.settings import ACCOUNTING_URL


class TransactionValidateApiTest(TransactionTestCase):
    """
    Test class for Validate Transaction API
    This class has 2 test function:
    1) using http 'post' method to validate a transaction that is valid.
    2) using http 'post' method to validate a transaction that is invalid
    """
    reset_sequences = True

    def mocked_node_request(*args, **kwargs):
        """
        mock function node_request for urls 'transactions/check', 'wallet/addresses' and 'utils/ergoTreeToAddress/'
        """
        if args[0] == "transactions/check":
            return {
                "status": "success",
                "response": "a1713c7d26e6d578cf2787425d07b9a6e4f010346f8172c84484ba508c85edf7"
            }
        elif args[0] == "wallet/addresses":
            return {
                "status": "success",
                "response": ["3WwYLP3oDYogUc8x9BbcnLZvpVqT5Zc77RHjoy19PyewAJMy9aDM"]
            }
        elif "utils/ergoTreeToAddress/" in args[0]:
            return {
                "status": "success",
                "response": {
                    "address": "3WwYLP3oDYogUc8x9BbcnLZvpVqT5Zc77RHjoy19PyewAJMy9aDM"
                }
            }

    def mocked_node_request_external_error_transactions_check(*args, **kwargs):
        """
        mock function node_request for urls 'transactions/check', 'wallet/addresses' and 'utils/ergoTreeToAddress/'
        """
        if args[0] == "transactions/check":
            return {
                "status": "External Error",
                "response": "External Error"
            }

    def mocked_node_request_external_error_wallet_addresses(*args, **kwargs):
        """
        mock function node_request for urls 'transactions/check', 'wallet/addresses' and 'utils/ergoTreeToAddress/'
        """
        if args[0] == "transactions/check":
            return {
                "status": "success",
                "response": "a1713c7d26e6d578cf2787425d07b9a6e4f010346f8172c84484ba508c85edf7"
            }
        elif args[0] == "wallet/addresses":
            return {
                "status": "External Error",
                "response": "External Error"
            }

    def mocked_node_request_external_error_utils_ergo_tree_to_address(*args, **kwargs):
        """
        mock function node_request for urls 'transactions/check', 'wallet/addresses' and 'utils/ergoTreeToAddress/'
        """
        if args[0] == "transactions/check":
            return {
                "status": "success",
                "response": "a1713c7d26e6d578cf2787425d07b9a6e4f010346f8172c84484ba508c85edf7"
            }
        elif args[0] == "wallet/addresses":
            return {
                "status": "success",
                "response": ["3WwYLP3oDYogUc8x9BbcnLZvpVqT5Zc77RHjoy19PyewAJMy9aDM"]
            }
        elif "utils/ergoTreeToAddress/" in args[0]:
            return {
                "status": "External Error",
                "response": {"External Error"}
            }

    @patch("Api.utils.general.General.node_request", side_effect=mocked_node_request)
    def test_post_valid(self, mock):
        """
        In this scenario we want to test the functionality of Validate Transaction API when
        it is called by a http "post" method.
        we send a http "post" method for check transaction,
        We expect that the status code of response be "201 ok" and output Transaction is valid
        :return:
        """
        data_input = {
            "pk": "02385E11D92F8AC74155878EE318B8A0FC4FC1FDA9D1D48A5EC34778F55DF01C6C",
            "transaction": {
                "id": "a1713c7d26e6d578cf2787425d07b9a6e4f010346f8172c84484ba508c85edf7",
                "outputs": [
                    {
                        "value": 1000000000,
                        "ergoTree": "0008cd027ae614dd724777fe9ead18d82f3c53f04de0525b46d235a74b04af694694485e"
                    },
                    {
                        "value": 1000000,
                        "ergoTree": "1005040004000e36100204a00b08cd0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798ea02d192a39a8cc7a701730073011001020402d19683030193a38cc7b2a57300000193c2b2a57301007473027303830108cdeeac93b1a57304"
                    },
                    {
                        "value": 216177000000,
                        "ergoTree": "0008cd027ae614dd724777fe9ead18d82f3c53f04de0525b46d235a74b04af694694485e"
                    }]
            }
        }
        # response of API /api/transaction/ should be this
        result = {
            "message": "Transaction is valid"
        }
        # send a http "post" request to the configuration endpoint
        response = self.client.post("/api/transaction/", data=data_input, content_type="application/json")
        # check the status of the response
        self.assertEqual(response.status_code, 201)
        # check the content of the response
        self.assertEqual(response.json(), result)
        # a block with lowercase public key must created
        self.assertTrue(Block.objects.filter(public_key=data_input["pk"].lower()).exists())

    @patch("Api.utils.general.General.node_request", side_effect=mocked_node_request)
    def test_post_invalid_tx_id(self, mock):
        """
        In this scenario we want to test the functionality of Validate Transaction API when
        it is called by a http "post" method.
        we send a http "post" method for check transaction,
        We expect that the status code of response be "400" and output Transaction is invalid because transaction id
         in input not equal with response of api transactions/check .
        :return:
        """
        data_input = {
            "pk": "02385E11D92F8AC74155878EE318B8A0FC4FC1FDA9D1D48A5EC34778F55DF01C6C",
            "transaction": {
                "id": "a2713c7d26e6d578cf2787425d07b9a6e4f010346f8172c84484ba508c85edf7",
                "outputs": [
                    {
                        "value": 1000000000,
                        "ergoTree": "0008cd027ae614dd724777fe9ead18d82f3c53f04de0525b46d235a74b04af694694485e"
                    },
                    {
                        "value": 1000000,
                        "ergoTree": "1005040004000e36100204a00b08cd0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798ea02d192a39a8cc7a701730073011001020402d19683030193a38cc7b2a57300000193c2b2a57301007473027303830108cdeeac93b1a57304"
                    },
                    {
                        "value": 216177000000,
                        "ergoTree": "0008cd027ae614dd724777fe9ead18d82f3c53f04de0525b46d235a74b04af694694485e"
                    }]
            }
        }
        # response of API /api/transaction/ should be this
        result = {
            "message": ["tx_id is invalid"]
        }
        # send a http "post" request to the Transaction Validate endpoint
        response = self.client.post("/api/transaction/", data=data_input, content_type="application/json")
        # check the status of the response
        self.assertEqual(response.status_code, 400)
        # check the content of the response
        self.assertEqual(response.json(), result)

    @patch("Api.utils.general.General.node_request", side_effect=mocked_node_request)
    def test_post_invalid_value_wallet_address(self, mock):
        """
        In this scenario we want to test the functionality of Validate Transaction API when
        it is called by a http "post" method.
        we send a http "post" method for check transaction,
        We expect that the status code of response be "400" and output Transaction is invalid because sum of value
         isn"t biggest than policy pool reward or wallet address is invalid.
        :return:
        """
        data_input = {
            "pk": "02385E11D92F8AC74155878EE318B8A0FC4FC1FDA9D1D48A5EC34778F55DF01C6C",
            "transaction": {
                "id": "a1713c7d26e6d578cf2787425d07b9a6e4f010346f8172c84484ba508c85edf7",
                "outputs": [
                    {
                        "value": 10000000,
                        "ergoTree": "0008cd027ae614dd724777fe9ead18d82f3c53f04de0525b46d235a74b04af694694485e"
                    },
                    {
                        "value": 1000000,
                        "ergoTree": "1005040004000e36100204a00b08cd0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798ea02d192a39a8cc7a701730073011001020402d19683030193a38cc7b2a57300000193c2b2a57301007473027303830108cdeeac93b1a57304"
                    },
                    {
                        "value": 21617700,
                        "ergoTree": "0018cd027ae614dd724777fe9ead18d82f3c53f04de0525b46d235a74b04af694694485e"
                    }]
            }
        }
        # response of API /api/transaction/ should be this
        result = {
            "message": ["Wallet address pool or value of transaction is invalid"]
        }
        # send a http "post" request to the configuration endpoint
        response = self.client.post("/api/transaction/", data=data_input, content_type="application/json")
        # check the status of the response
        self.assertEqual(response.status_code, 400)
        # check the content of the response
        self.assertEqual(response.json(), result)

    @patch("Api.utils.general.General.node_request", side_effect=mocked_node_request_external_error_transactions_check)
    def test_post_node_response_error_transactions_check(self, mock):
        """
        In this scenario we want to test the functionality of Validate Transaction API when
        it is called by a http "post" method.
        we send a http "post" method for check transaction,
        We expect that the status code of response be "400" because node send a response with status code except 200
         after call API transactions/check
        :return:
        """
        data_input = {
            "pk": "02385E11D92F8AC74155878EE318B8A0FC4FC1FDA9D1D48A5EC34778F55DF01C6C",
            "transaction": {}
        }
        # send a http "post" request to the configuration endpoint
        response = self.client.post("/api/transaction/", data=data_input, content_type="application/json")
        # check the status of the response
        self.assertEqual(response.status_code, 400)
        # check the content of the response
        self.assertEqual(response.json()['message'], ['External Error'])

    @patch("Api.utils.general.General.node_request", side_effect=mocked_node_request_external_error_wallet_addresses)
    def test_post_node_response_error_wallet_addresses(self, mock):
        """
        In this scenario we want to test the functionality of Validate Transaction API when
        it is called by a http "post" method.
        we send a http "post" method for check transaction,
        We expect that the status code of response be "400" because node send a response with status code except 200
         after call API wallet/addresses
        :return:
        """
        data_input = {
            "pk": "02385E11D92F8AC74155878EE318B8A0FC4FC1FDA9D1D48A5EC34778F55DF01C6C",
            "transaction": {
                "id": "a1713c7d26e6d578cf2787425d07b9a6e4f010346f8172c84484ba508c85edf7",
            }
        }
        # send a http "post" request to the configuration endpoint
        response = self.client.post("/api/transaction/", data=data_input, content_type="application/json")
        # check the status of the response
        self.assertEqual(response.status_code, 400)
        # check the content of the response
        self.assertEqual(response.json()['message'], ['External Error'])

    @patch("Api.utils.general.General.node_request",
           side_effect=mocked_node_request_external_error_utils_ergo_tree_to_address)
    def test_post_node_response_error_utils_ergo_tree_to_address(self, mock):
        """
        In this scenario we want to test the functionality of Validate Transaction API when
        it is called by a http "post" method.
        we send a http "post" method for check transaction,
        We expect that the status code of response be "400" because node send a response with status code except 200
         after call API utils/ergoTreeToAddress
        :return:
        """
        data_input = {
            "pk": "02385E11D92F8AC74155878EE318B8A0FC4FC1FDA9D1D48A5EC34778F55DF01C6C",
            "transaction": {
                "id": "a1713c7d26e6d578cf2787425d07b9a6e4f010346f8172c84484ba508c85edf7",
                "outputs": [
                    {
                        "value": 1000000000,
                        "ergoTree": "0008cd027ae614dd724777fe9ead18d82f3c53f04de0525b46d235a74b04af694694485e"
                    },
                    {
                        "value": 1000000,
                        "ergoTree": "1005040004000e36100204a00b08cd0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798ea02d192a39a8cc7a701730073011001020402d19683030193a38cc7b2a57300000193c2b2a57301007473027303830108cdeeac93b1a57304"
                    },
                    {
                        "value": 216177000000,
                        "ergoTree": "0008cd027ae614dd724777fe9ead18d82f3c53f04de0525b46d235a74b04af694694485e"
                    }]
            }
        }
        # send a http "post" request to the configuration endpoint
        response = self.client.post("/api/transaction/", data=data_input, content_type="application/json")
        # check the status of the response
        self.assertEqual(response.status_code, 400)
        # check the content of the response
        self.assertEqual(response.json()['message'], ["{'External Error'}"])


class TestValidateProof(TransactionTestCase):
    reset_sequences = True

    def test_valid(self):
        """
        In this scenario we want to test a valid proof.
        send a valid data and want to get status valid.
        we send a http 'post' method to validate a proof.
        We expect that the status code of response be '200 ok'.
        :return:
        """
        Block.objects.create(public_key="0354043bd5f16526b0184e6521a0bd462783f8b178db37ec034328a23fed4855a9",
                             tx_id="53c538c7f7fcc79e2980ce41ac65ddf9d3db979a9aeeccd9b46d8e81a8a291d5")
        proof_data = {
            "pk": "0354043bd5f16526b0184e6521a0bd462783f8b178db37ec034328a23fed4855a9",
            "msg_pre_image": "0146062b27d06c1155898ce2a04db6686a84af710135e87dfb89eaac4a32b58a4872011e52944ffdcd5e7f745ba14df4487ce8cf30f9b02a2be0c5a1096f8b612c190194448af0d8c9ae2170a7d970f621d18707dc4c2d5e9ec168adb1895e5cbbc555853afe04d0a87819523798e4db5f1b75fd43512cf76c5a3ce5eb8527725e12d1c3f9e0eb2db112e2d742dc71c6aa2df4b35fec85d8c28f6dc954796f3f95c308721e60cc9505016238dfbd02000000",
            "leaf": "53c538c7f7fcc79e2980ce41ac65ddf9d3db979a9aeeccd9b46d8e81a8a291d5",
            "levels": ["01c9a7e42a405a771add3b28b2538731577322930648b08ef4e5fd98854c064a7a"]
        }
        # send a http "post" request to the validation proof
        response = self.client.post("/api/header/", data=proof_data, content_type="application/json")
        # check the status of the response
        self.assertEqual(response.status_code, 201)
        # check the content of the response
        self.assertEqual(response.json()['message'], 'The proof is valid.')
        self.assertEqual(response.json()['status'], 'success')

    def test_invalid(self):
        """
        In this scenario we want to test a invalid proof leaf_hash != txs_root.
        send a invalid data and want to get status invalid.
        we send a http 'post' method to validate a proof.
        We expect that the status code of response be '200 ok'.
        :return:
        """
        Block.objects.create(public_key="0354043bd5f16526b0184e6521a0bd462783f8b178db37ec034328a23fed4855a9",
                             tx_id="53c538c7f7fcc79e2980ce41ac65ddf9d3db979a9aeeccd9b46d8e81a8a291d5")
        proof_data = {
            "pk": "0354043bd5f16526b0184e6521a0bd462783f8b178db37ec034328a23fed4855a9",
            "msg_pre_image": "0146062b27d06c1155898ce2a04db6686a84af710135e87dfb89eaac4a32b58a4872011e52944ffdcd5e7f745ba14df4487ce8cf30f9b02a2be0c5a1096f8b612c190194448af0d8c9ae2170a7d970f621d18707dc4c2d5e9ec168adb1895e5cbbc555853afe04d0a87819523798e4db5f1b75fd43512cf76c5a3ce5eb8527725e12d1c3f9e0eb2db112e2d742dc71c6aa2df4b35fec85d8c28f6dc954796f3f95c308721e60cc9505016238dfbd02000000",
            "leaf": "53c538c7f7fcc79e2980ce41ac65ddf9d3db979a9aeeccd9b46d8e81a8a291d5",
            "levels": ["00c9a7e42a405a771add3b28b2538731577322930648b08ef4e5fd98854c064a7a"]
        }
        # send a http "post" request to the validation proof
        response = self.client.post("/api/header/", data=proof_data, content_type="application/json")
        # check the status of the response
        self.assertEqual(response.status_code, 201)
        # check the content of the response
        self.assertEqual(response.json()['message'], 'The proof is invalid.')
        self.assertEqual(response.json()['status'], 'invalid')

    def test_input_invalid_levels(self):
        """
        In this scenario we want to test a invalid type input for proof.
        send a invalid data and want to get status failed because data input have wrong type input (levels).
        we send a http 'post' method to validate a proof.
        We expect that the status code of response be '400 ok'.
        :return:
        """
        Block.objects.create(public_key="0354043bd5f16526b0184e6521a0bd462783f8b178db37ec034328a23fed4855a9",
                             tx_id="53c538c7f7fcc79e2980ce41ac65ddf9d3db979a9aeeccd9b46d8e81a8a291d5")
        proof_data = {
            "pk": "0354043bd5f16526b0184e6521a0bd462783f8b178db37ec034328a23fed4855a9",
            "msg_pre_image": "0146062b27d06c1155898ce2a04db6686a84af710135e87dfb89eaac4a32b58a4872011e52944ffdcd5e7f745ba14df4487ce8cf30f9b02a2be0c5a1096f8b612c190194448af0d8c9ae2170a7d970f621d18707dc4c2d5e9ec168adb1895e5cbbc555853afe04d0a87819523798e4db5f1b75fd43512cf76c5a3ce5eb8527725e12d1c3f9e0eb2db112e2d742dc71c6aa2df4b35fec85d8c28f6dc954796f3f95c308721e60cc9505016238dfbd02000000",
            "leaf": "53c538c7f7fcc79e2980ce41ac65ddf9d3db979a9aeeccd9b46d8e81a8a291d5",
            "levels": ["01c9a7e?2a405a771add3b28b2538731577322930648b08ef4e5fd98854c064a7a"]
        }
        # send a http "post" request to the validation proof
        response = self.client.post("/api/header/", data=proof_data, content_type="application/json")
        self.assertEqual(response.status_code, 400)
        response = response.json()
        self.assertEqual(response['message'], ['Type of input is invalid'])
        self.assertEqual(response['status'], ['failed'])

    def test_input_invalid_msg_pre_image(self):
        """
        In this scenario we want to test a invalid type input for proof.
        send a invalid data and want to get status failed because data input have wrong type input (msg_pre_image).
        we send a http 'post' method to validate a proof.
        We expect that the status code of response be '400 ok'.
        :return:
        """
        Block.objects.create(public_key="0354043bd5f16526b0184e6521a0bd462783f8b178db37ec034328a23fed4855a9",
                             tx_id="53c538c7f7fcc79e2980ce41ac65ddf9d3db979a9aeeccd9b46d8e81a8a291d5")
        proof_data = {
            "pk": "0354043bd5f16526b0184e6521a0bd462783f8b178db37ec034328a23fed4855a9",
            "msg_pre_image": "01?6062b27d06c1155898ce2a04db6686a84af710135e87dfb89eaac4a32b58a4872011e52944ffdcd5e7f745ba14df4487ce8cf30f9b02a2be0c5a1096f8b612c190194448af0d8c9ae2170a7d970f621d18707dc4c2d5e9ec168adb1895e5cbbc555853afe04d0a87819523798e4db5f1b75fd43512cf76c5a3ce5eb8527725e12d1c3f9e0eb2db112e2d742dc71c6aa2df4b35fec85d8c28f6dc954796f3f95c308721e60cc9505016238dfbd02000000",
            "leaf": "53c538c7f7fcc79e2980ce41ac65ddf9d3db979a9aeeccd9b46d8e81a8a291d5",
            "levels": ["01c9a7e42a405a771add3b28b2538731577322930648b08ef4e5fd98854c064a7a"]
        }
        # send a http "post" request to the validation proof
        response = self.client.post("/api/header/", data=proof_data, content_type="application/json")
        self.assertEqual(response.status_code, 400)
        response = response.json()
        self.assertEqual(response['message'], ['Type of input is invalid'])
        self.assertEqual(response['status'], ['failed'])

    def test_input_invalid_leaf(self):
        """
        In this scenario we want to test a invalid leaf input for proof.
        send a leaf data and not equal with tx_id in the database for public_key of that.
        we send a http 'post' method to validate a proof.
        We expect that the status code of response be '400 ok'.
        :return:
        """
        Block.objects.create(public_key="0354043bd5f16526b0184e6521a0bd462783f8b178db37ec034328a23fed4855a9",
                             tx_id="63c538c7f7fcc79e2980ce41ac65ddf9d3db979a9aeeccd9b46d8e81a8a291d5")
        proof_data = {
            "pk": "0354043bd5f16526b0184e6521a0bd462783f8b178db37ec034328a23fed4855a9",
            "msg_pre_image": "0146062b27d06c1155898ce2a04db6686a84af710135e87dfb89eaac4a32b58a4872011e52944ffdcd5e7f745ba14df4487ce8cf30f9b02a2be0c5a1096f8b612c190194448af0d8c9ae2170a7d970f621d18707dc4c2d5e9ec168adb1895e5cbbc555853afe04d0a87819523798e4db5f1b75fd43512cf76c5a3ce5eb8527725e12d1c3f9e0eb2db112e2d742dc71c6aa2df4b35fec85d8c28f6dc954796f3f95c308721e60cc9505016238dfbd02000000",
            "leaf": "53c538c7f7fcc79e2980ce41ac65ddf9d3db979a9aeeccd9b46d8e81a8a291d5",
            "levels": ["01c9a7e42a405a771add3b28b2538731577322930648b08ef4e5fd98854c064a7a"]
        }
        # send a http "post" request to the validation proof
        response = self.client.post("/api/header/", data=proof_data, content_type="application/json")
        self.assertEqual(response.status_code, 400)
        response = response.json()
        self.assertEqual(response['message'], ['The leaf is invalid.'])
        self.assertEqual(response['status'], ['failed'])

    def test_does_not_exist_block(self):
        """
        In this scenario we want to test exist or don't exist block in data base.
        we send a http 'post' method to validate a proof.
        We expect that the status code of response be '400 ok'.
        :return:
        """
        Block.objects.create(public_key="123043bd5f16526b0184e6521a0bd462783f8b178db37ec034328a23fed4855a9",
                             tx_id="63c538c7f7fcc79e2980ce41ac65ddf9d3db979a9aeeccd9b46d8e81a8a291d5")
        proof_data = {
            "pk": "0354043bd5f16526b0184e6521a0bd462783f8b178db37ec034328a23fed4855a9",
            "msg_pre_image": "0146062b27d06c1155898ce2a04db6686a84af710135e87dfb89eaac4a32b58a4872011e52944ffdcd5e7f745ba14df4487ce8cf30f9b02a2be0c5a1096f8b612c190194448af0d8c9ae2170a7d970f621d18707dc4c2d5e9ec168adb1895e5cbbc555853afe04d0a87819523798e4db5f1b75fd43512cf76c5a3ce5eb8527725e12d1c3f9e0eb2db112e2d742dc71c6aa2df4b35fec85d8c28f6dc954796f3f95c308721e60cc9505016238dfbd02000000",
            "leaf": "53c538c7f7fcc79e2980ce41ac65ddf9d3db979a9aeeccd9b46d8e81a8a291d5",
            "levels": ["01c9a7e42a405a771add3b28b2538731577322930648b08ef4e5fd98854c064a7a"]
        }
        # send a http "post" request to the validation proof
        response = self.client.post("/api/header/", data=proof_data, content_type="application/json")
        self.assertEqual(response.status_code, 400)
        response = response.json()
        self.assertEqual(response['message'], ['Transaction not generated.'])
        self.assertEqual(response['status'], ['failed'])


class TestValidateBlock(TransactionTestCase):
    reset_sequences = True

    def mocked_node_request(*args, **kwargs):
        """
        mock function node_request for urls 'mining/candidate and 'info'
        """
        if args[0] == "info":
            return {
                "status": "success",
                "response": {
                    "headersHeight": 41496,
                    "difficulty": Configuration.objects.POOL_BASE_FACTOR
                }
            }

    def mocked_node_request_status_valid(*args, **kwargs):
        """
        mock function node_request for urls 'mining/candidate and 'info'
        """
        if args[0] == "info":
            return {
                "status": "success",
                "response": {
                    "headersHeight": 41496,
                    "difficulty": Configuration.objects.POOL_BASE_FACTOR * pow(10, 8)
                }
            }

    def test_type_input_d_str(self):
        block = ShareSerializer()
        output = block.validate_d("46242367293113109317096091884217605312791141894953570819396709798327")
        self.assertEqual(output, 46242367293113109317096091884217605312791141894953570819396709798327)

    def test_type_input_d_invalid(self):
        block = ShareSerializer()
        try:
            block.validate_d("462?2367293113109317096091884217605312791141894953570819396709798327")
        except ValidationError as e:
            self.assertEquals('invalid number entered', e.args[0])

    def test_ec_point_start_byte_2(self):
        block = ShareSerializer()
        output = block.__ec_point__(decode("0254043bd5f16526b0184e6521a0bd462783f8B178db37ec034328a23fed4855a9", "hex"))
        self.assertEqual(output['value'].x,
                         38001759640178464358233514318285492856403682368769743827942002958530733692329)
        self.assertEqual(output['value'].y,
                         47862723537995571517279590967139629780302343405661481110647004256081707204458)

    def test_ec_point_start_byte_except_2_3(self):
        block = ShareSerializer()
        try:
            block.__ec_point__(decode("0454043bd5f16526b0184e6521a0bd462783f8B178db37ec034328a23fed4855a9", "hex"))
        except ValidationError as e:
            self.assertEquals('First bytes of w_bytes is invalid.', e.args[0]['message'])

    def test_gen_indexes(self):
        """
        input function gen_indexes is concat array-bytes of msg and nonce
        """
        msg = "cfc5f330a71a99616453b18e572ee06a7e045e0c2f6cf35ce7d490572ec7a2ac".encode("ascii")
        nonce = "000000058B1CE60D".encode("ascii")
        block = ShareSerializer()
        output = block.__gen_indexes__(msg + nonce)
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
        block = ShareSerializer()
        output = block.__gen_element__(msg, p1, p2, struct.pack(">I", out_gen_indexes))
        self.assertEqual(output, 1442183731460476782005370820367939156210879287829514232459313282341328232038)

    @patch("Api.utils.general.General.node_request", side_effect=mocked_node_request)
    def test_status_solved_lesX(self, mock):
        """
        Solution
        Check that d < b and left == right for a share solved.
        """
        Block.objects.create(public_key="03cd07843e1f7e25407eda2369ad644854e532e381ab30d6488970e0b87d060d16",
                             msg="fc0ecfe7a0559c556cb5fe25dd9259e5b548a33502be0c474cd581f77f0acb89",
                             tx_id="53c538c7f7fcc79e2980ce41ac65ddf9d3db979a9aeeccd9b46d8e81a8a291d5")
        share = {
            "pk": "03cd07843e1f7e25407eda2369ad644854e532e381ab30d6488970e0b87d060d16",
            "w": "0370b32976a9bc37654e6b34390c8dd30d3dc44c3f52e9421cc4ec31ef6a1bca4c",
            "nonce": "00000237d4e1e20c",
            "d": 46242367293113109317096091884217605312791141894953570819396709798327
        }
        block = ShareSerializer()
        response = block.validate(share)
        self.assertEqual(response.get("pk"), "03cd07843e1f7e25407eda2369ad644854e532e381ab30d6488970e0b87d060d16")
        self.assertEqual(response.get("status"), "solved")
        self.assertEqual(response.get("share"), "09c7257058d70ec1e4a2d1248cf42aafc01fe6f773f5d991d295029b7059ca4a")
        self.assertEqual(response.get("difficulty"), 1)
        self.assertEqual(response.get("headers_height"), 41496)
        self.assertEqual(response.get("tx_id"), "53c538c7f7fcc79e2980ce41ac65ddf9d3db979a9aeeccd9b46d8e81a8a291d5")

    @patch("Api.utils.general.General.node_request", side_effect=mocked_node_request_status_valid)
    def test_status_valid(self, mock):
        """
        Solution
        Check that d < b and left == right for a share solved.
        """
        Block.objects.create(public_key="03cd07843e1f7e25407eda2369ad644854e532e381ab30d6488970e0b87d060d16",
                             msg="fc0ecfe7a0559c556cb5fe25dd9259e5b548a33502be0c474cd581f77f0acb89",
                             tx_id="53c538c7f7fcc79e2980ce41ac65ddf9d3db979a9aeeccd9b46d8e81a8a291d5")
        share = {
            "pk": "03cd07843e1f7e25407eda2369ad644854e532e381ab30d6488970e0b87d060d16",
            "w": "0370b32976a9bc37654e6b34390c8dd30d3dc44c3f52e9421cc4ec31ef6a1bca4c",
            "nonce": "00000237d4e1e20c",
            "d": 46242367293113109317096091884217605312791141894953570819396709798327
        }
        block = ShareSerializer()
        response = block.validate(share)
        self.assertEqual(response.get("pk"), "03cd07843e1f7e25407eda2369ad644854e532e381ab30d6488970e0b87d060d16")
        self.assertEqual(response.get("status"), "valid")
        self.assertEqual(response.get("share"), "09c7257058d70ec1e4a2d1248cf42aafc01fe6f773f5d991d295029b7059ca4a")
        self.assertEqual(response.get("difficulty"), pow(10, 8))

    @patch("ErgoApi.settings")
    @patch("Api.utils.general.General.node_request", side_effect=mocked_node_request)
    def test_status_invalid(self, mock, mock_setting):
        """
         Solution
         Check that d > POOL_DIFFICULTY or left =! right for a share invalid.
         """
        mock_setting.POOL_DIFFICULTY = 125792089237316195423570985008687907852837564279074904382605163141518161494337
        Block.objects.create(public_key="0354043bd5f16526b0184e6521a0bd462783f8b178db37ec034328a23fed4855a9",
                             msg="f548e38f716e90f52078880c7cdc5a81e27676b26b9b9251b5539e6b1df2ffb5",
                             tx_id="53c538c7f7fcc79e2980ce41ac65ddf9d3db979a9aeeccd9b46d8e81a8a291d5")

        share = {
            "pk": "0354043bd5f16526b0184e6521a0bd462783f8B178db37ec034328a23fed4855a9",
            "w": "03b783831ab40435c02bf0b3225890540b9689db3c93d4b0bdb32e5a837f281438",
            "nonce": "0000000000400ee0",
            "d": 99693760199151170059172331486081907352237598845267005513376026899853403721406
        }
        result_validate = {
            "pk": "0354043bd5f16526b0184e6521a0bd462783f8B178db37ec034328a23fed4855a9",
            "w": "03b783831ab40435c02bf0b3225890540b9689db3c93d4b0bdb32e5a837f281438",
            "nonce": "0000000000400ee0",
            "d": 99693760199151170059172331486081907352237598845267005513376026899853403721406,
            "share": "63b681227e7a131e9afd7d860fe77cd75aa83de75cc2732b4d6d4c14a4675fbe",
            "difficulty": 1,
            "status": "invalid"
        }

        block = ShareSerializer()
        response = block.validate(share)
        # check status for this block is invalid
        self.assertEqual(response.get("status"), "invalid")
        self.assertEqual(result_validate, response)

    def test_status_invalid_wrong_input(self):
        """
         Test for input wrong, params not hex and in this test, we must get status invalid for a public_key
          that there is in database.
         """
        Block.objects.create(public_key="0354043bd5f16526b0184e6521a0bd462783f8b178db37ec034328a23fed4855a9",
                             msg="f548e38f716e90f52078880c7cdc5a81e27676b26b9b9251b5539e6b1df2ffb5",
                             tx_id="53c538c7f7fcc79e2980ce41ac65ddf9d3db979a9aeeccd9b46d8e81a8a291d5")

        share = {
            "pk": "0354043bd5f16526b0184e6521a0bd462783f8b178db37ec034328a23fed4855a9",
            "w": "1",
            "nonce": "1",
            "d": 1
        }

        block = ShareSerializer()
        response = block.validate(share)
        self.assertEqual("invalid", response['status'])

    def test_status_failed_not_exist_public_key(self):
        """
         This Test is for status that public_key not exist in data_base and we want to raise exception validation error
          and get status 'failed'
         """

        share = {
            "pk": "0354043bd5f16526b0184e6521a0bd462783f8b178db37ec034328a23fed4855a9",
            "w": "03b783831ab40435c02bf0b3225890540b9689db3c93d4b0bdb32e5a837f281438",
            "nonce": "0000000000400ee0",
            "d": 99693760199151170059172331486081907352237598845267005513376026899853403721406
        }

        block = ShareSerializer()
        try:
            block.validate(share)
        except ValidationError as e:
            self.assertEquals('failed', e.args[0]['status'])


class ConfigurationManageApiTest(TestCase):
    """
    Test class for Configuration API
    This class has 3 test function based on 3 following general situations:
    1) using http 'get' method to retrieve a list of existing configurations
    2) using http 'post' method to create a new configuration
    3) using http 'post' method to update an existing configuration
    """

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
            return MockResponse({
                    'some_key': 1,
                    CONFIGURATION_KEY_CHOICE[0][0]: 1
            }, 200)

        return None

    def mocked_requests_options(*args, **kwargs):
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
            return MockResponse({
                "actions": {
                    "POST": {
                        "key": {
                            "choices": [
                                {
                                    "value": "some_key",
                                    "display_name": "some key"
                                },
                                {
                                    "value": CONFIGURATION_KEY_CHOICE[0][0],
                                    "display_name": "not important"
                                }
                            ]
                        },
                    }
                }
            }, 200)

        return None

    def setUp(self):
        self.factory = RequestFactory()
        User.objects.create_user(username='test', password='test')

    @patch('requests.get', side_effect=mocked_requests_get)
    @patch('requests.options', side_effect=mocked_requests_options)
    def test_configuration_Api_get_method_list(self, mocked_requests_options, mocked_requests_get):
        """
        In this scenario we want to test the functionality of Configuration API when
        it is called by a http 'get' method.
        For the above purpose first we create some configurations in the database and then
        we send a http 'get' method to retrieve a list of them.
        We expect that the status code of response be '200 ok' and
        the json format of response be as below (a list of dictionaries).
        one key is also present in accounting
        :return:
        """
        # Authorize for request /api/config/manage session
        self.client = APIClient()
        self.client.login(username='test', password='test')
        # retrieve all possible keys for KEY_CHOICES
        keys = [key for (key, temp) in CONFIGURATION_KEY_CHOICE]
        # define expected response as an empty list
        expected_response = dict(CONFIGURATION_DEFAULT_KEY_VALUE)
        # create a json like dictionary for any key in keys
        for key in keys:
            Configuration.objects.create(key=key, value='1')
            val_type = CONFIGURATION_KEY_TO_TYPE[key]
            expected_response[key] = locate(val_type)('1')

        expected_response['some_key'] = 1
        # send a http 'get' request to the configuration endpoint
        response = self.client.get('/api/config/manage/')
        # check the status of the response
        self.assertEqual(response.status_code, 200)
        # check the content of the response
        response = response.json()
        self.assertEqual(response, expected_response)

    @patch('requests.post')
    @patch('requests.get', side_effect=mocked_requests_get)
    @patch('requests.options', side_effect=mocked_requests_options)
    def test_configuration_api_post_method_create(self, mocked_requests_options, mocked_requests_get,
                                                  mocked_requests_post):
        """
        In this scenario we want to test the functionality of Configuration API when
        it is called by a http 'post' method to create a new configuration
        For this purpose we send a http 'post' method to create a new configuration with a non-existing key in database.
        We expect that the status code of response be '201' and
        the new configuration object exists in database with a value as below.
        :return:
        """
        # Authorize for request /api/config/manage session
        self.client = APIClient()
        self.client.login(username='test', password='test')
        # retrieve all possible keys for KEY_CHOICES
        keys = [key for (key, temp) in CONFIGURATION_KEY_CHOICE]
        # send http 'post' request to the configuration endpoint and validate the result
        for key in keys:
            # send http 'post' request to the endpoint
            response = self.client.post('/api/config/manage/', {'key': key, 'value': '1'})
            # check the status of the response
            self.assertEqual(response.status_code, 201)
            # retrieve the new created configuration from database
            configuration = Configuration.objects.get(key=key)
            # check whether the above object is created and saved to database or not
            self.assertIsNotNone(configuration)
            # check the value of the new created object
            self.assertEqual(configuration.value, '1')

        mocked_requests_post.assert_called_once()

    @patch('requests.post')
    @patch('requests.get', side_effect=mocked_requests_get)
    @patch('requests.options', side_effect=mocked_requests_options)
    def test_configuration_api_post_method_update(self, mocked_requests_options, mocked_requests_get,
                                                  mocked_requests_post):
        """
        In this scenario we want to test the functionality of Configuration API when
        it is called by a http 'post' method to update an existing configuration.
        For this purpose we send a http 'post' request for an existing configuration object in database.
        We expect that the status code of response be '201' and
        the new configuration object be updated in database with a new value as below.
        :return:
        """
        # Authorize for request /api/config/manage session
        self.client = APIClient()
        self.client.login(username='test', password='test')
        # retrieve all possible keys for KEY_CHOICES
        keys = [key for (key, temp) in CONFIGURATION_KEY_CHOICE]
        # send http 'post' request to the configuration endpoint and validate the result
        for key in keys:
            # create a configuration object to check the functionality of 'post' method
            Configuration.objects.create(key=key, value=1)
            # send http 'post' request to the endpoint
            response = self.client.post('/api/config/manage/', {'key': key, 'value': '2'})
            # check the status of the response
            self.assertEqual(response.status_code, 201)
            # retrieve the new created configuration from database
            configurations = Configuration.objects.filter(key=key)
            # check whether the above object is created and saved to database or not
            self.assertEqual(configurations.count(), 1)
            # check the value of the new created object
            self.assertEqual(configurations.first().value, '2')

        mocked_requests_post.assert_called_once()

    @patch('requests.post')
    @patch('requests.get', side_effect=mocked_requests_get)
    @patch('requests.options', side_effect=mocked_requests_options)
    def test_configuration_api_post_accounting(self, mocked_requests_options, mocked_requests_get,
                                               mocked_requests_post):
        """
        int this scenario we set a key which is present in accounting
        :return:
        """
        # Authorize for request /api/config/manage session
        self.client = APIClient()
        self.client.login(username='test', password='test')
        key = 'some_key'
        self.client.post('/api/config/manage/', {'key': key, 'value': '2'})
        self.assertEqual(Configuration.objects.filter(key=key).count(), 0)
        mocked_requests_post.assert_has_calls([call(urljoin(ACCOUNTING_URL, 'conf/'), data={'key': key, 'value': '2'})])

    def tearDown(self):
        """
        tearDown function to delete all configuration objects
        :return:
        """
        # delete all configuration objects
        Configuration.objects.all().delete()


class ConfigurationValueApiTest(TransactionTestCase):
    """
    Test class for Configuration API
    This class has 3 test function based on 3 following general situations:
    1) using http 'get' method to retrieve a list of existing configurations
    """
    reset_sequences = True

    def mocked_node_request(*args, **kwargs):
        """
        mock function node_request for urls wallet/addresses'
        """
        if args[0] == "wallet/addresses":
            return {
                "status": "success",
                "response": ["3WwYLP3oDYogUc8x9BbcnLZvpVqT5Zc77RHjoy19PyewAJMy9aDM"]
            }

    @patch("Api.utils.general.General.node_request", side_effect=mocked_node_request)
    def test_configuration_api_get_method_list_with_default(self, mock):
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
        # Remove all objects from the database for that check if an object there isn't in the database set default value
        Configuration.objects.all().delete()
        # response of API /config/value should be this
        PRECISION = Configuration.objects.REWARD_FACTOR_PRECISION
        REWARD = round((CONFIGURATION_DEFAULT_KEY_VALUE['TOTAL_REWARD'] / 1e9) * CONFIGURATION_DEFAULT_KEY_VALUE['REWARD_FACTOR'], PRECISION)
        REWARD = int(REWARD * 1e9)
        result = {
            "reward": REWARD,
            "wallet_address": "3WwYLP3oDYogUc8x9BbcnLZvpVqT5Zc77RHjoy19PyewAJMy9aDM",
            "pool_base_factor": CONFIGURATION_DEFAULT_KEY_VALUE['POOL_BASE_FACTOR'],
            "max_chunk_size": 10,
        }
        # send a http 'get' request to the configuration endpoint
        response = self.client.get('/api/config/value/')
        # check the status of the response
        self.assertEqual(response.status_code, 200)
        # check the content of the response
        self.assertEqual(response.json(), result)

    @patch("Api.utils.general.General.node_request", side_effect=mocked_node_request)
    def test_configuration_api_get_method_list(self, mock):
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
        Configuration.objects.create(key='TOTAL_REWARD', value=str(int(40e9)))
        Configuration.objects.create(key='REWARD_FACTOR', value='1')
        Configuration.objects.create(key='POOL_BASE_FACTOR', value='1')
        Configuration.objects.create(key='SHARE_CHUNK_SIZE', value='20')
        # response of API /config/value should be this
        result = {
            "reward": int(40e9),
            "wallet_address": "3WwYLP3oDYogUc8x9BbcnLZvpVqT5Zc77RHjoy19PyewAJMy9aDM",
            "pool_base_factor": 1,
            "max_chunk_size": 20,
        }

        # send a http 'get' request to the configuration endpoint
        response = self.client.get('/api/config/value/')
        # check the status of the response
        self.assertEqual(response.status_code, 200)
        # check the content of the response
        self.assertEqual(response.json(), result)

    def test_configuration_manager(self):
        """
        this test set all config in database and want get values that set in database for config
        :return:
        """
        for key in CONFIGURATION_KEY_CHOICE:
            Configuration.objects.create(key=key[0], value='2000')
        for key in CONFIGURATION_KEY_CHOICE:
            self.assertEqual(getattr(Configuration.objects, key[0]), 2000)
