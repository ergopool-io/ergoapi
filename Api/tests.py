from django.test.testcases import TransactionTestCase, TestCase
from django.test.client import RequestFactory
from rest_framework.test import APIClient
from unittest.mock import patch
from Api.models import Block, KEY_CHOICES, Configuration, DEFAULT_KEY_VALUES
from django.contrib.auth.models import User
from Api.serializers import ShareSerializer
from ErgoApi.settings import NODE_ADDRESS
import struct


class TestValidateProof(TransactionTestCase):
    reset_sequences = True

    def test_validate_proof(self):
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
        Block.objects.create(public_key="0354043bd5f16526b0184e6521a0bd462783f8b178db37ec034328a23fed4855a9",
                             tx_id="53c538c7f7fcc79e2980ce41ac65ddf9d3db979a9aeeccd9b46d8e81a8a291d5")
        proof_data = {"pk": "0354043bd5f16526b0184e6521a0bd462783f8b178db37ec034328a23fed4855a9",
                      "msg_pre_image": "0146062b27d06c1155898ce2a04db6686a84af710135e87dfb89eaac4a32b58a4872011e52944ffdcd5e7f745ba14df4487ce8cf30f9b02a2be0c5a1096f8b612c190194448af0d8c9ae2170a7d970f621d18707dc4c2d5e9ec168adb1895e5cbbc555853afe04d0a87819523798e4db5f1b75fd43512cf76c5a3ce5eb8527725e12d1c3f9e0eb2db112e2d742dc71c6aa2df4b35fec85d8c28f6dc954796f3f95c308721e60cc9505016238dfbd02000000",
                      "leaf": "53c538c7f7fcc79e2980ce41ac65ddf9d3db979a9aeeccd9b46d8e81a8a291d5",
                      "levels": [
                            "01c9a7e42a405a771add3b28b2538731577322930648b08ef4e5fd98854c064a7a"
                        ]}
        result = {
                "pk": "0354043bd5f16526b0184e6521a0bd462783f8b178db37ec034328a23fed4855a9",
                "msg_pre_image": "0146062b27d06c1155898ce2a04db6686a84af710135e87dfb89eaac4a32b58a4872011e52944ffdcd5e7f745ba14df4487ce8cf30f9b02a2be0c5a1096f8b612c190194448af0d8c9ae2170a7d970f621d18707dc4c2d5e9ec168adb1895e5cbbc555853afe04d0a87819523798e4db5f1b75fd43512cf76c5a3ce5eb8527725e12d1c3f9e0eb2db112e2d742dc71c6aa2df4b35fec85d8c28f6dc954796f3f95c308721e60cc9505016238dfbd02000000",
                "leaf": "53c538c7f7fcc79e2980ce41ac65ddf9d3db979a9aeeccd9b46d8e81a8a291d5",
                "levels": [
                    "01c9a7e42a405a771add3b28b2538731577322930648b08ef4e5fd98854c064a7a"
                ],
                "message": "The proof is valid.",
                "status": "success"
                }
        # send a http 'post' request to the configuration endpoint
        response = self.client.post('/api/header/', data=proof_data, content_type="application/json")
        # check the status of the response
        self.assertEqual(response.status_code, 201)
        # check the content of the response
        self.assertEqual(response.json(), result)


def mocked_requests_get(*args, **kwargs):
    class MockResponse:
        def __init__(self, json_data):
            self.json_data = json_data

        def json(self):
            return self.json_data

    if args[0] == NODE_ADDRESS + 'mining/candidate':
        return MockResponse({
            "b": 115792089237316195423570985008687907852837564279074904382605163141518161494337
        })
    elif args[0] == NODE_ADDRESS + 'info':
        return MockResponse({"headersHeight": 41496,
                             "difficulty": 12345})

    elif args[0] == NODE_ADDRESS + 'wallet/addresses':
        return MockResponse(["3WvrVTCPJ1keSdtqNL5ayzQ62MmTNz4Rxq7vsjcXgLJBwZkvHrGa"])

    return MockResponse(None)


class TestValidateBlock(TransactionTestCase):
    reset_sequences = True

    def test_gen_indexes(self):
        """
        input function gen_indexes is concat array-bytes of msg and nonce
        """
        msg = "cfc5f330a71a99616453b18e572ee06a7e045e0c2f6cf35ce7d490572ec7a2ac".encode("ascii")
        nonce = "000000058B1CE60D".encode("ascii")
        block = ShareSerializer()
        output = block.__gen_indexes__(msg + nonce)
        self.assertEqual(output, [54118084, 29803733, 46454084, 13976688, 21262480, 7376957, 9452803, 3998647, 17020853,
                                  62371271, 62244663, 29833011, 53949362, 53719676, 62029037,41741671, 15558442,
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
        output = block.__gen_element__(msg, p1, p2, struct.pack('>I', out_gen_indexes))
        self.assertEqual(output, 1442183731460476782005370820367939156210879287829514232459313282341328232038)

    @patch('requests.get', side_effect=mocked_requests_get)
    def test_validate_block_lesX(self, mock_get):
        """
        Solution
        Check that d < b and left == right for a share solved.
        """

        Block.objects.create(public_key="0354043bd5f16526b0184e6521a0bd462783f8b178db37ec034328a23fed4855a9",
                             msg="f548e38f716e90f52078880c7cdc5a81e27676b26b9b9251b5539e6b1df2ffb5",
                             tx_id="53c538c7f7fcc79e2980ce41ac65ddf9d3db979a9aeeccd9b46d8e81a8a291d5")
        share = {
            "pk": "0354043bd5f16526b0184e6521a0bd462783f8b178db37ec034328a23fed4855a9",
            "w": "03b783831ab40435c02bf0b3225890540b9689db3c93d4b0bdb32e5a837f281438",
            "nonce": "0000000000400ae0",
            "d": 99693760199151170059172331486081907352237598845267005513376026899853403721406
        }
        result_validate = {"pk": "0354043bd5f16526b0184e6521a0bd462783f8b178db37ec034328a23fed4855a9",
                           "w": "03b783831ab40435c02bf0b3225890540b9689db3c93d4b0bdb32e5a837f281438",
                           "nonce": "0000000000400ae0",
                           "d": 99693760199151170059172331486081907352237598845267005513376026899853403721406,
                           "share": "a1ae8ae3f9f9568fd90ac29009c18997d50829d1f7c0cd0bb500d930631f2065",
                           "status": "solved",
                           "difficulty": 12345,
                           "headers_height": 41496,
                           "tx_id": "53c538c7f7fcc79e2980ce41ac65ddf9d3db979a9aeeccd9b46d8e81a8a291d5"}
        block = ShareSerializer()
        response = block.validate(share)
        self.assertEqual(response, result_validate)

    @patch('ErgoApi.settings')
    @patch('requests.get', side_effect=mocked_requests_get)
    def test_validate_block_invalid(self, mock_get, mock_setting):
        """
         Solution
         Check that d > POOL_DIFFICULTY or left =! right for a share invalid.
         """
        mock_setting.POOL_DIFFICULTY = 125792089237316195423570985008687907852837564279074904382605163141518161494337
        Block.objects.create(public_key="0354043bd5f16526b0184e6521a0bd462783f8b178db37ec034328a23fed4855a9",
                             msg="f548e38f716e90f52078880c7cdc5a81e27676b26b9b9251b5539e6b1df2ffb5",
                             tx_id="53c538c7f7fcc79e2980ce41ac65ddf9d3db979a9aeeccd9b46d8e81a8a291d5")

        share = {"pk": "0354043bd5f16526b0184e6521a0bd462783f8b178db37ec034328a23fed4855a9",
                 "w": "03b783831ab40435c02bf0b3225890540b9689db3c93d4b0bdb32e5a837f281438",
                 "nonce": "0000000000400ee0",
                 "d": 99693760199151170059172331486081907352237598845267005513376026899853403721406
                 }
        result_validate = {"pk": "0354043bd5f16526b0184e6521a0bd462783f8b178db37ec034328a23fed4855a9",
                           "w": "03b783831ab40435c02bf0b3225890540b9689db3c93d4b0bdb32e5a837f281438",
                           "nonce": "0000000000400ee0",
                           "d": 99693760199151170059172331486081907352237598845267005513376026899853403721406,
                           "share": "63b681227e7a131e9afd7d860fe77cd75aa83de75cc2732b4d6d4c14a4675fbe",
                           "difficulty": 12345,
                           "status": "invalid"}

        block = ShareSerializer()
        response = block.validate(share)
        self.assertEqual(result_validate, response)


class ConfigurationManageApiTest(TestCase):
    """
    Test class for Configuration API
    This class has 3 test function based on 3 following general situations:
    1) using http 'get' method to retrieve a list of existing configurations
    2) using http 'post' method to create a new configuration
    3) using http 'post' method to update an existing configuration
    """
    def setUp(self):
        self.factory = RequestFactory()
        User.objects.create_user(username='test', password='test')

    def test_configuration_Api_get_method_list(self):
        """
        In this scenario we want to test the functionality of Configuration API when
        it is called by a http 'get' method.
        For the above purpose first we create some configurations in the database and then
        we send a http 'get' method to retrieve a list of them.
        We expect that the status code of response be '200 ok' and
        the json format of response be as below (a list of dictionaries).
        :return:
        """
        # Authorize for request /api/config/manage session
        self.client = APIClient()
        self.client.login(username='test', password='test')
        # retrieve all possible keys for KEY_CHOICES
        keys = [key for (key, temp) in KEY_CHOICES]
        # define expected response as an empty list
        expected_response = []
        # create a json like dictionary for any key in keys
        for key in keys:
            Configuration.objects.create(key=key, value=1)
            expected_response.append({'key': key, 'value': 1.0})
        # send a http 'get' request to the configuration endpoint
        response = self.client.get('/api/config/manage/')
        # check the status of the response
        self.assertEqual(response.status_code, 200)
        # check the content of the response
        self.assertEqual(response.json(), expected_response)

    def test_configuration_api_post_method_create(self):
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
        keys = [key for (key, temp) in KEY_CHOICES]
        # send http 'post' request to the configuration endpoint and validate the result
        for key in keys:
            # send http 'post' request to the endpoint
            response = self.client.post('/api/config/manage/', {'key': key, 'value': 1})
            # check the status of the response
            self.assertEqual(response.status_code, 201)
            # retrieve the new created configuration from database
            configuration = Configuration.objects.get(key=key)
            # check whether the above object is created and saved to database or not
            self.assertIsNotNone(configuration)
            # check the value of the new created object
            self.assertEqual(configuration.value, 1)

    def test_configuration_api_post_method_update(self):
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
        keys = [key for (key, temp) in KEY_CHOICES]
        # send http 'post' request to the configuration endpoint and validate the result
        for key in keys:
            # create a configuration object to check the functionality of 'post' method
            Configuration.objects.create(key=key, value=1)
            # send http 'post' request to the endpoint
            response = self.client.post('/api/config/manage/', {'key': key, 'value': 2})
            # check the status of the response
            self.assertEqual(response.status_code, 201)
            # retrieve the new created configuration from database
            configurations = Configuration.objects.filter(key=key)
            # check whether the above object is created and saved to database or not
            self.assertEqual(configurations.count(), 1)
            # check the value of the new created object
            self.assertEqual(configurations.first().value, 2)

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

    @patch('requests.get', side_effect=mocked_requests_get)
    def test_configuration_api_get_method_list_with_default(self, mock_get):
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
        result = {
            "reward": int(DEFAULT_KEY_VALUES['REWARD'] * DEFAULT_KEY_VALUES['REWARD_FACTOR'] * pow(10, 9)),
            "wallet_address": "3WvrVTCPJ1keSdtqNL5ayzQ62MmTNz4Rxq7vsjcXgLJBwZkvHrGa",
            "pool_difficulty_factor": DEFAULT_KEY_VALUES['POOL_DIFFICULTY_FACTOR']
            }
        # send a http 'get' request to the configuration endpoint
        response = self.client.get('/api/config/value/')
        # check the status of the response
        self.assertEqual(response.status_code, 200)
        # check the content of the response
        self.assertEqual(response.json(), result)

    @patch('requests.get', side_effect=mocked_requests_get)
    def test_configuration_api_get_method_list(self, mock_get):
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
        Configuration.objects.create(key='REWARD', value='40')
        Configuration.objects.create(key='REWARD_FACTOR', value='1')
        Configuration.objects.create(key='POOL_DIFFICULTY_FACTOR', value='1')
        # response of API /config/value should be this
        result = {
            "reward": 40 * 1 * pow(10, 9),
            "wallet_address": "3WvrVTCPJ1keSdtqNL5ayzQ62MmTNz4Rxq7vsjcXgLJBwZkvHrGa",
            "pool_difficulty_factor": 1
            }

        # send a http 'get' request to the configuration endpoint
        response = self.client.get('/api/config/value/')
        # check the status of the response
        self.assertEqual(response.status_code, 200)
        # check the content of the response
        self.assertEqual(response.json(), result)
