from django.test.testcases import TransactionTestCase, TestCase
from unittest.mock import patch
from Api.models import Block
from Api.util import validation_block, gen_indexes, gen_element, validation_proof
from ErgoApi.settings import NODE_ADDRESS
import struct


class TestValidateProof(TransactionTestCase):
    reset_sequences = True

    def test_validate_proof(self):
        Block.objects.create(public_key="0354043bd5f16526b0184e6521a0bd462783f8b178db37ec034328a23fed4855a9",
                             tx_id="53c538c7f7fcc79e2980ce41ac65ddf9d3db979a9aeeccd9b46d8e81a8a291d5")
        pk = "0354043bd5f16526b0184e6521a0bd462783f8b178db37ec034328a23fed4855a9"
        msg_pre_image_base16 = "0146062b27d06c1155898ce2a04db6686a84af710135e87dfb89eaac4a32b58a4872011e52944ffdcd5e7f745ba14df4487ce8cf30f9b02a2be0c5a1096f8b612c190194448af0d8c9ae2170a7d970f621d18707dc4c2d5e9ec168adb1895e5cbbc555853afe04d0a87819523798e4db5f1b75fd43512cf76c5a3ce5eb8527725e12d1c3f9e0eb2db112e2d742dc71c6aa2df4b35fec85d8c28f6dc954796f3f95c308721e60cc9505016238dfbd02000000"
        leaf = "53c538c7f7fcc79e2980ce41ac65ddf9d3db979a9aeeccd9b46d8e81a8a291d5"
        levels_encoded = ["01c9a7e42a405a771add3b28b2538731577322930648b08ef4e5fd98854c064a7a"]
        output = validation_proof(pk, msg_pre_image_base16, leaf, levels_encoded)
        self.assertEqual(output, {
                    'public_key': '0354043bd5f16526b0184e6521a0bd462783f8b178db37ec034328a23fed4855a9',
                    'message': 'The proof is valid.',
                    'status': 'success'
            })


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
        return MockResponse({"headersHeight": 41496})

    return MockResponse(None)


class TestValidateBlock(TransactionTestCase):
    reset_sequences = True

    def test_gen_indexes(self):
        """
        input function gen_indexes is concat array-bytes of msg and nonce
        """
        msg = "cfc5f330a71a99616453b18e572ee06a7e045e0c2f6cf35ce7d490572ec7a2ac".encode("ascii")
        nonce = "000000058B1CE60D".encode("ascii")
        output = gen_indexes(msg + nonce)
        self.assertEqual(output, [54118084, 29803733, 46454084, 13976688, 21262480, 7376957, 9452803, 3998647, 17020853, 62371271, 62244663, 29833011, 53949362, 53719676, 62029037,41741671, 15558442, 23538307, 53117732, 42149055, 52740024, 12564581, 62416135, 6620933, 17237427, 50705181, 28515596, 52235322, 17578593, 3826135, 39966521, 30882246])

    def test_gen_element(self):
        """
        input function gen_element is message, pk, w, member of output gen_indexes
        """
        msg = "cfc5f330a71a99616453b18e572ee06a7e045e0c2f6cf35ce7d490572ec7a2ac".encode("ascii")
        p1 = "02385E11D92F8AC74155878EE318B8A0FC4FC1FDA9D1D48A5EC34778F55DF01C6C".encode("ascii")
        p2 = "02600D9BEEE35425E5C467A4295D49EDAEF15E22C8B2EF7E916A9BE30EC7DA3B65".encode("ascii")
        out_gen_indexes = 54118084
        output = gen_element(msg, p1, p2, struct.pack('>I', out_gen_indexes))
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

        pow_solution = validation_block("0354043bd5f16526b0184e6521a0bd462783f8b178db37ec034328a23fed4855a9",
                                        "03b783831ab40435c02bf0b3225890540b9689db3c93d4b0bdb32e5a837f281438",
                                        "0000000000400ae0",
                                        99693760199151170059172331486081907352237598845267005513376026899853403721406)
        self.assertEqual(pow_solution,
                         {'public_key': '0354043bd5f16526b0184e6521a0bd462783f8b178db37ec034328a23fed4855a9',
                             'share': 'a1ae8ae3f9f9568fd90ac29009c18997d50829d1f7c0cd0bb500d930631f2065',
                             'status': 'solved',
                             'headersHeight': 41496,
                             'tx_id': '53c538c7f7fcc79e2980ce41ac65ddf9d3db979a9aeeccd9b46d8e81a8a291d5'})

    @patch('ErgoApi.settings')
    @patch('requests.get', side_effect=mocked_requests_get)
    def test_validate_block_biggerY(self, mock_get, mock_setting):
        """
         Solution
         Check that d > POOL_DIFFICULTY or left =! right for a share invalid.
         """
        mock_setting.POOL_DIFFICULTY = 125792089237316195423570985008687907852837564279074904382605163141518161494337
        Block.objects.create(public_key="0354043bd5f16526b0184e6521a0bd462783f8b178db37ec034328a23fed4855a9",
                             msg="f548e38f716e90f52078880c7cdc5a81e27676b26b9b9251b5539e6b1df2ffb5",
                             tx_id="53c538c7f7fcc79e2980ce41ac65ddf9d3db979a9aeeccd9b46d8e81a8a291d5")

        pow_solution = validation_block("0354043bd5f16526b0184e6521a0bd462783f8b178db37ec034328a23fed4855a9",
                                        "03b783831ab40435c02bf0b3225890540b9689db3c93d4b0bdb32e5a837f281438",
                                        "0000000000400ee0",
                                        99693760199151170059172331486081907352237598845267005513376026899853403721406)
        self.assertEqual(pow_solution,
                         {'public_key': '0354043bd5f16526b0184e6521a0bd462783f8b178db37ec034328a23fed4855a9',
                             'share': '63b681227e7a131e9afd7d860fe77cd75aa83de75cc2732b4d6d4c14a4675fbe',
                             'status': 'invalid'})
