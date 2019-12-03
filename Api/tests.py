from django.test import TestCase
from django.test.testcases import TransactionTestCase
from Api.util import validation_proof


class TestValidateProof(TransactionTestCase):
    reset_sequences = True

    def test_validate_proof(self):
        pk = "02b3d02c42ee01742e09d0ce1061a7c8865b26f84f964563aeaa9df7d2089aac9e"
        msg_pre_image_base16 = "0146062b27d06c1155898ce2a04db6686a84af710135e87dfb89eaac4a32b58a4872011e52944ffdcd5e7f745ba14df4487ce8cf30f9b02a2be0c5a1096f8b612c190194448af0d8c9ae2170a7d970f621d18707dc4c2d5e9ec168adb1895e5cbbc555853afe04d0a87819523798e4db5f1b75fd43512cf76c5a3ce5eb8527725e12d1c3f9e0eb2db112e2d742dc71c6aa2df4b35fec85d8c28f6dc954796f3f95c308721e60cc9505016238dfbd02000000"
        leaf = "53c538c7f7fcc79e2980ce41ac65ddf9d3db979a9aeeccd9b46d8e81a8a291d5"
        levels_encoded = ["01c9a7e42a405a771add3b28b2538731577322930648b08ef4e5fd98854c064a7a"]
        output = validation_proof(pk, msg_pre_image_base16, leaf, levels_encoded)
        self.assertEqual(output, {
                    'public_key': '02b3d02c42ee01742e09d0ce1061a7c8865b26f84f964563aeaa9df7d2089aac9e',
                    'message': 'The proof is valid.',
                    'status': 'success'
            })


class ApiTest(TestCase):

    def test_submit_share(self):
        pass
