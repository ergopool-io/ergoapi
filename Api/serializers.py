from urllib.parse import urljoin

import requests
from rest_framework import serializers, status
from rest_framework.exceptions import ValidationError
from Api.models import Configuration, Block
from Api.utils.general import General
from ErgoApi.settings import API_KEY, ACCOUNTING_URL

from codecs import decode
from ecpy.curves import Curve
import struct
import logging

logger = logging.getLogger(__name__)


class ShareSerializer(serializers.Serializer, General):
    pk = serializers.CharField()
    nonce = serializers.CharField()
    d = serializers.CharField()
    w = serializers.CharField()
    difficulty = serializers.IntegerField(required=False, read_only=True)
    share = serializers.CharField(required=False, read_only=True)
    status = serializers.CharField(required=False, read_only=True)
    tx_id = serializers.CharField(required=False, read_only=True)
    headers_height = serializers.CharField(required=False, read_only=True)

    K = 32
    # Number of elements in one solution
    M = b''
    # For convert m to 'flat map'
    n = 26
    # power of number of elements in a list
    N = pow(2, n)
    # Total number of elements
    curve = Curve.get_curve('secp256k1')
    ec_order = curve.order
    ec_generator = curve.generator
    # Create curve[Elliptic Curve Cryptography]
    # Cyclic group 'ec_generator' of prime order 'ec_order' with fixed generator 'ec_generator' and identity element
    # 'e.Secp256k1' elliptic curve
    # is used for this purpose
    valid_range = int(pow(2, 256) / ec_order) * ec_order

    def __init__(self, *args, **kwargs):
        self.base_factor = Configuration.objects.POOL_BASE_FACTOR
        super(ShareSerializer, self).__init__(*args, **kwargs)

    # biggest number <= 2^256 that is divisible by q without remainder

    def validate_d(self, value):
        try:
            return int(value)
        except:
            raise ValidationError("invalid number entered")

    def __get_base__(self, difficulty):
        """
        convert difficulty to base of network with division order of elliptic curve to difficulty
        :param difficulty: difficulty of network
        :return: base
        """
        return int(self.ec_order / difficulty)

    def __gen_indexes__(self, seed):
        """
        Algorithm 4
        function that takes `m` and `nonceBytes` and returns a list of size `k` with numbers in [0,`N`)
        :param seed:(Array Of Bytes)
        :return: Sequence of int
        """
        hash_seed = self.blake(seed)
        extended_hash = hash_seed + hash_seed[:3]
        result = list(map(lambda i: struct.unpack('>I', extended_hash[i:i + 4])[0] % self.N, range(0, self.K)))
        if len(result) == self.K:
            return list(result)
        logger.error('Length of map does not equal K.')
        raise ValidationError({
            'status': 'failed',
            'message': 'gen_indexes : The length of map not equal K'
        })

    def __hash_in__(self, array_byte):
        """
        Algorithm 3
        One way cryptographic hash function that produces numbers in [0,ec_order) range.
        It calculates blake2b256 hash of a provided input and checks whether the result is
        in range from 0 to a maximum number divisible by ec_order without remainder.
        If yes, it returns the result mod ec_order, otherwise make one more iteration using hash as an input.
        This is done to ensure uniform distribution of the resulting numbers.

        :param array_byte:(Array Of Bytes)
        :return: (int) Go to overhead description
        """
        while True:
            hashed = self.blake(array_byte)
            bi = int.from_bytes(hashed, byteorder="big")
            if bi < self.valid_range:
                x = bi % self.ec_order
                return x
            array_byte = hashed

    def __gen_element__(self, m, pk, w, index_bytes):
        """
        Generate element of Autolykos equation.

        :param m:(Array Of Bytes)
        :param pk:(Array Of Bytes)
        :param w:(Array Of Bytes)
        :param index_bytes:(Array Of Bytes)
        :return: (int)
        """
        if self.M is b'':
            for item in map(lambda i: struct.pack('>Q', i), range(0, 1024)):
                self.M += item
        return self.__hash_in__(index_bytes + self.M + pk + m + w)

    def __ec_point__(self, array_byte):
        """
        The function decode_point from package ecpy.curves has bug, the size of the value that has been set in this
        function is 34 but must be 33. To solve this problem, check first byte of array byte input
        and according to this situation add byte 0 or 1 at the end of array byte input.

        :param array_byte: w or p
        :return: cast array byte to Ec-Point type
        """
        if array_byte[0] == 2:
            return {'value': self.curve.decode_point(array_byte + decode('00', 'hex')), 'status': 'success'}
        elif array_byte[0] == 3:
            array_byte = b'\x02' + array_byte[1:]
            return {'value': self.curve.decode_point(array_byte + decode('01', 'hex')), 'status': 'success'}
        else:
            logger.error("First bytes of w_bytes is invalid.")
            raise ValidationError({
                'status': 'invalid',
                'message': 'First bytes of w_bytes is invalid.'
            })

    def __validate_difficulty__(self, d, difficulty):
        """
        validate pool difficulty and base and d
        :param d:(int) distance between pseudo-random number, corresponding to nonce `n` and a secret,
                    corresponding to `pk`. The lower `d` is, the harder it was to find this solution.
        :param difficulty:(int) difficulty of network
        :return: if d<b return 1 else if b<d<pb return 2 else return 0
        """
        # Convert difficulty to base
        base = self.__get_base__(difficulty)
        # Set POOL_DIFFICULTY
        pool_difficulty = base * self.base_factor
        # Compare difficulty and base and return
        return 1 if d < base else (2 if base < d < pool_difficulty else 0)

    def __validate_right_left__(self, message, nonce, p1, p2, d):
        f = list()
        for i in self.__gen_indexes__(message + nonce):
            check = self.__gen_element__(message, p1, p2, struct.pack('>I', i))
            f.append(check)
        f = sum(f) % self.ec_order
        pk_ec_point = self.__ec_point__(p1)
        w_ec_point = self.__ec_point__(p2)
        left = w_ec_point['value'].mul(f)
        right = self.ec_generator.mul(d).add(pk_ec_point['value'])
        return 1 if left == right else 0

    def validate(self, attrs):
        n = attrs['nonce']
        pk = attrs['pk'].lower()
        w = attrs['w']
        d = attrs['d']

        # Convert to array bytes
        try:
            nonce = decode(n, "hex")
            p1 = decode(pk, "hex")
            p2 = decode(w, "hex")
        except ValueError as e:
            logger.error("Share input parameters aren't valid.")
            logger.error(e)
            # Generate uniq id for share
            attrs.update({
                'share': self.blake((pk + n + w).encode('utf-8'), 'hex'),
                'status': "invalid"
            })
            return attrs

        try:
            # Get information share(ex: Message(hash of header block), Transaction Id) from database
            block = Block.objects.get(public_key=pk)
            # Convert to array bytes
            message = decode(block.msg, "hex")
            # Transaction Id
            tx_id = block.tx_id
            # Generate uniq id for share
            share_id = self.blake(message + nonce + p1 + p2, 'hex')
            logger.info('Block for pk {} is present.'.format(pk))
        except Block.DoesNotExist:
            logger.error('Block for pk {} does not exist, can not set share!'.format(pk))
            raise ValidationError({
                'message': 'There isn\'t this public-key',
                'status': 'failed'
            })
        # Request to node for get headersHeight
        data_node = self.node_request('info', {'accept': 'application/json'})
        height = data_node.get('response').get('headersHeight')
        difficulty = data_node.get('response').get('difficulty')
        # Create response for share
        response = {
            'share': share_id,
            'status': '',
            'difficulty': int(difficulty / self.base_factor)
        }
        # Validate solved or valid or invalid (d > pool difficulty)
        logger.info('Validating difficulty for share with pk {}.'.format(pk))
        flag = self.__validate_difficulty__(d, difficulty)
        logger.info('Difficulty validation result for share with pk {}.'.format(pk))
        # validate_right_left
        validation = self.__validate_right_left__(message, nonce, p1, p2, d)
        # ValidateBlock
        if validation == 1 and flag == 1:
            response['status'] = "solved"
        elif validation == 1 and flag == 2:
            response['status'] = 'valid'
        else:
            response['status'] = 'invalid'
        response['status'] = 'solved' if validation == 1 and flag == 1 else (
            'valid' if validation == 1 and flag == 2 else 'invalid')
        logger.info('Share status with pk {}: {}'.format(pk, response['status']))
        if response['status'] == 'solved':
            response.update({'headers_height': height})
            response.update({'tx_id': tx_id})
        attrs.update(response)
        return attrs

    def update(self, instance, validated_data):
        pass

    def create(self, validated_data):
        pass

    class Meta:
        fields = ['pk', 'nonce', 'd', 'w', 'share', 'difficulty', 'status', 'tx_id', 'headers_height']


class ProofSerializer(serializers.Serializer):
    pk = serializers.CharField()
    msg_pre_image = serializers.CharField()
    leaf = serializers.CharField()
    levels = serializers.ListField(child=serializers.CharField())
    message = serializers.CharField(required=False, read_only=True)
    status = serializers.CharField(required=False, read_only=True)

    def __merkle_proof__(self, leaf, levels_encoded, pk):
        # tx_id is a "leaf" in a Merkle proof
        tx_id = leaf
        # Merkle proof element is encoded in the following way:
        # - first, 1 byte showing whether COMPUTED value is on the right (1) or on the left (0)
        # - second, 32 bytes of stored value
        try:
            levels = list(map(lambda le: [decode(le, "hex")[1:], decode(le, "hex")[0:1]], levels_encoded))
        except ValueError as e:
            logger.error("Levels input parameter in proof is not valid.")
            logger.error(e)
            raise ValidationError({
                'pk': pk,
                'message': 'Type of input is invalid',
                'status': 'failed'
            })
        leaf_hash = General.blake(decode('00', "hex") + decode(tx_id, "hex"))
        for level in levels:
            if level[1] == decode('01', "hex"):
                leaf_hash = General.blake(decode('01', "hex") + level[0] + leaf_hash)
            elif level[1] == decode('00', "hex"):
                leaf_hash = General.blake(decode('01', "hex") + leaf_hash + level[0])
        return leaf_hash

    def __validate_transaction_id__(self, pk, leaf):
        try:
            # Get information miner(ex: Transaction Id) from database
            block = Block.objects.get(public_key=pk)
            if not block.tx_id == leaf:
                logger.error('The provided leaf is not valid with pk {}'.format(pk))
                raise ValidationError({
                    'pk': pk,
                    'message': 'The leaf is invalid.',
                    'status': 'failed'
                })
        except Block.DoesNotExist:
            logger.error('Block does not exist for public-key {}'.format(pk))
            raise ValidationError({
                'pk': pk,
                'message': 'Transaction not generated.',
                'status': 'failed'
            })

    def validate(self, attrs):
        """
         Merkle roof is constructed by given leaf data, leaf hash sibling and also siblings for parent nodes. Using this
         data, it is possible to compute nodes on the path to root hash, and the hash itself. The picture of a proof
         given below. In the picture, "^^" is leaf data(to compute leaf hash from), "=" values are to be computed,
         "*" values are to be stored.

         ........= Root
         ..... /  \
         .... *   =
         ....... / \
         ...... *   =
         ......... /.\
         .........*   =
         ............ ^^
        :return: status of merkle_proof
        """
        msg_pre_image_base16 = attrs['msg_pre_image']
        leaf = attrs['leaf']
        pk = attrs['pk'].lower()
        levels_encoded = attrs['levels']
        self.__validate_transaction_id__(pk, leaf)
        try:
            msg_pre_image = decode(msg_pre_image_base16, "hex")
        except ValueError as e:
            logger.error("Proof input parameters are not valid.")
            logger.error(e)
            raise ValidationError({
                'pk': pk,
                'message': 'Type of input is invalid',
                'status': 'failed'
            })

        # hash of "msg_pre_image" (which is a header without PoW) should be equal to "msg"
        msg = General.blake(msg_pre_image, 'hex')
        # Transactions Merkle tree digest is in bytes 65-96 (inclusive) of the unproven header
        txs_root = msg_pre_image[65:97]
        # Create Merkle Proof
        leaf_hash = self.__merkle_proof__(leaf, levels_encoded, pk)
        # Validate_merkle
        if leaf_hash == txs_root:
            # if proof is valid create or update block(public key and message) in database
            obj, created = Block.objects.get_or_create(public_key=pk)
            obj.msg = msg
            obj.save()
            logger.info('Proof is valid, updated the block for pk {}'.format(pk))
            attrs.update({
                'message': 'The proof is valid.',
                'status': 'success'
            })
            return attrs
        else:
            attrs.update({
                'message': 'The proof is invalid.',
                'status': 'invalid'
            })
            return attrs

    def update(self, instance, validated_data):
        pass

    def create(self, validated_data):
        pass

    class Meta:
        fields = ['pk', 'msg_pre_image', 'leaf', 'levels', 'message', 'status']


class TransactionSerializer(serializers.Serializer, General):
    pk = serializers.CharField()
    transaction = serializers.JSONField()
    status = serializers.CharField(required=False, read_only=True)
    message = serializers.CharField(required=False, read_only=True)
    tx_id = serializers.CharField(required=False, read_only=True)

    def validate(self, attrs):
        """
        Validate transaction with request to node and check tx_id response of transactions/check with tx_id in
         transaction json then get ergo_tree from output field and convert to address wallet and check with wallet
         addresses in the event that wallet address was true check sum value of output field that be greater than reward.
        :return: status of transaction
        """
        response = {'message': '', 'tx_id': ''}
        transaction = attrs['transaction']
        attrs['transaction'] = ''
        # Send request to node for validate transaction
        data_node = self.node_request('transactions/check',
                                      {'accept': 'application/json', 'content-type': 'application/json'},
                                      data=transaction, request_type="post")
        if data_node['status'] == 'External Error':
            logger.error('Node failed to validate transaction')
            raise ValidationError({"message": data_node['response']})
        else:
            tx_id = data_node.get('response')
            response['tx_id'] = tx_id
            if tx_id == transaction['id']:
                logger.info("Getting wallet addresses to validate transaction.")
                # Send request to node for get list of wallet addresses
                data_node = self.node_request('wallet/addresses',
                                              {'accept': 'application/json', 'content-type': 'application/json',
                                               'api_key': API_KEY})
                if data_node['status'] == 'External Error':
                    logger.error('Error while getting wallet addresses.')
                    raise ValidationError({"message": data_node['response']})
                else:
                    wallet_address = data_node.get('response')
                    value = 0
                    if 'outputs' in transaction:
                        for output in transaction['outputs']:
                            # Send request to node for Generate Ergo address from hex-encoded ErgoTree
                            data_node = self.node_request('utils/ergoTreeToAddress/' + output['ergoTree'],
                                                          {'accept': 'application/json'})
                            if data_node['status'] == 'External Error':
                                raise ValidationError({"message": data_node['response']})
                            # Check address after convert ergo tree that would have existed in the wallet_address
                            elif data_node.get('response')['address'] in wallet_address:
                                    value = value + output['value']
                    # Sum value of output field should be bigger than reward policy pool.
                    if value >= Configuration.objects.REWARD * Configuration.objects.REWARD_FACTOR * pow(10, 9):
                        logger.info('Transaction is valid.')
                        response['message'] = "Transaction is valid"
                    else:
                        logger.error('Transaction is invalid, either wallet address is invalid or the value')
                        raise ValidationError({"message": ["Wallet address pool or value of transaction is invalid"]})
            else:
                logger.error('Transaction id is invalid.')
                raise ValidationError({'message': 'tx_id is invalid'})
        attrs.update(response)
        return attrs

    def update(self, instance, validated_data):
        pass

    def create(self, validated_data):
        pass

    class Meta:
        fields = ['pk', 'transaction', 'status', 'tx_id', 'message']


class ConfigurationSerializer(serializers.ModelSerializer):
    class Meta:
        model = Configuration
        fields = ['key', 'value']

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.accounting_choices = set()

        # here we update the choices by appending the choices of accounting
        curr_choices = dict(self.fields['key'].grouped_choices)

        try:
            res = requests.options(urljoin(ACCOUNTING_URL, 'conf/'))

        except requests.exceptions.RequestException:
            logger.critical('Could not connect to accounting!')
            return

        if res.status_code != status.HTTP_200_OK:
            return

        res = res.json()
        for choice in res['actions']['POST']['key']['choices']:
            curr_choices[choice['value']] = choice['display_name']
            self.accounting_choices.add(choice['value'])

        curr_choices = {(key, value) for key, value in curr_choices.items()}
        self.fields['key'].grouped_choices = curr_choices
        self.fields['key'].choices = curr_choices


class ConfigurationValueSerializer(serializers.Serializer):
    reward = serializers.IntegerField()
    wallet_address = serializers.CharField()
    pool_difficulty_factor = serializers.FloatField()

    class Meta:
        fields = ['reward', 'wallet_address', 'pool_difficulty_factor']

    def update(self, instance, validated_data):
        pass

    def create(self, validated_data):
        pass


class ValidateTransactionSerializer(serializers.Serializer, General):
    transaction = serializers.JSONField()
    status = serializers.CharField(required=False, read_only=True)
    message = serializers.CharField(required=False, read_only=True)
    tx_id = serializers.CharField(required=False, read_only=True)

    def validate(self, attrs):
        """
        Validate transaction with request to node and check tx_id response of transactions/check with tx_id in
         transaction json then get ergo_tree from output field and convert to address wallet and check with wallet
         addresses in the event that wallet address was true check sum value of output field that be greater than reward
        :return: status of transaction
        """
        response = {
            'message': '',
            'tx_id': ''
        }
        transaction = attrs['transaction']
        attrs['transaction'] = ''
        # Send request to node for validate transaction
        data_node = self.node_request('transactions/check',
                                      {'accept': 'application/json', 'content-type': 'application/json'},
                                      data=transaction, request_type="post")
        if data_node['status'] == 'External Error':
            logger.error('Node failed to validate transaction')
            raise ValidationError({
                "message": data_node['response'],
                "status": "failed"
            })
        else:
            tx_id = data_node.get('response')
            response['tx_id'] = tx_id
            if tx_id == transaction['id']:
                logger.info("Getting wallet addresses to validate transaction.")
                # Send request to node for get list of wallet addresses
                data_node = self.node_request('wallet/addresses',
                                              {'accept': 'application/json', 'content-type': 'application/json',
                                               'api_key': API_KEY})
                if data_node['status'] == 'External Error':
                    logger.error('Error while getting wallet addresses.')
                    raise ValidationError({
                        "message": data_node['response'],
                        "status": "failed"
                    })
                else:
                    wallet_address = data_node.get('response')
                    value = 0
                    if 'outputs' in transaction:
                        for output in transaction['outputs']:
                            # Send request to node for Generate Ergo address from hex-encoded ErgoTree
                            data_node = self.node_request('utils/ergoTreeToAddress/' + output['ergoTree'],
                                                          {'accept': 'application/json'})
                            if data_node['status'] == 'External Error':
                                raise ValidationError({
                                    "message": data_node['response'],
                                    "status": "failed"
                                })
                            # Check address after convert ergo tree that would have existed in the wallet_address
                            elif data_node.get('response')['address'] in wallet_address:
                                    value = value + output['value']
                    # Sum value of output field should be bigger than reward policy pool.
                    if value >= Configuration.objects.REWARD * Configuration.objects.REWARD_FACTOR * pow(10, 9):
                        logger.info('Transaction is valid.')
                        response['status'] = 'valid'
                        response['message'] = "Transaction is valid"
                    else:
                        logger.error('Transaction is invalid, either wallet address is invalid or the value')
                        raise ValidationError({"message": "Wallet address pool or value of transaction is invalid",
                                               "status": "invalid"})
            else:
                logger.error('Transaction id is invalid.')
                raise ValidationError({'message': 'tx_id is invalid', 'status': 'invalid'})
        attrs.update(response)
        return attrs

    class Meta:
        fields = ['transaction', 'status', 'tx_id', 'message']


class ValidateProofSerializer(serializers.Serializer):
    msg_pre_image = serializers.CharField()
    leaf = serializers.CharField()
    levels = serializers.ListField(child=serializers.CharField())
    msg = serializers.CharField(required=False, read_only=True)
    message = serializers.CharField(required=False, read_only=True)
    status = serializers.CharField(required=False, read_only=True)

    def __merkle_proof__(self, leaf, levels_encoded):
        # tx_id is a "leaf" in a Merkle proof
        tx_id = leaf
        # Merkle proof element is encoded in the following way:
        # - first, 1 byte showing whether COMPUTED value is on the right (1) or on the left (0)
        # - second, 32 bytes of stored value
        try:
            levels = list(map(lambda le: [decode(le, "hex")[1:], decode(le, "hex")[0:1]], levels_encoded))
        except ValueError as e:
            logger.error("Levels input parameter in proof is not valid.")
            logger.error(e)
            raise ValidationError({
                'message': 'Type of input is invalid',
                'status': 'failed'
            })
        leaf_hash = General.blake(decode('00', "hex") + decode(tx_id, "hex"))
        for level in levels:
            if level[1] == decode('01', "hex"):
                leaf_hash = General.blake(decode('01', "hex") + level[0] + leaf_hash)
            elif level[1] == decode('00', "hex"):
                leaf_hash = General.blake(decode('01', "hex") + leaf_hash + level[0])
        return leaf_hash

    def validate_msg_pre_image(self, value):
        try:
            return decode(value, "hex")
        except ValueError as e:
            logger.error("Proof input parameters are not valid.")
            logger.error(e)
            raise ValidationError('Type of input is invalid')

    def validate(self, attrs):
        """
         Merkle roof is constructed by given leaf data, leaf hash sibling and also siblings for parent nodes. Using this
         data, it is possible to compute nodes on the path to root hash, and the hash itself. The picture of a proof
         given below. In the picture, "^^" is leaf data(to compute leaf hash from), "=" values are to be computed,
         "*" values are to be stored.

         ........= Root
         ..... /  \
         .... *   =
         ....... / \
         ...... *   =
         ......... /.\
         .........*   =
         ............ ^^
        :return: status of merkle_proof
        """

        leaf = attrs['leaf']
        levels_encoded = attrs['levels']
        msg_pre_image = attrs['msg_pre_image']

        # hash of "msg_pre_image" (which is a header without PoW) should be equal to "msg"
        msg = General.blake(msg_pre_image, 'hex')
        # Transactions Merkle tree digest is in bytes 65-96 (inclusive) of the unproven header
        txs_root = msg_pre_image[65:97]
        # Create Merkle Proof
        leaf_hash = self.__merkle_proof__(leaf, levels_encoded)
        # Validate_merkle
        if leaf_hash == txs_root:
            logger.info('Proof is valid for transaction id {}'.format(leaf))
            attrs.update({
                'msg': msg,
                'message': 'The proof is valid.',
                'status': 'valid'
            })
            return attrs
        else:
            attrs.update({
                'message': 'The proof is invalid.',
                'status': 'invalid'
            })
            return attrs

    class Meta:
        fields = ['pk', 'msg_pre_image', 'leaf', 'levels', 'message', 'status']


class ValidationShareSerializer(serializers.Serializer, General):
    w = serializers.CharField()
    nonce = serializers.CharField()
    d = serializers.CharField()

    def validate_d(self, value):
        try:
            return int(value)
        except:
            raise ValidationError("invalid number entered")

    class Meta:
        fields = ['pk', 'w', 'nonce', 'd']


class AddressesSerializer(serializers.Serializer):
    miner = serializers.CharField()
    lock = serializers.CharField()
    withdraw = serializers.CharField()

    class Meta:
        fields = ['miner', 'lock', 'withdraw']


class ValidationSerializer(serializers.Serializer):
    pk = serializers.CharField()
    addresses = AddressesSerializer(many=False)
    transaction = ValidateTransactionSerializer(many=False)
    proof = ValidateProofSerializer(many=False)
    shares = ValidationShareSerializer(many=True)

    def validate_pk(self, value):
        try:
            decode(value, 'hex')
        except:
            raise ValidationError("invalid pk entered")

    def create(self, validated_data):
        pass

    class Meta:
        fields = ['pk', 'addresses', 'transaction', 'proof', 'shares']



def builder_serializer(options):
    # Define types of field
    fields_type = {
        'integer': lambda fields: serializers.IntegerField(**fields),
        'float': lambda fields: serializers.FloatField(**fields),
        'string': lambda fields: serializers.CharField(**fields),
        'choice': lambda fields: serializers.ChoiceField(**fields),
        'datetime': lambda fields: serializers.DateTimeField(**fields)
                   }

    class ProxySerializer(serializers.Serializer):

        def update(self, instance, validated_data):
            pass

        def create(self, validated_data):
            pass

        class Meta:
            fields = ['__all__']

        def __init__(self, *args, **kwargs):
            super(ProxySerializer, self).__init__(*args, **kwargs)
            # Create Fields for content rest framework
            if options:
                for action in options:
                    for filed in options[action]:
                        param = options[action][filed]
                        if param['read_only']:
                            continue
                        field_type = param.pop('type')
                        if field_type == 'choice':
                            choices = tuple()
                            for choice in param['choices']:
                                choices = choices + ((choice['value'], choice['display_name']),)
                            param['choices'] = choices
                        self.fields.update(
                            {filed: fields_type[field_type if not field_type == 'field' else 'integer'](param)})
                        param.update({'type': field_type})
    return ProxySerializer
