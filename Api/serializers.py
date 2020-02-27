import logging
from codecs import decode, encode
from urllib.parse import urljoin

import requests
from django.utils.deconstruct import deconstructible
from rest_framework import serializers, status
from rest_framework.exceptions import ValidationError

from Api.utils.general import General, LazyConfiguration
from Api.utils.header import Reader, HeaderSerializer, HeaderWithoutPow, Writer
from ErgoApi.settings import API_KEY, ERGO_EXPLORER_ADDRESS, VERIFIER_ADDRESS

logger = logging.getLogger(__name__)


@deconstructible
class HexValidator:

    def __call__(self, value):
        """
        Validate that the input contains (or does *not* contain, if
        inverse_match is True) a match for the regular expression.
        """
        try:
            decode(value, "hex")
            return
        except ValueError as e:
            logger.error("input parameters are not valid.")
            logger.error(e)
            raise ValidationError('Type of input is invalid')


class ConfigurationValueSerializer(serializers.Serializer):
    reward = serializers.IntegerField()
    wallet_address = serializers.CharField()
    pool_difficulty_factor = serializers.FloatField()

    def __init__(self, *args, **kwargs):
        super().__init__(args, kwargs)

        request = self.context.get('request')
        self.configs = LazyConfiguration()
        if request is not None and request.configs is not None:
            self.configs = request.configs

    class Meta:
        fields = ['reward', 'wallet_address', 'pool_difficulty_factor']

    def update(self, instance, validated_data):
        pass

    def create(self, validated_data):
        pass


class ValidateProofSerializer(serializers.Serializer):
    msg_pre_image = serializers.CharField(validators=[HexValidator()])
    leaf = serializers.CharField(validators=[HexValidator()])
    levels = serializers.ListField(child=serializers.CharField(validators=[HexValidator()]))
    msg = serializers.CharField(required=False, read_only=True)
    message = serializers.CharField(required=False, read_only=True)
    status = serializers.CharField(required=False, read_only=True)

    def __init__(self, *args, **kwargs):
        super().__init__(args, kwargs)

        request = self.context.get('request')
        self.configs = LazyConfiguration()
        if request is not None and request.configs is not None:
            self.configs = request.configs

    def __merkle_proof(self, leaf, levels_encoded):
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
        :param leaf: tx_id
        :param levels_encoded: list of levels
        :return:
        """
        # tx_id is a "leaf" in a Merkle proof
        tx_id = leaf
        # Merkle proof element is encoded in the following way:
        # - first, 1 byte showing whether COMPUTED value is on the right (1) or on the left (0)
        # - second, 32 bytes of stored value
        levels = list(map(lambda le: [decode(le, "hex")[1:], decode(le, "hex")[0]], levels_encoded))
        leaf_hash = General.blake(b'\x00' + decode(tx_id, "hex"))
        for level in levels:
            if level[1] == 1:
                leaf_hash = General.blake(b'\x01' + level[0] + leaf_hash)
            elif level[1] == 0:
                leaf_hash = General.blake(b'\x01' + leaf_hash + level[0])
        return leaf_hash

    def __generate_path(self, header, height):
        """
        generate path from last header - THRESHOLD_HEIGHT to the height of header that works on that
        # TODO: Complete send request to accounting
        :param header: header of block (msg_pre_image)
        :param height:
        :return:
        """
        block_chain = General.node_request('/blocks/chainSlice?fromHeight=%s&toHeight=%s' %
                                           (str(height - self.configs.THRESHOLD_HEIGHT), str(height)),
                                           {'accept': 'application/json'})
        parent_id = header.parentId.hex()
        path = list()
        for block in block_chain.get('response'):
            path.append(block['height'])
            if block['id'] == parent_id:
                return str(len(path))

        # request to Ergo Explorer for get fork block_chain if not exist in main block chain
        try:
            path_second = list()
            url = urljoin(ERGO_EXPLORER_ADDRESS, 'stats/forks')
            query = {'fromHeight': height - self.configs.THRESHOLD_HEIGHT}
            response = requests.get(url, query)
            block_chain = response.json()
            for fork in block_chain.get('forks')[::-1]:
                for number, member in enumerate(fork['members']):
                    if parent_id == member[1]:
                        path_second.append(fork['members'][:number + 1])
                        number_chain = path.index(fork.get('branchPointHeight'))
                        return ','.join(str(number_chain + 1) + str(number + 1) + str(len(path_second)))
            return '-1'
        except ValidationError as e:
            logger.error("Can not resolve response from Ergo Explorer")
            logger.error(e)
            raise ValidationError("Can not resolve response from Ergo Explorer")

    def validate(self, attrs):
        """
        Validate timestamp and height and difficulty
        :return: status of merkle_proof
        """

        leaf = attrs['leaf']
        levels_encoded = attrs['levels']
        msg_pre_image_base_16 = attrs['msg_pre_image']

        msg_pre_image = decode(msg_pre_image_base_16, 'hex')
        # hash of "msg_pre_image" (which is a header without PoW) should be equal to "msg"
        msg = General.blake(msg_pre_image, 'hex')
        # Transactions Merkle tree digest is in bytes 65-96 (inclusive) of the unproven header
        txs_root = msg_pre_image[65:97]
        # Create Merkle Proof
        leaf_hash = self.__merkle_proof(leaf, levels_encoded)
        # Get information node (header, difficulty)
        data_node = General.node_request('info', {'accept': 'application/json'})
        height = data_node.get('response').get('headersHeight')
        difficulty = data_node.get('response').get('difficulty')
        # Get information last block
        last_header = General.node_request('/blocks/lastHeaders/1', {'accept': 'application/json'})
        # parse header with msg_pre_image
        reader = Reader(msg_pre_image)
        header = HeaderSerializer.parse_without_pow(reader)

        # Validate timestamp after that validate height and after that validate difficulty and after that generate path
        # from last header - THRESHOLD_HEIGHT to the height of header that works on that.
        if header.timestamp < last_header.get('response')[0].get(
                'timestamp') - self.configs.THRESHOLD_TIMESTAMP:
            logger.info('Proof is invalid (timestamp) for transaction id {}'.format(leaf))
            raise ValidationError({'message': 'The proof is invalid.', 'status': 'invalid'})
        if header.height <= height - self.configs.THRESHOLD_HEIGHT:
            logger.info('Proof is invalid (height) for transaction id {}'.format(leaf))
            raise ValidationError({'message': 'The proof is invalid.', 'status': 'invalid'})
        if header.decode_nbits < max(int(last_header.get('response')[0].get('difficulty')), int(difficulty)):
            logger.info('Proof is invalid (difficulty) for transaction id {}'.format(leaf))
            raise ValidationError({'message': 'The proof is invalid.', 'status': 'invalid'})
        # Generate path
        path = self.__generate_path(header, height)

        # Validate_merkle
        if not leaf_hash == txs_root:
            logger.info('Proof is invalid for transaction id {}'.format(leaf))
            raise ValidationError({'message': 'The proof is invalid.', 'status': 'invalid'})

        # Set parent and next block of candidate block
        block_next = General.node_request('/blocks/at/{}'.format(str(header.height)), {'accept': 'application/json'})
        block = {
            'height': header.height,
            'parent': header.parentId.hex(),
            'next': block_next.get('response'),
            'path': path
        }

        logger.info('Proof is valid for transaction id {}'.format(leaf))
        attrs.update({'msg': msg, 'block': block, 'message': 'The proof is valid.', 'status': 'valid'})
        return attrs

    def update(self, instance, validated_data):
        pass

    def create(self, validated_data):
        pass

    class Meta:
        fields = ['pk', 'msg_pre_image', 'leaf', 'levels', 'message', 'status']


class ValidationShareSerializer(serializers.Serializer, General):
    w = serializers.CharField(validators=[HexValidator()])
    nonce = serializers.CharField()
    d = serializers.CharField()

    def __init__(self, *args, **kwargs):
        super().__init__(args, kwargs)

        request = self.context.get('request')
        self.configs = LazyConfiguration()
        if request is not None and request.configs is not None:
            self.configs = request.configs

    def validate_d(self, value):
        try:
            return int(value)
        except ValueError as e:
            logger.error("Share input d is not valid.")
            logger.error(e)
            raise ValidationError("invalid number entered")

    def update(self, instance, validated_data):
        pass

    def create(self, validated_data):
        pass

    class Meta:
        fields = ['pk', 'w', 'nonce', 'd']


class AddressesSerializer(serializers.Serializer):
    miner = serializers.CharField()
    lock = serializers.CharField()
    withdraw = serializers.CharField()

    def __init__(self, *args, **kwargs):
        super().__init__(args, kwargs)

        request = self.context.get('request')
        self.configs = LazyConfiguration()
        if request is not None and request.configs is not None:
            self.configs = request.configs

    def update(self, instance, validated_data):
        pass

    def create(self, validated_data):
        pass

    class Meta:
        fields = ['miner', 'lock', 'withdraw']


class ValidationSerializer(serializers.Serializer):
    pk = serializers.CharField(validators=[HexValidator()])
    addresses = AddressesSerializer(many=False)
    transaction = serializers.JSONField()
    proof = ValidateProofSerializer(many=False)
    shares = ValidationShareSerializer(many=True)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        request = self.context.get('request')
        self.configs = LazyConfiguration()
        if request is not None and request.configs is not None:
            self.configs = request.configs

    def __validate_transaction_node(self, attrs):
        transaction = attrs['transaction']
        pk = attrs['pk']
        msg_pre_image = attrs['proof']['msg_pre_image']

        # Send request to node for validate transaction
        tx_id = None
        data_node = General.node_request('transactions/check', data=transaction, request_type="post")
        node_ok = False
        if data_node['status'] == 'success':
            node_ok = True
            tx_id = data_node['response']

        transaction_ok = False
        check_block = False
        if data_node['status'] == 'External Error':
            node_result = data_node['response']
            required_msg_custom = 'Scripts of all transaction inputs should pass verification'
            required_msg_mined = 'Every input of the transaction should be in UTXO'
            if 'detail' in node_result and required_msg_custom in node_result['detail']:
                miner_pk = attrs['addresses']['miner']
                # there is a chance that custom verifier verifies this transaction
                res = requests.post(urljoin(VERIFIER_ADDRESS, 'verify'), json={'minerPk': miner_pk,
                                                                               'transaction': transaction})
                if res.status_code == status.HTTP_200_OK:
                    result = res.json()
                    check_block = result['verified'] is None
                    if result['success'] and result['verified']:
                        # has been verified with custom context
                        logger.info('provided transaction was verified with custom verifier')
                        transaction_ok = True

            if (not transaction_ok) and (('detail' in node_result and required_msg_mined in node_result['detail'])
                                         or check_block):
                reader = Reader(decode(msg_pre_image, 'hex'))
                header = HeaderSerializer.parse_without_pow(reader)

                height = str(header.height)
                params = {'fromHeight': height, 'toHeight': height}
                data_node = General.node_request('blocks/chainSlice', params=params)

                logger.info('chain slice returned {}'.format(data_node))

                if data_node['status'] == 'success' and len(data_node['response']) == 1:
                    header = data_node['response'][0]
                    header['extensionRoot'] = header['extensionHash']
                    header = HeaderWithoutPow.create_from_json(header)
                    writer = Writer()
                    HeaderSerializer.serialize_without_pow(header, writer)
                    msg = encode(writer.get_bytes(), 'hex').decode('utf-8')

                    if msg != msg_pre_image:
                        logger.warning('solved share was not confirmed as a valid one, msg_pre_image does not match!')
                        raise ValidationError({"message": 'Invalid solved share!'})

                    logger.info('solved share accepted even though its input boxes was not ok!')
                    transaction_ok = True

        if not node_ok and not transaction_ok:
            logger.error('Node failed to validate transaction')
            raise ValidationError({"message": data_node['response']})

        if transaction_ok:
            res = requests.get(urljoin(VERIFIER_ADDRESS, 'get_id'), json=transaction)
            if res.status_code == status.HTTP_200_OK:
                result = res.json()
                tx_id = result['id']

        return tx_id

    def __value_of_transaction(self, wallet_address, transaction):
        value = 0
        if 'outputs' in transaction:
            for output in transaction['outputs']:
                # Send request to node for Generate Ergo address from hex-encoded ErgoTree
                data_node = General.node_request('utils/ergoTreeToAddress/' + output['ergoTree'],
                                                 {'accept': 'application/json'})
                if data_node['status'] == 'External Error':
                    raise ValidationError({
                        "message": data_node['response'],
                        "status": "failed"
                    })
                # Check address after convert ergo tree that would have existed in the wallet_address
                elif data_node.get('response')['address'] in wallet_address:
                    value = value + output['value']
        return value

    def __validate_transaction(self, attrs):
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

        # Send request to node for validate transaction
        tx_id = self.__validate_transaction_node(attrs)
        response['tx_id'] = tx_id

        logger.info("Getting wallet addresses to validate transaction.")
        # Send request to node for get list of wallet addresses
        data_node = General.node_request('wallet/addresses',
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
            # Calculate value of payed in transaction
            value = self.__value_of_transaction(wallet_address, transaction)
            # Sum value of output field should be bigger than reward policy pool.
            REWARD_FACTOR = self.configs.REWARD_FACTOR
            PRECISION = self.configs.REWARD_FACTOR_PRECISION
            TOTAL_REWARD = round((self.configs.TOTAL_REWARD / 1e9) * REWARD_FACTOR, PRECISION)
            TOTAL_REWARD = int(TOTAL_REWARD * 1e9)

            if value >= TOTAL_REWARD:
                logger.info('Transaction is valid.')
                response['status'] = 'valid'
                response['message'] = "Transaction is valid"
            else:
                logger.error('Transaction is invalid, either wallet address is invalid or the value')
                raise ValidationError({
                    "message": "Wallet address pool or value of transaction is invalid",
                    "status": "invalid"
                })
        attrs.update(response)
        return attrs

    def __validate_miner_address(self, attr):
        pk = attr['pk']
        miner_address = attr['addresses']['miner']
        res = requests.get(urljoin(VERIFIER_ADDRESS, 'address_to_pk'), json=miner_address)
        if res.status_code != 200:
            raise ValidationError({
                "message": "Could not verify miner address integrity with miner pk!",
                "status": "invalid"
            })

        expected_pk = res.json()['id'].lower()
        if pk.lower() != expected_pk:
            raise ValidationError({
                "message": "Could not verify miner address integrity with miner pk!",
                "status": "invalid"
            })

    def validate(self, attrs):
        self.__validate_miner_address(attrs)
        self.__validate_transaction(attrs)
        leaf = attrs['proof']['leaf']
        tx_id = attrs['tx_id']
        if leaf == tx_id:
            return attrs
        else:
            logger.error("leaf not equal with tx_id")
            raise ValidationError({"message": "leaf not equal with tx_id"})

    def create(self, validated_data):
        pass

    def update(self, instance, validated_data):
        pass

    class Meta:
        fields = ['pk', 'addresses', 'transaction', 'proof', 'shares']
