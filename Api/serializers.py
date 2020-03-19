import logging
from codecs import decode, encode
from urllib.parse import urljoin

import requests
from django.conf import settings
from django.utils.deconstruct import deconstructible
from rest_framework import serializers, status
from rest_framework.exceptions import ValidationError

from Api.utils.general import General, LazyConfiguration
from Api.utils.header import Reader, HeaderSerializer, HeaderWithoutPow, Writer
from ErgoApi.settings import API_KEY, ERGO_EXPLORER_ADDRESS, VERIFIER_ADDRESS

logger = logging.getLogger(__name__)

WALLET_ADDRESS = getattr(settings, "WALLET_ADDRESS")
WALLET_ADDRESS_TREE = getattr(settings, "WALLET_ADDRESS_TREE")


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

    def generate_path(self, parent_id, height):
        """
        generate path of the provided share's block
        :param parent_id: parent_id of the block in hex
        :return: three comma-separated numbers, (#block to go ahead in main chain, nth fork, '#blocks to go ahead in that chain)
        """
        try:
            block_chain = General.node_request('/blocks/chainSlice?fromHeight=%s&toHeight=%s' %
                                               (str(height - self.configs.THRESHOLD_HEIGHT), str(height)),
                                               {'accept': 'application/json'})
            for i, block in enumerate(block_chain.get('response')):
                if block['id'] == parent_id:
                    return str(i + 1)

            # request to Ergo Explorer for get fork block_chain if not exist in main block chain
            url = urljoin(ERGO_EXPLORER_ADDRESS, 'stats/forks')
            query = {'fromHeight': height - self.configs.THRESHOLD_HEIGHT}
            response = requests.get(url, query)
            block_chain = response.json()
            for fork in block_chain.get('forks')[::-1]:
                for number, member in enumerate(fork['members']):
                    if parent_id == member[1]:
                        forks = General.node_request('/blocks/at/{}'.format(fork['branchPointHeight']),
                                                     {'accept': 'application/json'})
                        if forks['status'] != 'success':
                            break

                        forks = forks['response']
                        ind = forks.index(parent_id)
                        return ','.join(str(10 - (height - fork.get('branchPointHeight')))
                                        + str(ind + 1) + str(number + 1))
            return '-1'
        except ValidationError as e:
            logger.error("Can not resolve response from Ergo Explorer")
            return '-1'

    def validate(self, attrs):
        """
        Validate timestamp and height and difficulty
        :return: status of merkle_proof
        """
        logger.info('validating proof.')
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
            logger.debug('Proof is invalid (timestamp) for transaction id {}'.format(leaf))
            raise ValidationError({'message': 'The proof is invalid.', 'status': 'invalid'})
        if header.height <= height - self.configs.THRESHOLD_HEIGHT:
            logger.debug('Proof is invalid (height) for transaction id {}'.format(leaf))
            raise ValidationError({'message': 'The proof is invalid.', 'status': 'invalid'})
        if header.decode_nbits < max(int(last_header.get('response')[0].get('difficulty')), int(difficulty)):
            logger.debug('Proof is invalid (difficulty) for transaction id {}'.format(leaf))
            raise ValidationError({'message': 'The proof is invalid.', 'status': 'invalid'})
        # Generate path
        path = self.generate_path(header.parentId.hex(), height)

        # Validate_merkle
        if not leaf_hash == txs_root:
            logger.debug('Proof is invalid for transaction id {}'.format(leaf))
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
        msg_pre_image = attrs['proof']['msg_pre_image']

        # Send request to node for validate transaction
        tx_id = None
        data_node = General.node_request('transactions/check', data=transaction, request_type="post")
        node_ok = False
        if data_node['status'] == 'success':
            logger.info('tx was validated by node, response: {}.'.format(data_node['response']))
            node_ok = True
            tx_id = data_node['response']

        transaction_ok = False
        check_block = False
        if data_node['status'] == 'External Error':
            logger.info('tx was not verified with node.')
            node_result = data_node['response']
            required_msg_custom = 'Scripts of all transaction inputs should pass verification'
            required_msg_mined = 'Every input of the transaction should be in UTXO'
            if 'detail' in node_result and required_msg_custom in node_result['detail']:
                logger.info('trying custom verifier to verify tx.')
                miner_address = attrs['addresses']['miner']
                res = requests.post(urljoin(VERIFIER_ADDRESS, 'verify'), json={'minerPk': miner_address,
                                                                               'transaction': transaction})
                if res.status_code == status.HTTP_200_OK:
                    result = res.json()
                    check_block = result['verified'] is None
                    if result['success'] and result['verified']:
                        # has been verified with custom context
                        logger.info('provided transaction was verified with custom verifier')
                        transaction_ok = True

                    else:
                        logger.info('tx was not verified with custom verifier, {}'.format(result))

                else:
                    logger.error('verifier returned non 200 response: {}, {}'.format(res, res.content))

            if (not transaction_ok) and (('detail' in node_result and required_msg_mined in node_result['detail'])
                                         or check_block):
                logger.info('tx inputs are spent! checking if blocked is already mined.')
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

                else:
                    logger.debug('got an non 200 response when getting slice, {}'.format(data_node))

        if not node_ok and not transaction_ok:
            logger.debug('Could not verify tx with any of our ways, rejecting it.')
            raise ValidationError({"message": data_node['response']})

        if transaction_ok:
            res = requests.get(urljoin(VERIFIER_ADDRESS, 'get_id'), json=transaction)
            if res.status_code == status.HTTP_200_OK:
                result = res.json()
                tx_id = result['id']

        return tx_id

    def __value_of_transaction(self, transaction):
        ergo_tree = WALLET_ADDRESS_TREE
        if ergo_tree is None:
            logger.debug('ergo tree is not set in production!')
            logger.info("getting wallet addresses from node to validate transaction.")
            data_node = None
            try:
                # Send request to node for get list of wallet addresses
                data_node = General.node_request('wallet/addresses',
                                                 {'accept': 'application/json', 'content-type': 'application/json',
                                                  'api_key': API_KEY})
                wallet_address = data_node.get('response')[0]
                data_node = General.node_request('script/addressToTree/' + wallet_address,
                                                 {'accept': 'application/json'})
                ergo_tree = data_node['response']['tree']

            except Exception as e:
                logger.error('error while getting wallet addresses, {}. exception: {}.'.format(data_node, e))
                raise ValidationError({
                    "message": 'exception while getting wallet addresses from node.',
                    "status": "failed"
                })

        if ergo_tree is None:
            logger.critical('could not get ergo tree')
            raise ValidationError({
                "message": 'could not verify transaction because could not get ergo tree.',
                "status": "failed"
            })

        value = 0
        if 'outputs' in transaction:
            for output in transaction['outputs']:
                if output['ergoTree'] == ergo_tree:
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

        # Calculate value of payed in transaction
        value = self.__value_of_transaction(transaction)
        # Sum value of output field should be bigger than reward policy pool.
        REWARD_FACTOR = self.configs.REWARD_FACTOR
        PRECISION = self.configs.REWARD_FACTOR_PRECISION
        TOTAL_REWARD = round((self.configs.TOTAL_REWARD / 1e9) * REWARD_FACTOR, PRECISION)
        TOTAL_REWARD = int(TOTAL_REWARD * 1e9)

        logger.info('needed erg to validate tx is {}, got {}'.format(TOTAL_REWARD, value))
        if value >= TOTAL_REWARD:
            logger.info('value of tx is ok.')
            response['status'] = 'valid'
            response['message'] = "Transaction is valid"
        else:
            logger.error('value of tx is not valid, rejecting.')
            raise ValidationError({
                "message": "invalid output pool addresses or invalid amount.",
                "status": "invalid"
            })
        attrs.update(response)
        return attrs

    def __validate_miner_address(self, attr):
        pk = attr['pk']
        miner_address = attr['addresses']['miner']
        res = requests.get(urljoin(VERIFIER_ADDRESS, 'address_to_pk'), json=miner_address)
        if res.status_code != 200:
            logger.error('got and non 200 response while getting pk out of address, {}, {}'.format(res, res.content))
            raise ValidationError({
                "message": "could not verify miner address integrity with miner pk!",
                "status": "invalid"
            })

        expected_pk = res.json()['id'].lower()
        if pk.lower() != expected_pk:
            logger.debug('miner address does not match miner pk')
            raise ValidationError({
                "message": "the provided miner address does not match with miner pk.",
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
            logger.debug("leaf does not equal with tx_id")
            raise ValidationError({"message": "leaf does not equal with tx_id", "status": "invalid"})

    def create(self, validated_data):
        pass

    def update(self, instance, validated_data):
        pass

    class Meta:
        fields = ['pk', 'addresses', 'transaction', 'proof', 'shares']


class SupportSerializer(serializers.Serializer):
    recaptcha_code = serializers.CharField(label="recaptcha code")
    name = serializers.CharField(required=False)
    email = serializers.EmailField()
    subject = serializers.CharField(required=False)
    message = serializers.CharField()

    def validate_recaptcha_code(self, value):
        if not General.verify_recaptcha(value):
            raise ValidationError("please verify recaptcha code")
