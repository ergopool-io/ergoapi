import logging
import struct
import time
from codecs import decode
from urllib.parse import urljoin

import celery
import requests
from django.conf import settings
from ecpy.curves import Curve
from rest_framework.exceptions import ValidationError

from Api.utils.general import General, LazyConfiguration

NUMBER_OF_LOG = getattr(settings, "NUMBER_OF_LOG")
ACCOUNTING = getattr(settings, "ACCOUNTING_URL")
logger = logging.getLogger(__name__)


class ValidateShare(General, celery.Task):
    ignore_result = True

    # Number of elements in one solution
    K = 32
    # For convert m to 'flat map'
    M = b''
    # power of number of elements in a list
    n = 26
    # Total number of elements
    N = pow(2, n)
    # Create curve[Elliptic Curve Cryptography]
    # Cyclic group 'ec_generator' of prime order 'ec_order' with fixed generator 'ec_generator' and identity element
    # 'e.Secp256k1' elliptic curve
    # is used for this purpose
    curve = Curve.get_curve('secp256k1')
    ec_order = curve.order
    ec_generator = curve.generator
    # biggest number <= 2^256 that is divisible by q without remainder
    valid_range = int(pow(2, 256) / ec_order) * ec_order

    @property
    def base_factor(self):
        if not self._base_factor:
            if not self.POOL_BASE_FACTOR:
                self.POOL_BASE_FACTOR = LazyConfiguration().POOL_BASE_FACTOR

            self._base_factor = self.POOL_BASE_FACTOR
        return self._base_factor

    def __init__(self):
        self._base_factor = None
        self.POOL_BASE_FACTOR = None

    def run(self, pk, w, nonce, d, msg, tx_id, block, addresses, client_ip, pool_base_factor, *args, **kwargs):
        self.POOL_BASE_FACTOR = pool_base_factor
        self.validate(pk, w, nonce, d, msg, tx_id, block, addresses, client_ip)

    def __get_base(self, difficulty):
        """
        convert difficulty to base of network with division order of elliptic curve to difficulty
        :param difficulty: difficulty of network
        :return: base
        """
        return int(self.ec_order / difficulty)

    def __gen_indexes(self, seed):
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
            'status': 'invalid'
        })

    def __hash_in(self, array_byte):
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

    def __gen_element(self, m, pk, w, index_bytes):
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
        return self.__hash_in(index_bytes + self.M + pk + m + w)

    def __ec_point(self, array_byte):
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
                'status': 'invalid'
            })

    def __validate_difficulty(self, d, difficulty):
        """
        validate pool difficulty and base and d
        :param d:(int) distance between pseudo-random number, corresponding to nonce `n` and a secret,
                    corresponding to `pk`. The lower `d` is, the harder it was to find this solution.
        :param difficulty:(int) difficulty of network
        :return: if d<b return 1 else if b<d<pb return 2 else return 0
        """
        # Convert difficulty to base
        base = self.__get_base(difficulty)
        # Set POOL_DIFFICULTY
        pool_difficulty = base * self.base_factor
        # Compare difficulty and base and return
        return 1 if d < base else (2 if base < d < pool_difficulty else 0)

    def __validate_right_left(self, message, nonce, p1, p2, d):
        f = list()
        for i in self.__gen_indexes(message + nonce):
            check = self.__gen_element(message, p1, p2, struct.pack('>I', i))
            f.append(check)
        f = sum(f) % self.ec_order
        pk_ec_point = self.__ec_point(p1)
        w_ec_point = self.__ec_point(p2)
        left = w_ec_point['value'].mul(f)
        right = self.ec_generator.mul(d).add(pk_ec_point['value'])
        return 1 if left == right else 0

    def save_share(self, share):
        """
        Function for send share to Accounting service
        :param share: A json consist of miner, status, share, difficulty,
         tx_id, headers_height, block, addresses, client_ip
        :return: status request to accounting
        """
        try:
            url = urljoin(ACCOUNTING, "shares/")
            response = requests.post(url, json={
                        "miner": share.get("miner"),
                        "share": share.get("share"),
                        "status": share.get("status"),
                        "difficulty": share.get("difficulty"),
                        "transaction_id": share.get("transaction_id"),
                        "block_height": share.get("block").get('height'),
                        "parent_id": share.get("block").get('parent'),
                        "next_ids": share.get("block").get('next'),
                        "path": share.get("block").get("path"),
                        "miner_address": share.get("addresses").get("miner"),
                        "lock_address": share.get("addresses").get("lock"),
                        "withdraw_address": share.get("addresses").get("withdraw"),
                        "client_ip": share.get("client_ip")
                        })
            logger.debug(response)
            return {'status': 'ok'}
        except requests.exceptions.RequestException as e:
            response = {
                'status': 'error',
                'message': e
            }
            return response

    def validate(self, pk, w, n, d, msg, tx_id, block, addresses, client_ip):
        """
        Checks that `header` contains correct solution of the Autolykos PoW puzzle.
        :param pk: miner public key.
        :param w: one-time public key. Prevents revealing of miners secret
        :param n: nonce
        :param d: distance between pseudo-random number, corresponding to nonce `n` and a secret,
                corresponding to `pk`. The lower `d` is, the harder it was to find this solution.
        :param msg: Hash of meg_pre_image (header of block without pow)
        :param tx_id: Transaction Id
        :param block: consist parent_id and next_ids candidate block and path
        :param addresses: address miner
        :param client_ip: ip of client that send request
        :return:
        """
        # Create response for share
        share = {
            'miner': pk,
            'share': '',
            'status': '',
            'difficulty': int(),
            'client_ip': client_ip
        }
        try:
            # Generate uniq id for share
            share_id = self.blake((msg + n + pk + w).encode('utf-8'), 'hex')
            # Request to node for get difficulty
            data_node = self.node_request('info', {'accept': 'application/json'})
            difficulty = data_node.get('response').get('difficulty')
            share['difficulty'] = int(difficulty / self.base_factor)
            share['share'] = share_id
            # Convert to array bytes
            try:
                nonce = decode(n, "hex")
                p1 = decode(pk, "hex")
                p2 = decode(w, "hex")
                message = decode(msg, "hex")
            except ValueError as e:
                logger.error("Share input parameters aren't valid.")
                logger.error(e)
                raise ValidationError({'status': 'invalid'})
            # Validate solved or valid or invalid (d > pool difficulty)
            logger.info('Validating difficulty for share with pk {}.'.format(pk))
            flag = self.__validate_difficulty(d, difficulty)
            logger.info('Difficulty validation result for share with pk {}.'.format(pk))
            # validate_right_left
            validation = self.__validate_right_left(message, nonce, p1, p2, d)
            # ValidateBlock
            if validation == 1 and flag == 1:
                share['status'] = "solved"
            elif validation == 1 and flag == 2:
                share['status'] = 'valid'
            else:
                share['status'] = 'invalid'
            logger.info('Share status with pk {}: {}'.format(pk, share['status']))
            if share['status'] == 'solved':
                share.update({
                    'transaction_id': tx_id,
                    'block': block,
                    'addresses': addresses
                })
            elif share['status'] == 'valid':
                block.pop('height', None)
                share.update({
                    'block': block,
                    'addresses': addresses
                              })
        except ValidationError as e:
            share['status'] = e.args[0]['status']

        # Set flag_logger for number of critical alarm limit according NUMBER_OF_LOG in while true
        flag_logger = 1
        while True:
            response = self.save_share(share)
            if response['status'] == 'ok':
                break
            else:
                if not flag_logger % NUMBER_OF_LOG:
                    logger.critical("Can not send request to Accounting service")
                    logger.critical(response['message'])
                    flag_logger += 1
                time.sleep(1)
