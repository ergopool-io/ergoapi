from ErgoApi.settings import POOL_DIFFICULTY, NODE_ADDRESS, API_KEY
from Api.models import Block
import Api.constant as constant
from codecs import decode
from hashlib import blake2b
import requests
import struct
import logging


def blake(data, kind='byte'):
    """
    Function for get hash from a string
    :param data: string
    :param kind: string hex or type
    :return: byte array or hex
    """
    return blake2b(data, digest_size=32).hexdigest() if kind == "hex" else blake2b(data, digest_size=32).digest()


def validation_proof(pk, msg_pre_image_base16, leaf, levels_encoded):
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

    :param pk:
    :param msg_pre_image_base16:
    :param leaf:
    :param levels_encoded:
    :return:
    """
    try:
        # Get information miner(ex: Transaction Id) from database
        block = Block.objects.get(public_key=pk)

        if not block.tx_id == leaf:
            return {
                'public_key': pk,
                'message': 'The leaf is invalid.',
                'status': 'failed'
            }
    except Block.DoesNotExist:
        return {
                'public_key': pk,
                'message': 'Transaction not generated.',
                'status': 'failed'
            }

    msg_pre_image = decode(msg_pre_image_base16, "hex")
    # hash of "msg_pre_image" (which is a header without PoW) should be equal to "msg"
    msg = blake(msg_pre_image, 'hex')
    # Transactions Merkle tree digest is in bytes 65-96 (inclusive) of the unproven header
    txs_root = msg_pre_image[65:97]
    # tx_id is a "leaf" in a Merkle proof
    tx_id = leaf

    # Merkle proof element is encoded in the following way:
    # - first, 1 byte showing whether COMPUTED value is on the right (1) or on the left (0)
    # - second, 32 bytes of stored value
    levels = list(map(lambda le: [decode(le, "hex")[1:], decode(le, "hex")[0:1]], levels_encoded))
    leaf_hash = blake(decode('00', "hex") + decode(tx_id, "hex"))
    for level in levels:
        if level[1] == decode('01', "hex"):
            leaf_hash = blake(decode('01', "hex") + level[0] + leaf_hash)
        elif level[1] == decode('00', "hex"):
            leaf_hash = blake(decode('01', "hex") + leaf_hash + level[0])
    if leaf_hash == txs_root:
        # if proof is valid create or update block(public key and message) in database
        obj, created = Block.objects.get_or_create(public_key=pk)
        obj.msg = msg
        obj.save()
        return {
                'public_key': pk,
                'message': 'The proof is valid.',
                'status': 'success'
        }
    else:
        return {
                'public_key': pk,
                'message': 'The proof is invalid.',
                'status': 'failed'
        }


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
        response.update({'status': 'success'})
        return response
    except requests.exceptions.RequestException as e:
        logging.error(e)
        logging.error("Can not resolve response from node")
        response = {'public_key': "Can not resolve", 'share': "Can not resolve", 'status': 'External Error'}
        return response

# https://github.com/ergoplatform/ergo/blob/master/papers/yellow/pow/ErgoPow.tex
# For develop functions validation_block, gen_element, gen_indexes, hash_in I use from reference overhead


def gen_indexes(seed):
    """
    Algorithm 4
    function that takes `m` and `nonceBytes` and returns a list of size `k` with numbers in [0,`N`)
    :param seed:(Array Of Bytes)
    :return: Sequence of int
    """
    hash_seed = blake(seed)

    extended_hash = hash_seed + hash_seed[:3]
    result = list(map(lambda i: struct.unpack('>I', extended_hash[i:i + 4])[0] % constant.N, range(0, constant.K)))
    if len(result) == constant.K:
        return list(result)
    logging.error("gen_indexes : The length of map not equal K")
    return False


def hash_in(array_byte):
    """
    Algorithm 3
    One way cryptographic hash function that produces numbers in [0,q) range.
    It calculates blake2b256 hash of a provided input and checks whether the result is
    in range from 0 to a maximum number divisible by q without remainder.
    If yes, it returns the result mod q, otherwise make one more iteration using hash as an input.
    This is done to ensure uniform distribution of the resulting numbers.

    :param array_byte:(Array Of Bytes)
    :return: (int) Go to overhead description
    """
    while True:
        hashed = blake(array_byte)
        bi = int.from_bytes(hashed, byteorder="big")
        if bi < constant.VALID_RANGE:
            x = bi % constant.Q
            return x
        array_byte = hashed


def gen_element(m, pk, w, index_bytes):
    """
    Generate element of Autolykos equation.

    :param m:(Array Of Bytes)
    :param pk:(Array Of Bytes)
    :param w:(Array Of Bytes)
    :param index_bytes:(Array Of Bytes)
    :return: (int)
    """
    return hash_in(index_bytes + constant.M + pk + m + w)


def ec_point(array_byte):
    """
    The function decode_point from package ecpy.curves has bug, the size of the value that has been set in this
    function is 34 but must be 33. To solve this problem, check first byte of array byte input
    and according to this situation add byte 0 or 1 at the end of array byte input.

    :param array_byte: w or p
    :return: cast array byte to Ec-Point type
    """
    if array_byte[0] == 2:
        return {'value': constant.CURVE.decode_point(array_byte + decode('00', 'hex')),
                'status': 'success'}
    elif array_byte[0] == 3:
        array_byte = b'\x02' + array_byte[1:]
        return {'value': constant.CURVE.decode_point(array_byte + decode('01', 'hex')),
                'status': 'success'}
    else:
        logging.error("First bytes of w_bytes is invalid.")
        return {'value': 'mistake',
                'status': 'invalid'}


def validation_block(pk, w, n, d):
    """
    Algorithm 2
    Checks that `header` contains correct solution of the Autolykos PoW puzzle.

    :param pk: miner public key. Should be used to collect block rewards
    :param w: one-time public key. Prevents revealing of miners secret
    :param n:(string) nonce
    :param d:(int) distance between pseudo-random number, corresponding to nonce `n` and a secret,
                corresponding to `pk`. The lower `d` is, the harder it was to find this solution.
    :return: (uniq id share and status share)
    """
    # Convert to array bytes
    nonce = decode(n, "hex")
    p1 = decode(pk, "hex")
    p2 = decode(w, "hex")
    try:
        # Get information share(ex: Message(hash of header block), Transaction Id) from database
        block = Block.objects.get(public_key=pk)
        # Convert to array bytes
        message = decode(block.msg, "hex")
        # Transaction Id
        tx_id = block.tx_id
        # Generate uniq id for share
        share_id = blake(message + nonce + p1 + p2, 'hex')
    except Block.DoesNotExist:
        return {
            'public_key': pk,
            # Generate uniq id for share
            'share': blake(nonce + p1 + p2, 'hex'),
            'status': "invalid"
        }

    # Create response for share
    response = {
        'public_key': pk,
        'share': share_id,
        'status': ''
    }

    # Send request to node for get base of network
    data_node = node_request('mining/candidate', {'accept': 'application/json', 'api_key': API_KEY})
    if data_node['status'] == 'External Error':
        return data_node
    else:
        base = data_node.get('b')

    # Compare difficulty and base
    flag = 1 if d < base else (2 if base < d < POOL_DIFFICULTY else 0)

    # For checked get response from 'Node'
    f = list()
    for i in gen_indexes(message + nonce):
        if not i:
            return {'public_key': pk, 'share': "Can not resolve", 'status': 'External Error'}
        else:
            check = gen_element(message, p1, p2, struct.pack('>I', i))
            if not check:
                return {'public_key': pk, 'share': "Can not resolve", 'status': 'External Error'}
            else:
                f.append(check)

    f = sum(f) % constant.Q
    pk_ec_point = ec_point(p1)
    w_ec_point = ec_point(p2)
    if w_ec_point['status'] == 'invalid' or pk_ec_point['status'] == 'invalid':
        return {'public_key': pk, 'share': share_id, 'status': 'invalid'}

    left = w_ec_point['value'].mul(f)
    right = constant.G.mul(d).add(pk_ec_point['value'])

    data_node = node_request('info', {'accept': 'application/json'})
    if data_node['status'] == 'External Error':
        return data_node
    else:
        height = data_node.get('headersHeight')
    # ValidateBlock
    response['status'] = 'solved' if left == right and flag == 1 else \
        ('valid' if left == right and flag == 2 else 'invalid')
    if response['status'] == 'solved':
        response.update({'headersHeight': height})
        response.update({'tx_id': tx_id})

    return response
