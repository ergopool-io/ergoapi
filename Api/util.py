from Api.models import Block
from hashlib import blake2b
from codecs import decode


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
