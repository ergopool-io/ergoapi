from codecs import decode


class HeaderWithoutPow:
    """
    :param version 1 byte
    :param parent_id 32 bytes
    :param ad_proofs_root 32 bytes
    :param transactions_root 32 bytes
    :param state_root 33 bytes
    :param timestamp
    :param extension_root 32 bytes
    :param n_bits
    :param height
    :param votes: 3 bytes
    """

    def __init__(self, version, parent_id, ad_proofs_root, transactions_root, state_root, timestamp, extension_root,
                 n_bits, height, votes):
        self.version = version
        self.parentId = parent_id
        self.ADProofsRoot = ad_proofs_root
        self.transactionsRoot = transactions_root
        self.stateRoot = state_root
        self.timestamp = timestamp
        self.extensionRoot = extension_root
        self.nBits = n_bits
        self.height = height
        self.votes = votes

    @property
    def decode_nbits(self):
        """
        The "compact" format is a representation of a whole number N using an unsigned 32 bit number similar to a
        floating point format. The most significant 8 bits are the unsigned exponent of base 256. This exponent can
        be thought of as "number of bytes of N". The lower 23 bits are the mantissa. Bit number 24 (0x800000) represents
        the sign of N. Therefore, N = (-1^sign) * mantissa * 256^(exponent-3)

        MPI encoded numbers are produced by the OpenSSL BN_bn2mpi function. They consist of
        a 4 byte big endian length field, followed by the stated number of bytes representing
        the number in big endian format (with a sign bit).

        :return: difficulty (int)
        """
        size = int(self.nBits >> 24) & 0xFF
        bytes_ = [b'\x00'] * (size + 4)
        bytes_[3] = size.to_bytes(1, 'little')
        if size >= 1:
            bytes_[4] = ((self.nBits >> 16) & 0xFF).to_bytes(1, 'little')
        if size >= 2:
            bytes_[5] = ((self.nBits >> 8) & 0xFF).to_bytes(1, 'little')
        if size >= 3:
            bytes_[6] = (self.nBits & 0xFF).to_bytes(1, 'little')

        # MPI encoded numbers for in this implement have length So implemented it accordingly
        bytes_arr = b''.join(bytes_[:4])
        length = int.from_bytes(bytes_arr, 'big')
        buf = [b'\x00'] * length
        buf[:3] = bytes_[4:]
        if not len(buf):
            return 0
        else:
            is_negative = (buf[0][0] & 0x80) == 0x80
            if is_negative:
                buf[0] = (buf[0][0] & 0x7f).to_bytes(1, 'little')
            result = int.from_bytes(b''.join(buf), 'big')
            return (result * -1) if is_negative else result


class Writer:
    """
    Write data to a byte array
    """
    def __init__(self):
        self.list_writer = list()

    def put_byte(self, x):
        """
        Encode signed byte
        :param x: byte value to encode
        """
        self.list_writer.append(x.to_bytes(1, 'little'))

    def put_bytes(self, x):
        """
        Encode an array of bytes
        :param x: value to encode
        """
        self.list_writer.append(x)

    def put_int(self, x: int):
        """
        Encode signed int value using VLQ.
        Both negative and positive values are supported, but only positive values are encoded
        efficiently, negative values are taking a toll and use six bytes.
        [[https://en.wikipedia.org/wiki/Variable-length_quantity
        :param x: prefer unsigned int
        """
        if x == 0:
            self.list_writer.append(b'\x00')
        bytes_ = list()
        while x > 0:
            value_bits = x & 127
            bytes_.append((0b1 << 7) | value_bits)
            x >>= 7
        bytes_[-1] &= 127
        for y in bytes_:
            self.list_writer.append(y.to_bytes(1, 'big'))

    def put_big_indian(self, x: int):
        """
        Encode int to bytes with size 4 and format big endian
        :param x: int
        """
        self.list_writer.append(x.to_bytes(4, 'big'))

    def get_bytes(self):
        """
        get bytes encoded data
        :return: bytes
        """
        return b''.join(self.list_writer)


class Reader:
    """
    Read data from bytes
    """
    def __init__(self, data):
        """
        get data (bytes) and assign to a list
        :param data: bytes
        """
        self.list_reader = list()
        for x in data:
            self.list_reader.append(x.to_bytes(1, 'little'))

    def get_byte(self):
        """
        Decode signed byte
        :return: Byte
        """
        return self.list_reader.pop(0)

    def get_bytes(self, size):
        """
        Decode array of byte values
        :param size: expected size of decoded array
        :return: Bytes
        """
        out = b''.join(self.list_reader[:size])
        del self.list_reader[:size]
        return out

    def get_int(self):
        """
        Decode int with using VLQ.
        [[https://en.wikipedia.org/wiki/Variable-length_quantity]]
        :return: int
        """
        bytes_ = b''.join(self.list_reader)
        i = 0
        while bytes_[i] & 128 and i < 9:
            i += 1
        vlq = b''.join(self.list_reader[:i+1])
        del self.list_reader[:i+1]
        t = 0
        for item in vlq[::-1]:
            t = (t << 7) | item & 127
        return t

    def get_big_indian(self):
        """
        Parse 4 bytes from the byte array (starting at the offset) as unsigned 32-bit integer in big endian format
        :return: int
        """
        bytes_ = b''.join(self.list_reader[:4])
        out = int.from_bytes(bytes_, 'big')
        del self.list_reader[:4]
        return out


class HeaderSerializer:
    """
    Serialize and Parse Header
    """

    @staticmethod
    def parse_without_pow(reader: Reader):
        """
        get a Reader object
        :param reader: Reader object
        :return: a header without pow
        """
        version = reader.get_byte()
        parent_id = reader.get_bytes(32)
        ad_proofs_root = reader.get_bytes(32)
        transactions_root = reader.get_bytes(32)
        state_root = reader.get_bytes(33)
        timestamp = reader.get_int()
        extension_root = reader.get_bytes(32)
        n_bits = reader.get_big_indian()
        height = reader.get_int()
        votes = reader.get_bytes(3)
        return HeaderWithoutPow(version, parent_id, ad_proofs_root, transactions_root, state_root, timestamp,
                                extension_root, n_bits, height, votes)

    @staticmethod
    def serialize_without_pow(header: HeaderWithoutPow, writer: Writer):
        """
        get header without pow and Writer object
        :param header: HeaderWithoutPow object
        :param writer: Writer object
        """
        writer.put_byte(header.version)
        writer.put_bytes(decode(header.parentId, 'hex'))
        writer.put_bytes(decode(header.ADProofsRoot, 'hex'))
        writer.put_bytes(decode(header.transactionsRoot, 'hex'))
        writer.put_bytes(decode(header.stateRoot, 'hex'))
        writer.put_int(header.timestamp)
        writer.put_bytes(decode(header.extensionRoot, 'hex'))
        writer.put_big_indian(header.nBits)
        writer.put_int(header.height)
        writer.put_bytes(decode(header.votes, 'hex'))
