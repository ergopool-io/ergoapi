import struct
from ecpy.curves import Curve

# Number of elements in one solution
K = 32

# For convert m to 'flat map'
M = b''
for item in map(lambda i: struct.pack('>Q', i), range(0, 1024)):
    M += item

n = 26
N = pow(2, n)

# Create curve[Elliptic Curve Cryptography]
# Cyclic group 'G' of prime order 'Q' with fixed generator 'G' and identity element 'e.Secp256k1' elliptic curve
# is used for this purpose
CURVE = Curve.get_curve('secp256k1')
Q = CURVE.order
G = CURVE.generator

VALID_RANGE = int(pow(2, 256) / Q) * Q

"""
:param K: Number of elements in one solution
:param M: Constant data to be added to hash function to increase it's calculation time
:param n: Power of number of elements in a list
:param N: Total number of elements
:param Q: the order of this Cyclic group
:param G: the point generator of this Cyclic group
:param VALID_RANGE: Biggest number <= 2^256 that is divisible by q without remainder

"""


