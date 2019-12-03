import struct
K = 32

m = map(lambda i: struct.pack('>q', i), range(0, 1024))
# For convert m to 'flat map'
M = [item for elem in m for item in elem]

n = 26
N = pow(2, n)

"""
:param K: Number of elements in one solution
:param M: Constant data to be added to hash function to increase it's calculation time
:param n: Power of number of elements in a list
:param N: Total number of elements

"""


