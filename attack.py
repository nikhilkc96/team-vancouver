import numpy as np
from hexutils import *


def find_mat(enc, l):

    a = np.zeros((l, l), dtype=int)
    b = np.zeros((l, l), dtype=int)

    # compute matrix A
    u = strhex_to_bin_array('0x00000000')
    for j in range(l):
        e = np.zeros((l,), dtype=int)
        e[j] = 1
        x = enc(u, e, 17)
        x = x.reshape((32, 1))
        a[:, j] = x[:, 0]

    # compute matrix B
    k = strhex_to_bin_array('0x00000000')
    for j in range(l):
        e = np.zeros((l,), dtype=int)
        e[j] = 1
        x = enc(e, k, 17)
        x = x.reshape((32, 1))
        b[:, j] = x[:, 0]

    return a, b