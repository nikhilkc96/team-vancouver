import numpy as np
from hexutils import *


def find_mat(enc, l, f):
	a = np.zeros((l, l), dtype=int)
	b = np.zeros((l, l), dtype=int)

	# compute matrix A
	u = strhex_to_bin_array('0x00000000', 32)
	for j in range(l):
		e = np.zeros((l,), dtype=int)
		e[j] = 1
		x = enc(u, e, 17, l, f)
		x = x.reshape((32, 1))
		a[:, j] = x[:, 0]

	# compute matrix B
	k = strhex_to_bin_array('0x00000000', 32)
	for j in range(l):
		e = np.zeros((l,), dtype=int)
		e[j] = 1
		x = enc(e, k, 17, l, f)
		x = x.reshape((32, 1))
		b[:, j] = x[:, 0]

	return a, b


def find_key_kpa(a, b, u, x):
	a_inv = np.linalg.inv(a)
	a_det = np.linalg.det(a)
	a1 = (a_inv * a_det)
	a1 = np.mod(a1, 2)
	#print("inverted a:")
	#print(a1)
	k = np.dot(a1, (x + np.dot(b, u)))
	k = np.rint(k).astype(int)  # the previous arrays are all float with some errors
	#print("key found: ", k)

	return np.mod(k, 2)
