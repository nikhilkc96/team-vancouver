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


def meet_in_the_middle(n1, n2, enc, dec, u, x, f, l):
	l1 = []
	l2 = [] 
	# generate n1 random guesses for k1 and the corresponding encrypted cyphertexts
	while len(l1) < n1:
		k1 = np.random.randint(0, 2, l, dtype=int)
		x1 = enc(u, k1, 13, l, f)
		l1.append([k1, x1])
	# generate n2 random guesses for k2 and the corresponding decrypted plaintexts
	while len(l2) < n2:
		k2 = np.random.randint(0, 2, l, dtype=int)
		u2 = dec(x, k2, 13, l, f)
		l2.append([k2, u2])

	# search for matches between x1 and u2
	matches = []
	for i in range(len(l1)):
		for j in range(len(l2)):
			if np.array_equal(l1[i][1], l2[j][1]):
				matches.append([l1[i][0], l2[j][0]])
	return matches