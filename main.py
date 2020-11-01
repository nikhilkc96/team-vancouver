import numpy as np


def strhex_to_bin_array(s):
    b = bin(int(s, 16))[2:]
    a = np.array(list(b), dtype=int)
    return a


def bin_array_to_strhex(a):
    b = ""
    for x in a:
        b += str(x)
    h = hex(int(b, 2))
    return h


def key_gen(i, k):
    l_k = k.shape[0]
    key = np.zeros((l_k,), dtype=int)

    for j in range(l_k):
        index = ((5 * i + j - 1) % l_k)  # the formula in the slide is 1-indexed
        key[j] = k[index]

    return key


def f(k, i, y):
    l = y.shape[0]
    w = np.zeros((l,), dtype=int)
    for j in range(l):
        if j <= l / 2:
            w[j] = y[j] ^ k[4*j - 3]
        else:
            w[j] = y[j] ^ k[4*j - 2*l]
    return w


def encrypt(u, k, r):
    z = u[:16]
    y = u[16:]

    for i in range(r):
        round_key = key_gen(i+1, k)
        w = f(round_key, i, y)
        v = np.bitwise_xor(w, z)
        z = y
        y = v

    x = np.append(y, z)  # wrong way around since we did one more T in the for loop
    return x


def decrypt(x, k, r):
    z = x[:16]
    y = x[16:]

    for i in range(r):
        round_key = key_gen(r-i, k)  # inverted key sequence
        w = f(round_key, i, y)
        v = np.bitwise_xor(w, z)
        z = y
        y = v

    u = np.append(y, z)  # wrong way around since we did one more T in the for loop
    return u


def main():
    k = strhex_to_bin_array('0x80000000')
    u = strhex_to_bin_array('0x80000000')

    x = encrypt(u, k, 17)
    uu = decrypt(x, k, 17)

    print(x)
    print(bin_array_to_strhex(x))

    print(uu)
    print(bin_array_to_strhex(uu))


if __name__ == "__main__":
    main()
