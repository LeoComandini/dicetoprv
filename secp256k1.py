#!/usr/bin/python3

""" secp256k1 specs
elliptic curve y^2 = x^3 + a * x + b
"""


ec_prime = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f
ec_a = 0; ec_b = 7
gx = 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
gy = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8
ec_G = (gx, gy)
ec_order = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


def mod_inv(a, p):
    # p should be ec_prime, etc...
    return pow(a, p-2, p)


def ec_double(p):
    lam = ((3*p[0]*p[0]+ec_a) * mod_inv(2*p[1], ec_prime)) % ec_prime
    x = (lam*lam-2*p[0]) % ec_prime
    y = (lam*(p[0]-x)-p[1]) % ec_prime
    return x, y


def ec_add(p, q):
    if p == q:
        return ec_double(p)
    lam = ((q[1]-p[1]) * mod_inv(q[0]-p[0], ec_prime)) % ec_prime
    x = (lam*lam-p[0]-q[0]) % ec_prime
    y = (lam*(p[0]-x)-p[1]) % ec_prime
    return x, y


def ec_multiply(n, p):
    assert n != 0
    if n == 1:
        return p
    elif n % 2 == 1: # addition when n is odd
        return ec_add(p, ec_multiply(n - 1, p))
    else:            # doubling when n is even
        return ec_multiply(n//2, ec_double(p))


print(ec_multiply(10, ec_G))