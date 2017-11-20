#!/usr/bin/env python3

"""
create a new private key
 1. insert randomness from the dice
 2. dumb way for testing
 3. insert randomness pressing the keyboard multiple times
"""

# packages
from pytictoc import TicToc
from numpy import log
from math import ceil
from base58 import b58encode_check
from hashlib import sha256, new as hash_new
from argparse import ArgumentParser

# parameters
ec_prime = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f
ec_a = 0
ec_b = 7
ec_gx = 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
ec_gy = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8
ec_G = (ec_gx, ec_gy)
ec_order = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141
secp256k1_param = ec_prime, ec_a, ec_b, ec_G, ec_order

# adapted from https://github.com/alexmgr/tinyec


def mod_inv(a, p):
    # p should be ec_prime, etc...
    return pow(a, p-2, p)


def h160(inp):
    h1 = sha256(inp).digest()
    return hash_new('ripemd160', h1).digest()


class Curve(object):

    def __init__(self, param):
        prime, a, b, (gx, gy), order = param
        self.prime = prime
        self.a = a
        self.b = b
        self.G = gx, gy
        self.order = order

    def __eq__(self, other):
        return self.prime == other.prime and \
               self.a == other.a and \
               self.b == other.b and \
               self.G == other.G and \
               self.order == other.order

    def __ne__(self, other):
        return not self.__eq__(other)

    # checks on curve

    def __str__(self):
        return "y^2 mod (" + str(self.prime) + ") = \
                x^3 + " + str(self.a) + " * x + " + str(self.b) + " mod (" + str(self.prime) + ")"


class EcPoint(object):

    def __init__(self, x=None, y=None):
        self.x = x
        self.y = y
        self.inf = (self.x is None and self.y is None)
        self.curve = Curve(secp256k1_param)
        self.on_curve = self.is_on_curve()

    def is_on_curve(self):
        if self.inf:
            return True
        else:
            return self.y ** 2 % self.curve.order == \
                   (self.x ** 3 + self.curve.a * self.x + self.curve.b) % self.curve.order

    def __eq__(self, other):
        if not isinstance(other, EcPoint):
            return False
        return self.x == other.x and self.y == other.y and self.curve == other.curve

    def __ne__(self, other):
        return not self.__eq__(other)

    def __add__(self, other):
        if not isinstance(other, EcPoint):
            raise TypeError("Unsupported operand type for +")
        if not self.curve == other.curve:
            raise ValueError("Cannot compare point of different curves")
        if self.inf:
            return other
        if other.inf:
            return self
        if self.x == other.x and self.y != other.y:
            return EcPoint()
        if self == other:
            lam = ((3 * self.x * self.x + self.curve.a) * mod_inv(2 * self.y, self.curve.prime)) % self.curve.prime
            x = (lam * lam - 2 * self.x) % self.curve.prime
            y = (lam * (self.x - x) - self.y) % self.curve.prime
            return EcPoint(x, y)
        else:
            lam = ((other.y - self.y) * mod_inv(other.x - self.x, self.curve.prime)) % self.curve.prime
            x = (lam * lam - self.x - other.x) % self.curve.prime
            y = (lam * (self.x - x) - self.y) % self.curve.prime
            return EcPoint(x, y)

    def __mul__(self, other):
        if not isinstance(other, int):
            raise TypeError("multiplication only with int")
        scalar = other % self.curve.order
        result = EcPoint()
        addend = self
        while scalar > 0:
            if scalar % 2 == 1:
                result += addend
            addend += addend
            scalar //= 2
        return result

    def __rmul__(self, other):
        return self.__mul__(other)

    def __str__(self):
        if self.inf:
            return "Point @ Infinity"
        return "(" + hex(self.x) + "," + hex(self.y) + ")"

    def __repr__(self):
        return self.__str__()


class Keys(object):

    def __init__(self, prv, compressed=True):
        self.prv = prv
        self.pub = self.prv * EcPoint(ec_G[0], ec_G[1])
        self.compressed = compressed
        self.version_prefix_prv_wif = b'\x80'
        self.version_prefix_address = b'\x00'
        self.add = self._pub_to_add()

    def _prv_to_wif(self):
        return b58encode_check(self.version_prefix_prv_wif + self.prv.to_bytes(32, "big") +
                               (b'\x01' if self.compressed else b''))

    def _pub_to_bytes(self):
        if self.compressed:
            return (b'\x02' if self.pub.y % 2 == 0 else b'\x03') + self.pub.x.to_bytes(32, "big")
        else:
            return b'\x04' + self.pub.x.to_bytes(32, "big") + self.pub.y.to_bytes(32, "big")

    def _pub_to_add(self):
        return h160(self._pub_to_bytes())

    def _add_to_wif(self):
        return b58encode_check(self.version_prefix_address + self._pub_to_add())

    def __str__(self):
        return \
            "\nformat:\n" + \
            ("compressed" if self.compressed else "uncompressed") + \
            "\nprivate key in hex:\n" + \
            hex(self.prv)[2:] + \
            "\nprivate key in wif:\n" + \
            self._prv_to_wif() + \
            "\npublic key in hex:\n" + \
            self._pub_to_bytes().hex() + \
            "\naddress in hex:\n" + \
            self._pub_to_add().hex() + \
            "\naddress in wif:\n" + \
            self._add_to_wif()


class DiceRoll:

    def __init__(self, method, base, ind, max_ind):
        self.method = method
        self.base = base
        self.ind = ind
        self.max_ind = max_ind
        self.result = self._throw()

    def _throw(self):
        dice = None
        if self.method == 1:  # insert from keyboard
            flag = True
            while flag:
                padding = " " * (len(str(self.max_ind)) - len(str(self.ind)))
                str_input = "throw " + padding + str(self.ind) + "/" + str(self.max_ind) + ", result: "
                inp = input(str_input)
                if all(c in "0123456789" for c in inp) and inp != "":
                    dice = int(inp) - 1
                    if dice in range(self.base):
                        flag = False
                    else:
                        print("invalid result, insert again")
                else:
                    print("invalid result, insert again")
        if self.method == 2:  # dice result always 2
            dice = 1
            padding = " " * (len(str(self.max_ind)) - len(str(self.ind)))
            print("throw " + padding + str(self.ind) + "/" + str(self.max_ind) + ", result: " + str(dice + 1))
        if self.method == 3:  # throw pressing keyboard
            t = TicToc()
            t.tic()
            input("Press enter to throw")
            dice = int(t.tocvalue() * 10**8) % self.base
            padding = " " * (len(str(self.max_ind)) - len(str(self.ind)))
            print("throw " + padding + str(self.ind) + "/" + str(self.max_ind) + ", result: " + str(dice + 1))
        return dice


class GeneratePrv:

    def __init__(self, base, method=1):
        if not isinstance(base, int):
            raise TypeError("base must be an int")
        if base < 0:
            raise ValueError("base must be a positive int")
        if method not in (1, 2, 3):
            raise ValueError("method must be 1, 2 or 3")
        self.base = base
        self.n_throw = int(ceil(256 * log(2) / log(self.base)))  # approx ec_order is almost 2**256
        self.method = method
        self.curve = Curve(secp256k1_param)
        self.seq = []
        self.prv = self._receive_results()

    def _receive_results(self):
        print("\n_____________")
        print("Start generation of a private key using a dice with " + str(self.base) + " faces")
        n = self.n_throw - 1
        prv = 0
        while n >= 0:
            dr = DiceRoll(self.method, self.base, n + 1, self.n_throw)
            prv += dr.result * self.base ** n
            if prv < self.curve.order:
                self.seq += [dr.result]
                n -= 1
            else:
                print("The number generated is too high, repeat from the start to generate safely")
                n = self.n_throw - 1
                prv = 0
        if prv != 0:
            return prv
        else:
            print("The number generated is 0, repeat to generate safely")
            return self._receive_results()

    def __str__(self):
        seq_str = []
        for r in self.seq:
            seq_str += " " + str(r)
        return "dice with " + str(self.base) + "faces\n" + \
               "sequence of results:" + seq_str + "\n" + \
               "private key: " + hex(self.prv)[2:]


parser = ArgumentParser(description="Create private key with corresponding public key and address")
parser.add_argument("base", type=int, help="dice number of faces")
parser.add_argument("-m", "--method", type=int, choices=[1, 2, 3], default=1,
                    help="method to insert randomness: 1 from dice, 2 all values are '1', 3 from keyboard")
parser.add_argument("-u", "--uncompressed", help="obtain uncompressed keys and address", action="store_true")

args = parser.parse_args()
print(Keys(GeneratePrv(args.base, args.method).prv, not args.uncompressed))
