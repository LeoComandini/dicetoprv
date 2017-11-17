# -*- coding: utf-8 -*-
"""
create a new private key
 1. insert randomness from the dice
 2. insert randomness pressing the keyboard multiple times
 3. dumb way for testing
"""

# packages
# from pytictoc import TicToc
from numpy import log
from math import ceil
from base58 import b58encode_check
from hashlib import sha256, new as hash_new
# from os import urandom

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

    def __init__(self, prv):
        self.prv = prv
        self.pub = self.prv * EcPoint(ec_G[0], ec_G[1])
        self.compressed = True
        self.version_prefix_prv_wif = b'\x80'
        self.version_prefix_address = b'\x00'
        self.add = self.__pub_to_add()

    def __prv_to_wif(self):
        return b58encode_check(self.version_prefix_prv_wif + self.prv.to_bytes(32, "big") +
                               (b'\x01' if self.compressed else b''))

    def __pub_to_bytes(self):
        if self.compressed:
            return (b'\x02' if self.pub.y % 2 == 0 else b'\x03') + self.pub.x.to_bytes(32, "big")
        else:
            return "04" + self.pub.x.to_bytes(32, "big") + self.pub.y.to_bytes(32, "big")

    def __pub_to_add(self):
        return h160(self.__pub_to_bytes())

    def __add_to_wif(self):
        return b58encode_check(self.version_prefix_address + self.__pub_to_add())

    def __str__(self):
        return \
            "private key in hex:\n" + \
            hex(self.prv)[2:] + \
            "\nprivate key in wif:\n" + \
            self.__prv_to_wif() + \
            "\npublic key in hex:\n" + \
            self.__pub_to_bytes().hex() + \
            "\naddress in hex:\n" + \
            self.__pub_to_add().hex() + \
            "\naddress in wif:\n" + \
            self.__add_to_wif()


class DiceRoll:

    def __init__(self, method, base, ind, max_ind):
        self.method = method
        self.base = base
        self.ind = ind
        self.max_ind = max_ind
        self.result = self.__throw()

    def __throw(self):
        dice = None
        if self.method == 1:
            flag = True
            while flag:
                str_input = "throw " + str(self.ind) + "/" + str(self.max_ind) + ", result: "
                dice = int(input(str_input)) - 1
                if dice in range(self.base):
                    flag = False
                else:
                    print("Invalid result, insert again")
        if self.method == 2:
            dice = 1
            print("throw " + str(self.ind) + "/" + str(self.max_ind) + ", result: " + str(dice + 1))
        return dice


class GeneratePrv:

    def __init__(self, base):
        self.base = base
        self.n_throw = int(ceil(256 * log(2) / log(self.base)))  # approx ec_order is almost 2**256
        self.method = 2
        self.curve = Curve(secp256k1_param)
        self.seq = []
        self.prv = self.__receive_results()

    def __receive_results(self):
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
            return self.__receive_results()

    def __str__(self):
        return hex(self.prv)[2:]


gp = GeneratePrv(16)
print(Keys(gp.prv))

'''
class CreatePrv:
    
    def __init__(self, method, base):
        self.method = method
        self.base = base
        self.n_throw = self.compute_n_throw()
        self.compressed = True
        self.prv 
        self.pub
        self.add


class CreatePrv:

    def __init__(self):
        self.method = self.decide_method()
        self.get_base()
        self.compressed = True
        self.prv = self.receive_dice_results()
        self.prv_to_pub()
        self.add = self.pub_to_add()

        self.print_stuff()

    def decide_method(self):
        print("How do you want to generate the randomness?")
        print("1    : insert manually")
        print("dumb : dumb way for testing")
        print("other: from keyboard")
        inp = input()
        if inp == "1": return 1
        elif inp == "dumb": return 2
        else: return 0

    def get_base(self):
        base = int(input("How many faces does the dice have?  "))
        assert base > 0, "the number of faces must be a postive int"
        self.base = base
        self.n_throw = int( ceil(256 * log(2) / log(self.base))) # approx ec_order is almost 2**256

    def roll_dice_with_keyboard(self, ind, max_ind):
        t = TicToc()
        t.tic()
        print("shaking dice ...")
        input("press a key to roll")
        r = t.tocvalue()
        r = int(r * 10**8) % self.base
        print("throw " + str(ind) + "/" + str(max_ind)+ " : " + str(r + 1))
        return r

    def get_digit(self, ind, max_ind):
        str_input = str(ind) + "/" + str(max_ind) + " -- insert digit:"
        digit = int(input(str_input)) - 1
        if digit in range(self.base): return digit
        else:
            print("Insert again")
            return self.get_digit(ind, max_ind)

    def dumb(self): # very bad written!
        n = int(input("insert dumb value  ")) - 1
        assert n in range(self.base)
        prv = 0
        for i in range(self.n_throw):
            prv += n * self.base**i
            if prv >= ec_order:
                prv -= n * self.base**i
                print_dumb_seq(n, i, self.n_throw)
                return prv

        assert 0 < prv and prv < ec_order, "invalid dumb value"
        print_dumb_seq(n, i, self.n_throw)
        return prv

    def receive_dice_results(self):
        if self.method == 1:
            roll_func = self.get_digit
        elif self.method == 2:
            return self.dumb()
        else:
            roll_func = self.roll_dice_with_keyboard
        print("\nStart now! _______________________________________")
        prv = 0
        exceed = False
        n = self.n_throw - 1
        while n >= 0 and not exceed:
            prv += roll_func(n + 1, self.n_throw) * self.base**(n)
            if prv > ec_order:
                exceed = True
                print("Exceeded max dimension, repeat to generate safely")
            n -= 1
        if exceed: return self.receive_dice_results()
        elif prv == 0:
            print("prv can't be 0, repeat to generate safely")
            return self.receive_dice_results()
        else: return prv

    def set_uncompressed(self):
        self.compressed = False

    def set_compressed(self):
        self.compressed = True

    def prv_to_wif(self):
        return b58encode_check(b'\x80' + self.prv.to_bytes(32, "big") + \
               (b'\x01' if self.compressed else b''))

    def print_stuff(self):
        print("\n__________________________________________________")
        print("format: " + ("compressed" if self.compressed else "uncompressed"))
        print("private key in hex:")
        print(hex(self.prv))
        print("private key in WIF:")
        print(self.prv_to_wif())
        print("public key:")
        print(self.pub)
        print("address:")
        print(self.add)

    def prv_to_pub(self):
        pub = ec_multiply(self.prv, ec_G)
        if self.compressed:
            self.pub = ("02" if pub[1] % 2 == 0 else "03") + to_bytes_str(pub[0])
        else:
            self.pub = "04" + to_bytes_str(pub[0]) + to_bytes_str(pub[1])

    def pub_to_add(self):
        return b58encode_check(b'\x00' + h160(self.pub.encode()))


def bytes_length(b):
    return (b.bit_length() + 7) // 8


def to_bytes_str(s):
    return s.to_bytes(bytes_length(s), "big").hex()


def print_dumb_seq(n, i, n_throw):
    seq = ""
    for j in range (n_throw):
        seq += (str(n + 1) if j < i else str(0)) + "-"
    print("dumb sequence, from bottom to top")
    print(seq)
    print(i, "times", n+1, "and", n_throw-i, "times 0")


#cp = CreatePrv()
'''