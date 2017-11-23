#!/usr/bin/env python3

# packages
from numpy import log
from math import ceil
from base58 import b58encode_check, b58decode_check, alphabet as b58digits
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
# version prefixes
version_prefix_prv = {"mainnet": b'\x80', "testnet": b'\xef'}
version_prefix_add = {"mainnet": b'\x00', "testnet": b'\x6f'}
version_default_prv = version_prefix_prv["mainnet"]
version_default_add = version_prefix_add["mainnet"]


class Curve(object):

    # checks on curve, prime, positive, etc

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

    def __str__(self):
        return "y^2 mod (" + str(self.prime) + ") = \
                x^3 + " + str(self.a) + " * x + " + str(self.b) + " mod (" + str(self.prime) + ")"


default_curve = Curve(secp256k1_param)


def mod_inv(a, p):
    # p should be ec_prime, etc...
    return pow(a, p-2, p)


# def mod_sqrt(s, p): # missing


class EcPoint(object):

    def __init__(self, x=None, y=None):
        self.curve = default_curve
        self.x = None
        self.y = None
        if x is not None and y is not None:
            self.inf = True
            self.set_x_y(x, y)
        self.inf = (self.x is None and self.y is None)
        self.on_curve = self.is_on_curve()

    def set_x_y(self, x, y):
        if not isinstance(x, int):
            raise TypeError("ec point coordinate must be int")
        if 0 >= x or x >= self.curve.prime:
            raise ValueError("ec point coordinate must be in [1..prime]")
        if not isinstance(y, int):
            raise TypeError("ec point coordinate must be int")
        if 0 >= y or y >= self.curve.prime:
            raise ValueError("ec point coordinate must be in [1..prime]")
        self.x = x
        self.y = y
        self.on_curve = self.is_on_curve()

    def set_x_y_parity(self, x, y_odd):
        if not isinstance(x, int):
            raise TypeError("ec point coordinate must be int")
        if 0 >= x or x >= self.curve.prime:
            raise ValueError("ec point coordinate must be in [1..prime]")
        if y_odd in (0, 1):
            raise ValueError("y_odd must be 0 or 1")
        # y = mod_sqrt(x**3 + self.curve.b * x + self.curve.a, self.curve.prime)
        y = x  # temp, now mod_sqrt is missing!
        if y % 2 + y_odd == 1:
            y = self.curve.prime - y
        self.x = x
        self.y = y
        self.on_curve = self.is_on_curve()

    def set_curve(self, curve):
        if not isinstance(curve, Curve):
            raise TypeError("curve must be a Curve")
        self.curve = curve

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


class PrivateKey(object):

    def __init__(self):
        self.prv = None
        self.version = version_default_prv
        self.compressed = True
        self.curve = default_curve

    def set_prv(self, prv):
        if not isinstance(prv, int):
            raise TypeError("prv must be an int")
        if 0 >= prv or prv >= self.curve.order:
            raise ValueError("prv must be in [1..order]")
        self.prv = prv

    def set_version(self, version):
        if not isinstance(version, bytes):
            raise TypeError("version prefix must be in bytes")
        self.version = version

    def set_compressed(self):
        self.compressed = True

    def set_uncompressed(self):
        self.compressed = False

    def set_curve(self, curve):
        if not isinstance(curve, Curve):
            raise TypeError("curve must be a Curve")
        self.curve = curve

    def to_wif(self):
        return b58encode_check(self.version + self.prv.to_bytes(32, "big") + (b'\x01' if self.compressed else b''))

    def str_verbose(self):
        return \
            "\nprivate key in hex:\n" + hex(self.prv)[2:] + \
            "\nformat:\n" + ("" if self.compressed else "un") + "compressed" + \
            "\nversion prefix:\n" + self.version.hex() + \
            "\nprivate key in wif:\n" + self.to_wif()

    def __str__(self):
        if self.prv is None:
            return "missing private key"
        else:
            return "\nprivate key in wif:\n" + self.to_wif()


class PublicKey(object):

    def __init__(self):
        self.private_key = None
        self.public_key = None
        self.compressed = True
        self.curve = default_curve

    def set_compressed(self):
        self.compressed = True

    def set_uncompressed(self):
        self.compressed = False

    def set_curve(self, curve):
        if not isinstance(curve, Curve):
            raise TypeError("expected Curve object")
        self.curve = curve

    def set_private(self, private):
        if not isinstance(private, PrivateKey):
            raise TypeError("expected PrivateKey object")
        if self.curve != private.curve:
            raise ValueError("PrivateKey and PublicKey objects must have the same Curve")
        if self.compressed != private.compressed:
            raise ValueError("PrivateKey and PublicKey objects must be both compressed or both uncompressed")
        self.private_key = private
        self.public_key = private.prv * EcPoint(self.curve.G[0], self.curve.G[1])

    def set_public(self, public):
        if not isinstance(public, EcPoint):
            raise TypeError("expected EcPoint object")
        if public.inf:
            raise ValueError("public key cannot be the point @ infinity")
        if self.private_key is not None:
            raise ValueError("cannot set public key if private is already set")
        self.public_key = public

    def to_bytes(self):
        if self.public_key is None:
            raise ValueError("public key is not set")
        if self.compressed:
            return (b'\x02' if self.public_key.y % 2 == 0 else b'\x03') + self.public_key.x.to_bytes(32, "big")
            # 32 or min len bytes?
        else:
            return b'\x04' + self.public_key.x.to_bytes(32, "big") + self.public_key.y.to_bytes(32, "big")

    def str_verbose(self):
        prv_str = "\nunknown private key" if self.private_key is None else self.private_key.str_verbose()
        return \
            prv_str + \
            "\npublic key in hex:\n" + self.to_bytes().hex() + \
            "\nformat:\n" + ("" if self.compressed else "un") + "compressed"

    def __str__(self):
        if self.public_key is None:
            return "missing public key"
        else:
            return self.to_bytes().hex()


def h160(inp):
    h1 = sha256(inp).digest()
    return hash_new('ripemd160', h1).digest()


class Address(object):

    def __init__(self):
        self.public = None
        self.address = None
        self.version = version_default_add
        self.compressed = None

    def set_private(self, private):
        if not isinstance(private, PrivateKey):
            raise TypeError("expected PrivateKey object")
        public = PublicKey()
        public.set_private(private)
        self.set_public(public)

    def set_public(self, public):
        if not isinstance(public, PublicKey):
            raise TypeError("expected PublicKey object")
        self.public = public
        self.compressed = public.compressed
        self.address = h160(self.public.to_bytes())

    def set_address(self, address):
        if self.public is not None:
            raise ValueError("cannot set address if public key is already set")
        if not (isinstance(address, bytes) and len(address) == 20):
            raise TypeError("expected 20 bytes")
        self.address = address

    def set_version(self, version):
        if not isinstance(version, bytes):
            raise TypeError("version prefix must be in bytes")
        self.version = version

    def set_compressed(self):
        self.compressed = True

    def set_uncompressed(self):
        self.compressed = False

    def set_unknown_format(self):
        self.compressed = None

    def to_wif(self):
        print(b58encode_check(self.version + self.address))
        return b58encode_check(self.version + self.address)

    def str_verbose(self):
        pub_str = "\nunknown public key" if self.public is None else self.public.str_verbose()
        format_address = "unknown" if self.compressed is None else (("" if self.compressed else "un") + "compressed")
        return \
            pub_str + \
            "\naddress in hex:\n" + self.address.hex() + \
            "\nformat:\n" + format_address + \
            "\nversion prefix:\n" + self.version.hex() + \
            "\naddress in wif:\n" + self.to_wif()

    def __str__(self):
        if self.address is None:
            return "missing address"
        else:
            return "\naddress in wif:\n" + self.to_wif()


class DiceRoll(object):

    def __init__(self, base, ind, max_ind, how):
        self.how = how
        self.base = base
        self.ind = ind
        self.max_ind = max_ind
        self.result = self._throw()

    def _throw(self):
        dice = None
        if self.how == 1:  # insert from keyboard
            flag = True
            while flag:
                padding = " " * (len(str(self.max_ind)) - len(str(self.ind)))
                inp = input("throw " + padding + str(self.ind) + "/" + str(self.max_ind) + ", result: ")
                if all(c in "0123456789" for c in inp) and inp != "":
                    dice = int(inp) - 1
                    if dice in range(self.base):
                        flag = False
                    else:
                        print("invalid result, insert again")
                else:
                    print("invalid result, insert again")
        if self.how == 2:  # dice result always 2 (for testing)
            dice = 1
            padding = " " * (len(str(self.max_ind)) - len(str(self.ind)))
            print("throw " + padding + str(self.ind) + "/" + str(self.max_ind) + ", result: " + str(dice + 1))
        return dice


# class GeneratePrv:
#   base -> n_throw
#   prv <- multiple RollDice

# class RollDice:
#   base, ind, max ind
#   dice_result



