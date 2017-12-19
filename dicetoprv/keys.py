#!/usr/bin/env python3

"""
create private keys from dice rolls
$ generateprv 20
compute its address
$ prvtoadd PRV
"""

# packages
from numpy import log
from math import ceil
from base58 import b58encode_check, b58decode_check
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
def mod_sqrt(a, p):
    """since in secp256k1 p = 3 (mod 4) then the if the square root mod p of a exists it is
    x = a ** ((n+1)/4) (mod n)
    """
    x = pow(a, (p + 1) // 4, p)
    if x ** 2 % p == a % p or x ** 2 % p == -a % p:
        return x
    else:
        return 0


class EcPoint(object):

    def __init__(self, x=None, y=None, y_odd=None):
        self.curve = default_curve
        self.x = None
        self.y = None
        self.inf = True
        if x is not None and y is not None:
            self.set_x_y(x, y)
        if x is not None and y_odd is not None:
            self.set_x_y_parity(x, y_odd)
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
        self.inf = False
        self.on_curve = self.is_on_curve()

    def set_x_y_parity(self, x, y_odd):
        if not isinstance(x, int):
            raise TypeError("ec point coordinate must be int")
        if 0 >= x or x >= self.curve.prime:
            raise ValueError("ec point coordinate must be in [1..prime]")
        if y_odd not in (0, 1):
            raise ValueError("y_odd must be 0 or 1")
        y = mod_sqrt(x**3 + self.curve.b * x + self.curve.a, self.curve.prime)
        if y == 0:  # may be not valid if parameters are changed
            raise ValueError("x is not a licit coordinate for a point on the curve")
        if y % 2 + y_odd == 1:
            y = self.curve.prime - y
        self.x = x
        self.y = y
        self.inf = False
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

    def __init__(self, prv=None):
        self.prv = None
        self.version = version_default_prv
        self.compressed = True
        self.curve = default_curve
        self.set_prv(prv)

    def set_prv(self, prv):
        if prv is not None:
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
        if self.prv is None:
            return "private key is not set"
        else:
            return b58encode_check(self.version + self.prv.to_bytes(32, "big") + (b'\x01' if self.compressed else b''))

    def str_verbose(self):
        if self.prv is None:
            return "missing private key"
        else:
            return \
                "\nprefix - private key in hex                                               - " + \
                ("" if self.compressed else "un") + "compressed" + \
                "\n    " + self.version.hex() + " - " + hex(self.prv)[2:] + (" - 01" if self.compressed else "") + \
                "\nprivate key in wif:\n" + self.to_wif()

    def __str__(self):
        if self.prv is None:
            return "missing private key"
        else:
            return "\nprivate key in wif:\n" + self.to_wif()


class PublicKey(object):

    def __init__(self, private=None):
        self.private_key = None
        self.public_key = None
        self.compressed = True
        self.curve = default_curve
        self.set_private(PrivateKey(private))

    def set_compressed(self):
        self.compressed = True

    def set_uncompressed(self):
        self.compressed = False

    def set_curve(self, curve):
        if not isinstance(curve, Curve):
            raise TypeError("expected Curve object")
        self.curve = curve

    def set_private(self, private):
        if private.prv is not None:
            if not isinstance(private, PrivateKey):
                raise TypeError("expected PrivateKey object")
            if self.curve != private.curve:
                raise ValueError("PrivateKey and PublicKey objects must have the same Curve")
            self.compressed = private.compressed
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
            # raise ValueError("public key is not set")
            return b''
        if self.compressed:
            return (b'\x02' if self.public_key.y % 2 == 0 else b'\x03') + self.public_key.x.to_bytes(32, "big")
            # 32 or min len bytes?
        else:
            return b'\x04' + self.public_key.x.to_bytes(32, "big") + self.public_key.y.to_bytes(32, "big")

    def str_verbose(self):
        prv_str = "\nunknown private key" if self.private_key is None else self.private_key.str_verbose()
        if self.public_key is None:
            return "missing public key"
        else:
            return \
                prv_str + \
                "\npublic key in hex:\n" + self.to_bytes().hex() + \
                "\nformat:\n" + ("" if self.compressed else "un") + "compressed"

    def __str__(self):
        if self.public_key is None:
            return "missing public key"
        else:
            return "\npublic key in hex:\n" + self.to_bytes().hex()


def h160(inp):
    h1 = sha256(inp).digest()
    return hash_new('ripemd160', h1).digest()


class Address(object):

    def __init__(self, private=None):
        self.public = None
        self.address = None
        self.version = version_default_add
        self.compressed = None
        self.set_private(PrivateKey(private))

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
        if self.public.public_key is not None:
            self.compressed = public.compressed
        self.address = h160(self.public.to_bytes())

    def set_address(self, address):
        if self.public.public_key is not None:
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
        if self.address is None:
            return "address is not set"
        else:
            return b58encode_check(self.version + self.address)

    def str_verbose(self):
        pub_str = "\nunknown public key" if self.public is None else self.public.str_verbose()
        format_address = "unknown" if self.compressed is None else (("" if self.compressed else "un") + "compressed")
        if self.address is None:
            return "missing address"
        else:
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
        if self.how == 2:  # dice result always 2 (for testing, may cause infinite loop)
            dice = 1
            padding = " " * (len(str(self.max_ind)) - len(str(self.ind)))
            print("throw " + padding + str(self.ind) + "/" + str(self.max_ind) + ", result: " + str(dice + 1))
        return dice


class GeneratePrv:

    def __init__(self, base, how=1, curve=default_curve):
        if not isinstance(base, int):
            raise TypeError("base must be an int")
        if base < 0:
            raise ValueError("base must be a positive int")
        if how not in (1, 2, 3):
            raise ValueError("method must be 1, 2 or 3")
        self.base = base
        self.n_throw = int(ceil(256 * log(2) / log(self.base)))  # approx ec_order is almost 2**256
        self.how = how
        self.curve = curve
        self.seq = []
        self.prv = self._receive_results()

    def _receive_results(self):
        print("\n_____________")
        print("Start generation of a private key using a dice with " + str(self.base) + " faces")
        n = 0
        prv = 0
        while n <= self.n_throw - 1:
            dr = DiceRoll(self.base, n + 1, self.n_throw, self.how)
            prv += dr.result * self.base ** (self.n_throw - 1 - n)
            if prv < self.curve.order:
                self.seq += [dr.result]
                n += 1
            else:
                print("The number generated is too high, repeat from the start to generate safely")
                n = 0
                prv = 0
        if prv != 0:
            return prv
        else:
            print("The number generated is 0, repeat to generate safely")
            return self._receive_results()

    def __str__(self):
        seq_str = ""
        for r in self.seq:
            seq_str += str(r + 1) + ","
        return "dice with " + str(self.base) + " faces\n" + \
               "sequence of results: " + seq_str[:-1] + ";\n" + \
               "private key: " + hex(self.prv)[2:]


def is_hex(s):
    return(all(c in "0123456789abcdefABCDEF") for c in s)


def is_b58(s):
    return(all(c in "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz") for c in s)


def str_to_1bytes(s):
    if not isinstance(s, str):
        raise TypeError("s must be a str")
    if len(s) >= 3:
        if s[:2] == "0x":
            s = s[2:]
    if not all(c in "0123456789abcdefABCDEF" for c in s):
        raise TypeError("s must have hex values")
    h = int(s, 16)
    if h < 0 or h > 0xff:
        raise ValueError("hex should be between 0x00 and 0xff to be converted to 1 byte")
    return h.to_bytes(1, "big")


def hex_to_bytes(h, max_len):
    if type(h) != str or not is_hex(h) and len(h) > max_len and len(h) % 2 == 1:
        raise TypeError("expected hex string, with an even number of chars less or equal to" + str(max_len))
    return int(h, 16).to_bytes(len(h)//2, "big")


def generate_prv():
    parser = ArgumentParser(description="Create private key from dice result")
    parser.add_argument("base", type=int, help="dice number of faces")
    parser.add_argument("-t", "--how", type=int, choices=[1, 2], default=1,
                        help="how to insert randomness: 1 from dice (default), 2 all dice results are '2'")
    parser.add_argument("-u", "--uncompressed", help="generate an uncompressed private key, default is compressed",
                        action="store_true")
    parser.add_argument("-p", "--prefix_prv", help="version prefix for private keys in hex, in [0x00, 0xff]", type=str)
    parser.add_argument("-v", "--verbose", help="print more output", action="store_true")
    args = parser.parse_args()
    private = PrivateKey(GeneratePrv(args.base, args.how).prv)
    if args.uncompressed:
        private.set_uncompressed()
    if args.prefix_prv is not None:
        private.set_version(str_to_1bytes(args.prefix_prv))
    print(private.str_verbose() if args.verbose else private)


def decode_prv(prv_wif):
    if type(prv_wif) != str or not is_b58(prv_wif) or len(prv_wif) not in (51, 52):
        raise TypeError("expected a wif string of 51 or 52 char")
    try:
        b58decode_check(prv_wif.encode())
    except:
        ValueError("invalid checksum")
    wif_decoded = b58decode_check(prv_wif.encode())
    version = wif_decoded[:1]
    prv = int.from_bytes(wif_decoded[1:33], "big")
    private = PrivateKey(prv)
    private.set_version(version)
    if len(prv_wif) == 52:
        if wif_decoded[-1] != 1:
            raise TypeError("when the private key is compressed the last value must be a b'\x01'")
    else:
        private.set_uncompressed()
    return private


def prv_to_add():
    parser = ArgumentParser(description="Obtain address from private key")
    parser.add_argument("private_wif", type=str, help="private key in wif")
    parser.add_argument("-p", "--prefix_add", help="version prefix for address in hex, in [0x00, 0xff]", type=str)
    parser.add_argument("-v", "--verbose", help="print more output", action="store_true")
    args = parser.parse_args()
    private = decode_prv(args.private_wif)
    address = Address()
    address.set_private(private)
    if args.prefix_add is not None:
        address.set_version(str_to_1bytes(args.prefix_add))
    print(address.str_verbose() if args.verbose else address)


def decode_pub(pub_str):
    """from pub key in str to PublicKey
    """
    # fixme: should I manage the case with pub_str shorter than 33 bytes? may happen if x starts with b'\x00'
    if type(pub_str) != str and is_hex(pub_str) and len(pub_str) not in (128, 66):
        raise TypeError("expected hex string of 128 or 66 char")
    pub = PublicKey()
    if len(pub_str) == 130:
        if pub_str[:2] != "04":
            raise TypeError("public key in uncompressed format must start with '04'")
        pub.set_uncompressed()
        pub.set_public(EcPoint(x=int(pub_str[2:66], 16), y=int(pub_str[66:], 16)))
    else:
        if pub_str[:2] not in ("02", "03"):
            raise TypeError("public key in compressed format must start with '02' or '03'")
        pub.set_compressed()
        pub.set_public(EcPoint(x=int(pub_str[2:], 16), y_odd=int(pub_str[:2], 16) % 2))
    return pub


def pub_to_add():
    parser = ArgumentParser(description="Obtain address from public key")
    parser.add_argument("public", type=str, help="public key in hex")
    parser.add_argument("-p", "--prefix_add", help="version prefix for address in hex, in [0x00, 0xff]", type=str)
    parser.add_argument("-v", "--verbose", help="print more output", action="store_true")
    args = parser.parse_args()
    public = decode_pub(args.public)
    address = Address()
    address.set_public(public)
    if args.prefix_add is not None:
        address.set_version(str_to_1bytes(args.prefix_add))
    print(address.str_verbose() if args.verbose else address)


def decode_add(address_wif):
    if type(address_wif) != str or not is_b58(address_wif) or len(address_wif) > 34:
        raise TypeError("expected a wif string of 34 or less char")
    wif_decoded = b58decode_check(address_wif.encode())
    version = wif_decoded[:1]
    address = Address()
    address.set_address(wif_decoded[1:21])
    address.set_version(version)
    return address


def address_details():
    parser = ArgumentParser(description="Obtain address details")
    parser.add_argument("address", type=str, help="address in wif")
    args = parser.parse_args()
    address = decode_add(args.address)
    print(address.str_verbose())


def prv_hex_to_wif():
    parser = ArgumentParser(description="From private key in hex to wif")
    parser.add_argument("private_hex", type=str, help="private key in hex")
    parser.add_argument("-p", "--prefix_prv", help="version prefix for private key in hex, in [0x00, 0xff]", type=str)
    parser.add_argument("-u", "--uncompressed", help="uncompressed private key, default is compressed",
                        action="store_true")
    args = parser.parse_args()
    if type(args.private_hex) != str or not is_hex(args.private_hex) and len(args.private_hex) > 64:
        raise TypeError("expected hex string of 64 or less chars")
    private = PrivateKey(int(args.private_hex, 16))
    if args.prefix_prv is not None:
        private.set_version(str_to_1bytes(args.prefix_prv))
    if args.uncompressed:
        private.set_uncompressed()
    print(private)


def add_hex_to_wif():
    parser = ArgumentParser(description="From address in hex to wif")
    parser.add_argument("address_hex", type=str, help="address in hex")
    parser.add_argument("-p", "--prefix_add", help="version prefix for address in hex, in [0x00, 0xff]", type=str)
    args = parser.parse_args()
    address = Address()
    address.set_address(hex_to_bytes(args.address_hex, 20 * 2))
    if args.prefix_add is not None:
        address.set_version(str_to_1bytes(args.prefix_add))
    print(address)


# fixme: add field for empty public/private key, add tests
