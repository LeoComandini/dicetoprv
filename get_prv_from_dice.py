# -*- coding: utf-8 -*-
"""
create a new private key
 1. insert randomness from the dice
 2. insert randomness pressing the keyboard multiple times
 3. dumb way for testing
"""

# packages
from pytictoc import TicToc
from numpy import log
from math import ceil
from base58 import b58encode_check
from hashlib import sha256, new as hash_new

# modules
from secp256k1 import ec_multiply, ec_G, ec_order
# migrate to class secp256k1 ?


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


def h160(inp):
    h1 = sha256(inp).digest()
    return hash_new('ripemd160', h1).digest()


def print_dumb_seq(n, i, n_throw):
    seq = ""
    for j in range (n_throw):
        seq += (str(n + 1) if j < i else str(0)) + "-"
    print("dumb sequence, from bottom to top")
    print(seq)
    print(i, "times", n+1, "and", n_throw-i, "times 0")


cp = CreatePrv()
