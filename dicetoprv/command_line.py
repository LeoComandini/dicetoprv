import dicetoprv


def main():
    print(dicetoprv.receive_arguments())


def prvdet():
    print(dicetoprv.prv_details())


def cmd_decode_prv_wif():
    dicetoprv.decode_prv_wif()


def cmd_prv_hex_to_wif():
    dicetoprv.prv_hex_to_wif()


def generateprv():
    dicetoprv.generate_prv()


def prvtoadd():
    dicetoprv.prv_to_add()
