import dicetoprv


def main():
    print(dicetoprv.receive_arguments())


def prvdet():
    print(dicetoprv.prv_details())


def prvdec():
    dicetoprv.prv_wif_info()


def generateprv():
    dicetoprv.generate_prv()


def prvtoadd():
    dicetoprv.prv_to_add()
