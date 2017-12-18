import dicetoprv


def cmd_generateprv():
    dicetoprv.generate_prv()


def cmd_prvtoadd():
    dicetoprv.prv_to_add()


def cmd_pubtoadd():
    dicetoprv.pub_to_add()


def cmd_addressdetails():
    dicetoprv.address_details()


def cmd_prvhextowif():
    dicetoprv.prv_hex_to_wif()


def cmd_addhextowif():
    dicetoprv.add_hex_to_wif()
