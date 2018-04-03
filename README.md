# dicetoprv
package to generate private keys from dice results

to install:
```
pip install git+https://github.com/LeoComandini/dicetoprv.git
```

You can:
- generate a private key using dice results: `$ generateprv NUMBER_OF_FACES`
- from private key to address: `$ prvtoadd PRIVATE_KEY`
- from public key to address: `$ pubtoadd PUBLIC_KEY`
- address details: `$ addressdetails ADDRESS_WIF`
- from private key in hex to wif: `$ prvhextowif PRIVATE_HEX`
- from address in hex to wif: `$ addhextowif ADDRESS_HEX`
