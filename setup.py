from setuptools import setup

setup(name='dicetoprv',
      version='0.1',
      description='generate private key using a dice',
      url='https://github.com/LeoComandini/dicetoprv.git',
      author='Leonardo Comandini',
      author_email='leonardocomandini@hotmail.it',
      license='MIT',
      packages=['dicetoprv'],
      install_requires=[
          'base58',
          'pytictoc',
          'numpy',
          'math',
          'hashlib',
          'argparse'
      ],
      script=['bin/generateprv'],
      zip_safe=False)
