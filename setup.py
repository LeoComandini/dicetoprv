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
          'numpy',  # 'math', 'hashlib',
          'argparse'
      ],
      entry_points={
          'console_scripts': ['generateprv=dicetoprv.command_line:cmd_generateprv',
                              'prvtoadd=dicetoprv.command_line:cmd_prvtoadd',
                              'pubtoadd=dicetoprv.command_line:cmd_pubtoadd',
                              'addressdetails=dicetoprv.command_line:cmd_addressdetails',
                              'prvhextowif=dicetoprv.command_line:cmd_prvhextowif',
                              'addhextowif=dicetoprv.command_line:cmd_addhextowif']
      },
      zip_safe=False)
