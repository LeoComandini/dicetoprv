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
          'console_scripts': ['generateprvold=dicetoprv.command_line:main',
                              'prvdetails=dicetoprv.command_line:prvdet',
                              'decodeprv=dicetoprv.command_line:prvdec',
                              'generateprv=dicetoprv.command_line:generateprv',
                              'prvtoadd=dicetoprv.command_line:prvtoadd']
      },
      zip_safe=False)
