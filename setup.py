from setuptools import setup, find_packages
from codecs import open
from os import path

DESCRIPTION = 'Python library for SPIFFE'

here = path.abspath(path.dirname(__file__))

# Get the long description from the README file
try:
    with open(path.join(here, 'README.md'), encoding='utf-8') as f:
        long_description = f.read()
except FileNotFoundError:
    long_description = DESCRIPTION

setup(
    name='pyspiffe',
    version='0.0.1',
    description=DESCRIPTION,
    long_description=long_description,
    long_description_content_type='text/markdown',
    url='https://github.com/spiffe/py-spiffe',
    author='HPE',
    author_email=security@spiffe.io,
    license='Apache License Version 2.0',
    packages=find_packages(where='src', exclude=['test']),
    package_dir={'': 'src'},
    install_requires=['rfc3987', 'pyjwt'],
    python_requires='>=3.6',
)
