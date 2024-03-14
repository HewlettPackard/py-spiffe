""""
(C) Copyright 2021 Hewlett Packard Enterprise Development LP

Licensed under the Apache License, Version 2.0 (the "License"); you may
not use this file except in compliance with the License. You may obtain
a copy of the License at

https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
License for the specific language governing permissions and limitations
under the License.
"""

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
    author_email='security@spiffe.io',
    license='Apache License Version 2.0',
    packages=find_packages(where='src', exclude=['test']),
    package_dir={'': 'src'},
    install_requires=[
        'rfc3987',
        'pyjwt',
        'cryptography',
        'grpcio-tools',
        'pyasn1',
        'pyasn1-modules',
        'pem',
    ],
    python_requires='>=3.9',
)
