"""
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

from pathlib import Path

from utils.utils import read_file_bytes

TEST_CERTS_DIR = Path(__file__).parent / 'x509-certs'
TEST_BUNDLE_CERTS_DIR = Path(__file__).parent / 'x509-bundle-certs'

CHAIN1 = read_file_bytes(TEST_CERTS_DIR / '1-chain.der')
KEY1 = read_file_bytes(TEST_CERTS_DIR / '1-key.der')
CHAIN2 = read_file_bytes(TEST_CERTS_DIR / '4-cert.der')
KEY2 = read_file_bytes(TEST_CERTS_DIR / '4-key.der')
BUNDLE = read_file_bytes(TEST_BUNDLE_CERTS_DIR / 'cert.der')
FEDERATED_BUNDLE = read_file_bytes(TEST_BUNDLE_CERTS_DIR / 'federated_bundle.der')
CORRUPTED = read_file_bytes(TEST_BUNDLE_CERTS_DIR / 'corrupted')
