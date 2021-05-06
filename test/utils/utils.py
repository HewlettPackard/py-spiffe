_TEST_JWKS_PATH = 'test/bundle/jwt_bundle/jwks/{}'


def read_file_bytes(filename):
    with open(filename, 'rb') as file:
        return file.read()


JWKS_1_EC_KEY = read_file_bytes(_TEST_JWKS_PATH.format('jwks_1_ec_key.json'))
JWKS_2_EC_1_RSA_KEYS = read_file_bytes(_TEST_JWKS_PATH.format('jwks_3_keys.json'))
JWKS_MISSING_KEY_ID = read_file_bytes(_TEST_JWKS_PATH.format('jwks_missing_kid.json'))
JWKS_MISSING_X = read_file_bytes(_TEST_JWKS_PATH.format('jwks_ec_missing_x.json'))
