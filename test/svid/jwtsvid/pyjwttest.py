from calendar import timegm
import datetime
import jwt
from jwt import PyJWKClient, PyJWS

token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6Ik5FRTFRVVJCT1RNNE16STVSa0ZETlRZeE9UVTFNRGcyT0Rnd1EwVXpNVGsxUWpZeVJrUkZRdyJ9.eyJpc3MiOiJodHRwczovL2Rldi04N2V2eDlydS5hdXRoMC5jb20vIiwic3ViIjoiYVc0Q2NhNzl4UmVMV1V6MGFFMkg2a0QwTzNjWEJWdENAY2xpZW50cyIsImF1ZCI6Imh0dHBzOi8vZXhwZW5zZXMtYXBpIiwiaWF0IjoxNTcyMDA2OTU0LCJleHAiOjE1NzIwMDY5NjQsImF6cCI6ImFXNENjYTc5eFJlTFdVejBhRTJINmtEME8zY1hCVnRDIiwiZ3R5IjoiY2xpZW50LWNyZWRlbnRpYWxzIn0.PUxE7xn52aTCohGiWoSdMBZGiYAHwE5FYie0Y1qUT68IHSTXwXVd6hn02HTah6epvHHVKA2FqcFZ4GGv5VTHEvYpeggiiZMgbxFrmTEY0csL6VNkX1eaJGcuehwQCRBKRLL3zKmA5IKGy5GeUnIbpPHLHDxr-GXvgFzsdsyWlVQvPX2xjeaQ217r2PtxDeqjlf66UYl6oY6AqNS8DH3iryCvIfCcybRZkc_hdy-6ZMoKT6Piijvk_aXdm7-QQqKJFHLuEqrVSOuBqqiNfVrG27QzAPuPOxvfXTVLXL2jek5meH6n-VWgrBdoMFH93QEszEDowDAEhQPHVs0xj7SIzA"
kid = "NEE1QURBOTM4MzI5RkFDNTYxOTU1MDg2ODgwQ0UzMTk1QjYyRkRFQw"
url = "https://dev-87evx9ru.auth0.com/.well-known/jwks.json"
jwks_client = PyJWKClient(url)
signing_key = jwks_client.get_signing_key_from_jwt(token)
data = jwt.decode(
    token,
    signing_key.key,
    algorithms=["RS256"],
    audience="https://expenses-api",
    options={"verify_exp": False},
)
print(data)
print("Data: {}".format(data))
print("---------------------------------------------------------------------")

header = jwt.get_unverified_header(token)
print("Header: {}".format(header))
print("Algorithm: {}".format(header['alg']))
print("---------------------------------------------------------------------")


payload = jwt.decode(
    token,
    key=signing_key.key,
    algorithms=header['alg'],
    options={"verify_exp": False, "verify_aud": False},
)
print("Payload: {}".format(payload))
print("---------------------------------------------------------------------")

payload = jwt.decode(
    token, algorithms=header['alg'], options={'verify_signature': True}
)
print("Payload: {}".format(payload))
print("---------------------------------------------------------------------")

try:
    print(payload['ttt'])
except KeyError as key_error:
    print(key_error.args[0])

'''now = timegm(datetime.utcnow().utctimetuple())'''
token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJzcGlmZmU6Ly90ZXN0Lm9yZy8iLCJuYW1lIjoiSm9obiBEb2UiLCJpYXQiOjE1MTYyMzkwMjIsImV4cCI6NDcyMTUwNTQzNywiYXVkIjpbInNwaXJlIl19.cvoi48geyYPAP88RQbBXyEXoRX09II5xAR0XKULWDwQ"
