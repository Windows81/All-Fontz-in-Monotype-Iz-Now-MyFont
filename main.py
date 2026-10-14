import functools
import os
import urllib.parse

from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.hazmat.primitives.serialization import load_der_public_key
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
import requests
import base64
import json

CLIENT_ID = 'n2T8ilPqVAD6jeSj4z7ZpX1OSIHoyiRE'
CHARACTER_SUBSETS = [
    (65, 90),
    (94, 94),
    (96, 122),
    (180, 181),
    (184, 184),
    (186, 186),
    (192, 214),
    (216, 231),
    (1424, 1535),
    (1536, 1791),
    (1872, 1919),
    (2160, 2303),
    (64285, 64310),
    (64312, 64316),
    (64318, 64318),
    (64320, 64321),
    (64323, 64324),
    (64326, 64335),
    (64336, 64829),
    (64832, 64975),
    (65008, 65023),
    (65136, 65140),
    (65142, 65276),
    (69216, 69246),
    (69314, 69319),
    (69328, 69336),
    (69370, 69375),
    (126464, 126467),
    (126469, 126495),
    (126497, 126498),
    (126500, 126500),
    (126503, 126503),
    (126505, 126514),
    (126516, 126519),
    (126521, 126521),
    (126523, 126523),
    (126530, 126530),
    (126535, 126535),
    (126537, 126537),
    (126539, 126539),
    (126541, 126543),
    (126545, 126546),
    (126548, 126548),
    (126551, 126551),
    (126553, 126553),
    (126555, 126555),
    (126557, 126557),
    (126559, 126559),
    (126561, 126562),
    (126564, 126564),
    (126567, 126570),
    (126572, 126578),
    (126580, 126583),
    (126585, 126588),
    (126590, 126590),
    (126592, 126601),
    (126603, 126619),
    (126625, 126627),
    (126629, 126633),
    (126635, 126651),
    (126704, 126705),
]


@functools.cache
def genAndKeepIV() -> bytes:
    return os.urandom(12)


@functools.cache
def genAndKeepToken() -> str:
    URL = 'https://wfpreviewv2.monotype.com/token?clientId=' + CLIENT_ID
    return requests.post(URL).json()['authorization']


@functools.cache
def getTokenEncryptor() -> RSAPublicKey:
    URL = 'https://wfpreviewv2.monotype.com/key'
    key_json_value = requests.get(URL).json()['key']
    partial_key = base64.b64decode(
        base64.b64decode(key_json_value)
        .removeprefix(b'-----BEGIN PUBLIC KEY-----\n')
        .removesuffix(b'\n-----END PUBLIC KEY-----')
        .replace(b'\n', b'')
    )
    return load_der_public_key(partial_key)


def genAndKeepEncryptedData(fontMD5: str, subsets: list[tuple[int, int]] = CHARACTER_SUBSETS):

    # {"fontMD5":"bece0fc4fcd4ef8ee9b536e6006c213c","subset":[{"start":"0020","end":"0020"},{"start":"0041","end":"005A"},{"start":"005E","end":"005E"},{"start":"0060","end":"007A"},{"start":"00A0","end":"00A0"},{"start":"00A8","end":"00A8"},{"start":"00AA","end":"00AA"},{"start":"00AF","end":"00AF"},{"start":"00B4","end":"00B5"},{"start":"00B8","end":"00B8"},{"start":"00BA","end":"00BA"},{"start":"00C0","end":"00D6"},{"start":"00D8","end":"00E7"}]}
    json_data = {
        'fontMD5': fontMD5,
        'subset': [
            {
                'start': '%04X' % s,
                'end': '%04X' % e,
            }
            for (s, e) in subsets
        ]
    }
    plaintext = json.dumps(json_data).encode()
    nonce = genAndKeepIV()

    key = genAndKeepToken().encode()[:32]
    encrypted_bin = AESGCM(key).encrypt(nonce, plaintext, None)
    return encrypted_bin[:-16], encrypted_bin[-16:]


def encryptToken() -> bytes:
    return getTokenEncryptor().encrypt(
        plaintext=genAndKeepToken().encode(),
        padding=padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def generateURL(fontMD5: str):
    (encrypted_data, tag) = genAndKeepEncryptedData(fontMD5)
    return 'https://wfpreviewv2.monotype.com/web-font?' + urllib.parse.urlencode({
        'encryptedToken': base64.b64encode(encryptToken()),
        'iv': base64.b64encode(genAndKeepIV()),
        'encryptedFontData': base64.b64encode(encrypted_data),
        'tag': base64.b64encode(tag),
        'fontFormat': 'WOFF2',
        'clientId': CLIENT_ID,
    })


r = generateURL("bece0fc4fcd4ef8ee9b536e6006c213c")
rr = requests.get(r)
print(r, rr)
