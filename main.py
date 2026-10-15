from io import BytesIO
import urllib.parse
import functools
import base64
import json
import os

from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.hazmat.primitives.serialization import load_der_public_key
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from fontTools.ttLib import woff2
from fontTools.ttx import TTFont
import fontTools.merge
import requests

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
def genAndKeepToken() -> str:
    json_result = requests.post(
        headers={'origin': 'https://www.myfonts.com'},
        url='https://wfpreviewv2.monotype.com/token?clientId=' + CLIENT_ID,
    ).json()
    return json_result['authorization']


@functools.cache
def getTokenEncryptor() -> RSAPublicKey:
    URL = 'https://wfpreviewv2.monotype.com/key'
    key_json_value = requests.get(URL).json()['key']
    partial_key = base64.b64decode(
        base64.b64decode(s=key_json_value)
        .removeprefix(b'-----BEGIN PUBLIC KEY-----\n')
        .removesuffix(b'\n-----END PUBLIC KEY-----')
        .replace(b'\n', b'')
    )
    return load_der_public_key(partial_key)


def getSpecs(fontMD5: str) -> dict[str, int | str]:
    json_result = requests.post(
        json={'md5': fontMD5},
        headers={'origin': 'https://www.myfonts.com'},
        url='https://services.myfonts.com/api/metadata/tech',
    ).json()
    return json_result


def listGlyphSubsets(fontMD5: str) -> list[tuple[int, int]]:
    json_result = requests.post(
        json={'md5': fontMD5},
        headers={'origin': 'https://www.myfonts.com'},
        url='https://services.myfonts.com/api/metadata/glyph',
    ).json()

    ranges = []
    for group_name, block in json_result['data']['unicodeBlocks'].items():
        for subrange in block['range'].split(', '):
            try:
                dash_index = subrange.index('-')
                start = int(subrange[:dash_index])
                end = int(subrange[dash_index+1:])
            except ValueError:
                start = end = int(subrange)

            RANGE_MAX = 200
            while end - start > RANGE_MAX:
                ranges.append((start, start+RANGE_MAX-1))
                start += RANGE_MAX
            ranges.append((start, end))

    return sorted(ranges)


def genAndKeepEncryptedData(fontMD5: str, subsets: list[tuple[int, int]] = CHARACTER_SUBSETS, nonce: bytes = b'\0'*12) -> tuple[bytes, bytes]:

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

    aes_plaintext = json.dumps(json_data).encode()
    aes_key = genAndKeepToken().encode()[:32]

    encrypted_bin = AESGCM(aes_key).encrypt(nonce, aes_plaintext, None)

    return (
        encrypted_bin[:-16],  # cyphertext
        encrypted_bin[-16:],  # 16-byte GCM tag appended
    )


def encryptToken() -> bytes:
    return getTokenEncryptor().encrypt(
        plaintext=genAndKeepToken().encode(),
        padding=padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def generateWoff2URL(fontMD5: str, glyphSubsets: list[tuple[int, int]]):
    nonce = os.urandom(12)
    (encrypted_data, tag) = genAndKeepEncryptedData(fontMD5, glyphSubsets, nonce)

    query_string = urllib.parse.urlencode({
        'encryptedFontData': base64.b64encode(encrypted_data),
        'encryptedToken': base64.b64encode(encryptToken()),
        'iv': base64.b64encode(nonce),
        'tag': base64.b64encode(tag),
        'fontFormat': 'WOFF2',
        'clientId': CLIENT_ID,
    })

    return 'https://wfpreviewv2.monotype.com/web-font?' + query_string


if __name__ == '__main__':
    FONT_MD5 = 'bece0fc4fcd4ef8ee9b536e6006c213c'

    url = generateWoff2URL(
        fontMD5=FONT_MD5,
        glyphSubsets=listGlyphSubsets(FONT_MD5),
    )

    woff2_data = requests.get(url).content

    merger = fontTools.merge.Merger()
    merged_ttf = merger.merge([
        BytesIO(woff2_data),
    ])

    merged_ttf.save('font.ttf')
