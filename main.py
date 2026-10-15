from typing import Any

from fontTools.ttLib.ttFont import TTFont
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
from fontTools.ttLib.tables import _n_a_m_e
from fontTools.ttx import TTFont, Tag
from fontTools.ttLib import woff2
import fontTools.merge
import requests

CLIENT_ID = 'n2T8ilPqVAD6jeSj4z7ZpX1OSIHoyiRE'


@functools.cache
def getAndKeepToken() -> str:
    json_result = requests.post(
        headers={'origin': 'https://www.myfonts.com'},
        url='https://wfpreviewv2.monotype.com/token?clientId=' + CLIENT_ID,
    ).json()
    return json_result['authorization']


@functools.cache
def getAndKeepEncryptedToken() -> bytes:
    URL = 'https://wfpreviewv2.monotype.com/key'
    key_json_value = requests.get(URL).json()['key']
    partial_key = base64.b64decode(
        base64.b64decode(s=key_json_value)
        .removeprefix(b'-----BEGIN PUBLIC KEY-----\n')
        .removesuffix(b'\n-----END PUBLIC KEY-----')
        .replace(b'\n', b'')
    )
    public_key = load_der_public_key(partial_key)
    assert isinstance(public_key, RSAPublicKey)
    return public_key.encrypt(
        plaintext=getAndKeepToken().encode(),
        padding=padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


@functools.cache
def getAndKeepSpecs(fontMD5: str) -> dict[str, int | str]:
    # {"data": {"character_set": "ASCII, EBCDIC-CP-BE (Western Europe), IBM CP 037 (English), IBM CP 1026 (Turkish), IBM CP 1140 (Western Europe), ISO Latin-1, ISO Latin-13 (Baltic), ISO Latin-15 (Western Europe), ISO Latin-16 (South-Eastern Europe), ISO Latin-2 (Central and Eastern Europe), ISO Latin-4 (Baltic), ISO Latin-9 (Turkish), MS CP 1250 (Central and Eastern Europe), MS CP 1252 (Western Europe), MS CP 1254 (Turkish), MS CP 1257 (Baltic), Mac Central Europe, Mac Icelandic, Mac Turkish", "family_name": "Regina Standard", "file_size": 205036, "format": "OpenType CFF", "full_name": "Regina Standard Regular", "glyph_count": 1506, "ot_features": "aalt c2sc case ccmp dlig dnom frac kern liga lnum locl mark numr ordn pnum rlig sinf smcp ss01 ss02 ss03 ss04 ss05 ss06 ss08 ss09 ss10 ss11 ss12 ss13 subs sups tnum", "post_script_name": null, "sub_family_name": "Regular", "supported_languages": "Afar, Afrikaans, Aragonese, Asu, Azeri, Bemba, Bena, Bosnian, Catalan, Cebuano, Chiga, Corsican, Czech, Welsh, Danish, Taita, German, Lower Sorbian, Jola-Fonyi, Embu, English, Spanish, Estonian, Basque, Finnish, Filipino, Faroese, French, Friulian, Western Frisian, Irish, Scottish Gaelic, Galician, Swiss German, Gusii, Manx, Croatian, Upper Sorbian, Hungarian, Interlingua, Indonesian, Ido, Icelandic, Italian, Lojban, Machame, Jju, Kamba, Makonde, Kabuverdianu, Kaingang, Kikuyu, Kalaallisut, Kalenjin, Shambala, Colognian, Kurdish, Cornish, Latin, Luxembourgish, Ganda, Ligurian, Lithuanian, Luo, Luyia, Latvian, Meru, Morisyen, Malagasy, Makhuwa-Meetto, Maori, Malay, Maltese, Norwegian Bokm\u00e5l, North Ndebele, Low German, Dutch, Norwegian Nynorsk, Norwegian, South Ndebele, Northern Sotho, Nyanja, Nyankole, Occitan, Oromo, Polish, Portuguese, Romansh, Rundi, Romanian, Rombo, Kinyarwanda, Rwa, Samburu, Sangu, Sardinian, Northern Sami, Sena, Sango, Sidamo, Slovak, Slovenian, Southern Sami, Lule Sami, Inari Sami, Shona, Somali, Albanian, Serbian, Swati, Saho, Southern Sotho, Sundanese, Swedish, Swahili, Teso, Turkmen, Tswana, Turkish, Taroko, Tsonga, Volap\u00fck, Vunjo, Walloon, Walser, Warlpiri, Wolof, Xhosa, Soga, Zulu", "version": "Version 1.000;Glyphs 3.4.1 (3436)", "version_id": ""}}
    json_result = requests.post(
        json={'md5': fontMD5},
        headers={'origin': 'https://www.myfonts.com'},
        url='https://services.myfonts.com/api/metadata/tech',
    ).json()
    return json_result


@functools.cache
def getAndKeepFontNamesAndHashes(slug: str) -> list[dict[str, Any]]:
    json_result = requests.post(
        json={
            'requests': [{
                'indexName': 'universal_search_data',
                'params': {
                    'analyticsTags': ['quickViewMTFCOM', 'en'],
                    'attributesToHighlight': [],
                    'distinct': False,
                    'facetFilters': ['handle:'+slug],
                    'facets': [],
                    'hitsPerPage': 500,
                    'numericFilters': [],
                    'ruleContexts': ['quickViewMTFCOM', 'en'],
                    'tagFilters': '',
                }
            }]
        },
        headers={'origin': 'https://www.myfonts.com'},
        url='https://search-myfonts-api.monotype.com/v1/myfonts-search?x-algolia-application-id=P11UZVL396',
    ).json()
    return [
        hit['font_data']
        for hit in json_result['results'][0]['hits']
    ]


@functools.cache
def getAndKeepGlyphSubsets(fontMD5: str) -> list[tuple[int, int]]:
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


def genEncryptedData(fontMD5: str, subsets: list[tuple[int, int]], nonce: bytes = b'\0'*12) -> tuple[bytes, bytes]:

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
    aes_key = getAndKeepToken().encode()[:32]

    encrypted_bin = AESGCM(aes_key).encrypt(nonce, aes_plaintext, None)

    return (
        encrypted_bin[:-16],  # cyphertext
        encrypted_bin[-16:],  # 16-byte GCM tag appended
    )


def generateWoff2URL(fontMD5: str, glyphSubsets: list[tuple[int, int]]):
    nonce = os.urandom(12)
    (encrypted_data, tag) = genEncryptedData(fontMD5, glyphSubsets, nonce)

    query_string = urllib.parse.urlencode({
        'encryptedFontData': base64.b64encode(encrypted_data),
        'encryptedToken': base64.b64encode(getAndKeepEncryptedToken()),
        'iv': base64.b64encode(nonce),
        'tag': base64.b64encode(tag),
        'fontFormat': 'WOFF2',
        'clientId': CLIENT_ID,
    })

    return 'https://wfpreviewv2.monotype.com/web-font?' + query_string


def loadAndDecompressFont(fontMD5: str, fontName: str = 'myfontsOutput', fontHandle: str = 'myfontsOutput') -> TTFont:
    font_specs = getAndKeepSpecs(fontMD5)
    download_url = generateWoff2URL(
        fontMD5=fontMD5,
        glyphSubsets=getAndKeepGlyphSubsets(fontMD5),
    )

    woff2_data = requests.get(download_url).content

    result_woff2 = TTFont(
        file=BytesIO(initial_bytes=woff2_data),
        recalcBBoxes=False, recalcTimestamp=False,
    )
    result_woff2['name'].names.extend([
        _n_a_m_e.makeName(
            string=fontName, nameID=1,  # fontfamily
            platformID=3, platEncID=1, langID=0x409,
        ),
        _n_a_m_e.makeName(
            string=fontName, nameID=2,  # fontSubfamily
            platformID=3, platEncID=1, langID=0x409,
        ),
        _n_a_m_e.makeName(
            string=fontName, nameID=4,  # fullName
            platformID=3, platEncID=1, langID=0x409,
        ),
        _n_a_m_e.makeName(
            string=fontHandle, nameID=6,  # postScriptName
            platformID=3, platEncID=1, langID=0x409,
        ),
    ])
    for name_obj in result_woff2['name'].names:
        if name_obj.nameID != 5:
            continue
        name_obj.string = name_obj.string.split(b';', 1)[0]
        break

    return result_woff2


def processFontData(data: dict[str, Any]):
    file_path = font['handle'] + '.woff2'
    loadAndDecompressFont(
        fontMD5=data['md5'], fontName=font['name'],
    ).save(file_path)


if __name__ == '__main__':
    fonts = getAndKeepFontNamesAndHashes('regine-font-pizzatypefaces')
    for font in fonts:
        processFontData(font)
