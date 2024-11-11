import base64
import hashlib
import json
import os
import platform
import re
import secrets
import sqlite3
import time
from http import cookiejar
from pathlib import Path
from typing import Any, TypedDict, cast
from urllib.parse import urlencode

import httpx
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from win32crypt import CryptUnprotectData  # pyright: ignore[reportUnknownVariableType]
from win32cryptcon import CRYPTPROTECT_UI_FORBIDDEN

API_TYPE = 24
CLIENT_VERSION = 647  # 24.11.1
ZCID_ENC_KEY = b"3FC4F0D2AB50057BCE0D90D9187A22B1"

# it's a UUID + md5(userAgent)
RE_IMEI = re.compile(
    rb"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}-[0-9a-f]{32}"
)


class LocalStateOsCrypt(TypedDict):
    encrypted_key: str


class LocalState(TypedDict):
    os_crypt: LocalStateOsCrypt


def sign_request_params(request_name: str, params: dict[str, Any]):
    data = f"zsecure{request_name}"

    for key in sorted(params.keys()):
        data += str(params[key])

    return hashlib.md5(data.encode()).hexdigest()


def create_zcid(api_type: int, unique_client_id: str, request_time: int | None = None):
    if request_time is None:
        request_time = int(time.time() * 1000)

    cipher = AES.new(ZCID_ENC_KEY, AES.MODE_CBC, b"\x00" * 16)  # pyright: ignore[reportUnknownMemberType]

    return (
        cipher.encrypt(
            pad(f"{api_type},{unique_client_id},{request_time}".encode(), 16)
        )
        .hex()
        .upper()
    )


def derive_encryption_key(zcid: str, zcid_ext: str):
    zcid_ext_hash = hashlib.md5(zcid_ext.encode()).hexdigest().upper()
    zcid_ext_hash_even = ""

    for i in range(0, len(zcid_ext_hash), 2):
        zcid_ext_hash_even += zcid_ext_hash[i]

    zcid_even = ""
    zcid_odd_rev = ""

    for i, c in enumerate(zcid):
        if i % 2 == 0:
            zcid_even += c
        else:
            zcid_odd_rev = c + zcid_odd_rev

    return zcid_ext_hash_even[0:8] + zcid_even[0:12] + zcid_odd_rev[0:12]


zalo_data = Path(os.environ["APPDATA"]) / "ZaloData"
local_state_path = zalo_data / "Local State"
local_storage_path = zalo_data / "Partitions" / "zalo" / "Local Storage" / "leveldb"
cookies_db_path = zalo_data / "Partitions" / "zalo" / "Network" / "Cookies"

with local_state_path.open(encoding="utf-8") as f:
    local_state: LocalState = json.load(f)
    encrypted_key = base64.b64decode(local_state["os_crypt"]["encrypted_key"].encode())
    _, key = cast(
        tuple[str, bytes],
        CryptUnprotectData(
            encrypted_key[5:], None, None, None, CRYPTPROTECT_UI_FORBIDDEN
        ),
    )

imei = None

for file in local_storage_path.glob("*.ldb"):
    with file.open("rb") as f:
        data = f.read()

        if (match := RE_IMEI.search(data)) and imei is None:
            imei = match.group(0).decode()


if imei is None:
    print("Could not find device identifier in local storage")
    exit(0)

cookies_db = sqlite3.connect(cookies_db_path)
(encrypted_token,) = cast(
    tuple[bytes],
    cookies_db.execute(
        "SELECT encrypted_value FROM cookies WHERE host_key = '.chat.zalo.me' AND name = 'zpw_sek'"
    ).fetchone(),
)
nonce = encrypted_token[3:15]
tag = encrypted_token[-16:]
ciphertext = encrypted_token[15:-16]
cipher = AES.new(key, AES.MODE_GCM, nonce)  # pyright: ignore[reportUnknownMemberType]
token = cipher.decrypt_and_verify(ciphertext, tag).decode()

client = httpx.Client(verify=False, cookies=cookiejar.CookieJar())
client.cookies.set("zpw_sek", token, ".chat.zalo.me", "/")
client.headers.update(
    {
        "accept-language": "en-US",
        "user-agent": f"ZaloPC-win32-{API_TYPE}v{CLIENT_VERSION}",
        "sec-ch-ua": '"Not?A_Brand";v="8", "Chromium";v="108"',
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": '"Windows"',
    }
)

params = json.dumps(
    {
        "imei": imei,
        "computer_name": platform.node(),
        "language": "vi",
        "ts": int(time.time() * 1000),
    },
    separators=(",", ":"),
).encode()
zcid = create_zcid(API_TYPE, imei)
zcid_ext = secrets.token_hex(3)
key = derive_encryption_key(zcid, zcid_ext).encode()
iv = b"\x00" * 16

query_params = {
    "zcid": zcid,
    "zcid_ext": zcid_ext,
    "enc_ver": "v2",
    "params": base64.b64encode(AES.new(key, AES.MODE_CBC, iv).encrypt(pad(params, 16))),  # pyright: ignore[reportUnknownMemberType]
    "type": API_TYPE,
    "client_version": CLIENT_VERSION,
}
query_params["signkey"] = sign_request_params("getlogininfo", query_params)

resp = client.get(
    f"https://wpa.chat.zalo.me/api/login/getLoginInfo?{urlencode(query_params)}",
    headers={
        "accept": "application/json, text/plain, */*",
        "content-type": "application/x-www-form-urlencoded",
        "sec-fetch-site": "cross-site",
        "sec-fetch-mode": "cors",
        "sec-fetch-dest": "empty",
    },
)
data = json.loads(
    unpad(
        AES.new(key, AES.MODE_CBC, iv).decrypt(  # pyright: ignore[reportUnknownMemberType]
            base64.b64decode(resp.json()["data"].encode())  # pyright: ignore[reportAny]
        ),
        16,
    )
)
print(data["data"]["dkey"])
