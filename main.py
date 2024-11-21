import argparse
import hashlib
import os
import sys
import tarfile
import tempfile
from pathlib import Path

from Crypto.Cipher import AES

parser = argparse.ArgumentParser()
_ = parser.add_argument("dkey", type=str.encode, help="Decryption key")
_ = parser.add_argument("path", type=Path, help="Path to encrypted backup")

args = parser.parse_args()
dkey: bytes = args.dkey  # pyright: ignore[reportAny]
path: Path = args.path  # pyright: ignore[reportAny]

key = hashlib.sha256(dkey).digest()

if len(path.suffixes) == 1:
    iv = b"\x00" * 16
else:
    iv = b"zie" + dkey[:13]

cipher = AES.new(key, AES.MODE_CBC, iv)  # pyright: ignore[reportUnknownMemberType]

fd, temp = tempfile.mkstemp()
print(temp)
os.close(fd)

with path.open("rb") as fi, open(temp, "wb") as fout:
    while True:
        chunk = fi.read(1048576)

        if not chunk:
            break

        _ = fout.write(cipher.decrypt(chunk))

output = path

while len(output.suffixes) > 0:
    output = output.with_suffix("")

output.mkdir(parents=True, exist_ok=True)

with tarfile.TarFile(temp) as tar:
    if sys.version_info >= (3, 12):
        tar.extractall(output, filter="data")
    else:
        tar.extractall(output)

os.unlink(temp)
