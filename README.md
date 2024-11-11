# zalo-decrypt-backup

Decrypt Zalo backups created by the desktop client.

## Installation

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1  # or activate.bat if on cmd

pip install -r requirements.lock
```

## Usage

Log into the desktop client on the machine you're running this on. Then, run `get_dkey.py`
to get the backup encryption key:

```shell
$ python get_dkey.py
0123456789abcdef0123456789abcdef
```

Then, run `main.py` to decrypt the backup:

```shell
$ python main.py <dkey> </path/to/backup.zl.zip>
```

The backup will be decrypted and extracted to the same folder as the original backup file.


