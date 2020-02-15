import gnupg
from typing import Optional
from getpass import getpass

gpg = gnupg.GPG()
gpg.encoding = 'utf-8'


def encrypt(file_in: str, file_out: Optional[str] = None, passphrase: Optional[str] = None, cipher: str = "AES256"):
    if passphrase is None:
        passphrase = getpass()

    cipher = cipher.upper()
    if cipher not in {"IDEA", "3DES", "CAST5", "BLOWFISH", "AES", "AES192", "AES256", "TWOFISH",
                      "CAMELLIA128", "CAMELLIA192", "CAMELLIA256"}:
        raise ValueError(f"Cipher '{cipher}' is not supported.")

    with open(file_in, "rb") as stream:
        return gpg.encrypt_file(stream, None, symmetric=cipher, output=file_out, passphrase=passphrase)


def decrypt(file_in: str, file_out: Optional[str] = None, passphrase: Optional[str] = None):
    if passphrase is None:
        passphrase = getpass()

    with open(file_in, "rb") as stream:
        return gpg.decrypt_file(stream, output=file_out, passphrase=passphrase)
