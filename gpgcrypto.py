import gnupg
from typing import Optional

gpg = gnupg.GPG()
gpg.encoding = 'utf-8'


def encrypt(file_in: str, file_out: Optional[str] = None):
    return gpg.encrypt(open(file_in, "rb"), None, symmetric="AES256", output=file_out)


def decrypt(file_in: str, file_out: Optional[str] = None):
    return gpg.decrypt(open(file_in, "rb"), symmetric="AES256", output=file_out)