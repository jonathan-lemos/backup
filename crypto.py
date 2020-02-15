from typing import Iterable, List, Optional, Tuple, Union
from getpass import getpass
import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from enum import Enum

__backend = default_backend()


class KdfType(Enum):
    PBKDF2 = 0,
    HKDF = 1


class HashType(Enum):
    SHA256 = 0,
    SHA512 = 1,
    SHA3_512 = 2


def __make_key(
        key_len: int,
        salt: bytes,
        iterations: int = 10000,
        passphrase: Optional[str] = None,
        kdf: KdfType = KdfType.PBKDF2,
        hash: HashType = HashType.SHA3_512
):
    if passphrase is None:
        passphrase = getpass("Enter passphrase:")

    kdffunc = {
        KdfType.PBKDF2: PBKDF2HMAC,
        KdfType.HKDF: HKDF
    }[kdf]

    hashfunc = {
        HashType.SHA256: hashes.SHA256,
        HashType.SHA512: hashes.SHA512,
        HashType.SHA3_512: hashes.SHA3_512
    }[hash]

    df = kdffunc(
        algorithm=hashfunc,
        length=key_len,
        salt=salt,
        iterations=iterations,
        backend=__backend
    )

    return df.derive(bytes(passphrase, "utf-8"))


def encrypt(
        input: Union[str, bytes],
        file_out: Optional[str] = None,
        passphrase: Optional[str] = None
) -> Optional[bytearray]:
    salt = os.urandom(16)
    iv = os.urandom(12)
    key = __make_key(32, salt, passphrase=passphrase)

    encryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv),
        backend=__backend
    ).encryptor()

    if isinstance(input, str):
        with open(input, "rb") as rf:
            if file_out:
                with open(file_out, "wb") as wf:
                    wf.write(b'0' * 16)
                    wf.write(iv)
                    wf.write(salt)
                    while len(buf := rf.read(65536)) != 0:
                        wf.write(encryptor.update(buf))
                    wf.write(encryptor.finalize())

                assert len(encryptor.tag) == 16
                with open(file_out, "r+b") as af:
                    af.seek(0)
                    wf.write(encryptor.tag)
                return
            else:
                ba = bytearray()
                ba.extend(iv)
                ba.extend(salt)
                while len(buf := rf.read(65536)) != 0:
                    ba.extend(encryptor.update(buf))
                ba.extend(encryptor.finalize())
                return encryptor.tag + ba
    else:
        if file_out:
            with open(file_out, "wb") as wf:
                wf.write(b'0' * 16)
                wf.write(iv)
                wf.write(salt)
                wf.write(encryptor.update(input))
                wf.write(encryptor.finalize())

            assert len(encryptor.tag) == 16
            with open(file_out, "r+b") as af:
                af.seek(0)
                wf.write(encryptor.tag)
            return
        else:
            ba = bytearray()
            ba.extend(iv)
            ba.extend(salt)
            ba.extend(encryptor.update(input))
            ba.extend(encryptor.finalize())
            return encryptor.tag + ba


def decrypt(
        input: Union[str, bytes],
        file_out: Optional[str] = None,
        passphrase: Optional[str] = None
) -> Optional[bytearray]:
    if isinstance(input, str):
        with open(input, "rb") as rf:
            tag = rf.read(16)
            iv = rf.read(12)
            salt = rf.read(16)

            if len(salt) < 16:
                raise ValueError(f"The file '{input}' is not long enough to have been encrypted with encrypt()")

            key = __make_key(32, salt, passphrase=passphrase)

            decryptor = Cipher(
                algorithms.AES(key),
                modes.GCM(iv, tag),
                backend=__backend
            ).decryptor()

            if file_out:
                with open(file_out, "wb") as wf:
                    while len(buf := rf.read(65536)) != 0:
                        wf.write(decryptor.update(buf))
                    wf.write(decryptor.finalize())
            else:
                ba = bytearray()
                while len(buf := rf.read(65536)) != 0:
                    ba.extend(decryptor.update(buf))
                ba.extend(decryptor.finalize())
                return ba
    else:
        if len(input) < 44:
            raise ValueError("The input byte array is not long enough to have been encrypted with encrypt().")

        tag = input[0:16]
        iv = input[16:28]
        salt = input[28:44]
        remainder = input[44:]

        key = __make_key(32, salt, passphrase=passphrase)

        decryptor = Cipher(
            algorithms.AES(key),
            modes.GCM(iv, tag),
            backend=__backend
        ).decryptor()

        if file_out:
            with open(file_out, "wb") as wf:
                wf.write(decryptor.update(remainder))
                wf.write(decryptor.finalize())
        else:
            ba = bytearray()
            ba.extend(decryptor.update(remainder))
            ba.extend(decryptor.finalize())
            return ba
