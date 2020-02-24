import argparse
import os
import secrets
import sys
from bufferedreader import BufferedReader
from enum import Enum
from getpass import getpass
from typing import Callable, Dict, Iterable, Optional, Tuple, Union

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.padding import PKCS7


class CipherType(Enum):
    AES = {
        "name": "AES",
        "key_sizes": [128, 192, 256],
        "algorithm": algorithms.AES,
        "block_cipher": True,
        "block_size": 16,
    }
    CAMELLIA = {
        "name": "CAMELLIA",
        "key_sizes": [128, 192, 256],
        "algorithm": algorithms.Camellia,
        "block_cipher": True,
        "block_size": 16
    }
    CAST5 = {
        "name": "CAST5",
        "key_sizes": list(range(40, 128 + 1, 8)),
        "algorithm": algorithms.CAST5,
        "block_cipher": True,
        "block_size": 8
    }
    SEED = {
        "name": "SEED",
        "key_sizes": [128],
        "algorithm": algorithms.SEED,
        "block_cipher": True,
        "block_size": 8
    }


class BlockCipherModeType(Enum):
    CBC = {
        "name": "CBC",
        "algorithm": modes.CBC,
        "auth_tag": None,
        "padded": True
    }
    CTR = {
        "name": "CTR",
        "algorithm": modes.CTR,
        "auth_tag": None,
        "padded": False
    }
    OFB = {
        "name": "OFB",
        "algorithm": modes.OFB,
        "auth_tag": None,
        "padded": False
    }
    CFB = {
        "name": "CFB",
        "algorithm": modes.CFB,
        "auth_tag": None,
        "padded": False
    }
    GCM = {
        "name": "GCM",
        "algorithm": modes.GCM,
        "auth_tag": 16,
        "padded": False
    }


class KdfType(Enum):
    PBKDF2 = {
        "name": "PBKDF2",
        "algorithm": PBKDF2HMAC
    }
    HKDF = {
        "name": "HKDF",
        "algorithm": HKDF
    }


class HashType(Enum):
    SHA256 = {
        "name": "SHA256",
        "algorithm": hashes.SHA256
    }
    SHA512 = {
        "name": "SHA512",
        "algorithm": hashes.SHA512
    }
    SHA3_512 = {
        "name": "SHA3_512",
        "algorithm": hashes.SHA3_512
    }


__backend = default_backend()
__cipher_dict = {x.name: x.value for x in CipherType}
__mode_dict = {x.name: x.value for x in BlockCipherModeType}


def __supported_ciphers() -> Dict[str, Tuple[Dict, int, Optional[Dict]]]:
    ret = {}
    for cipher in __cipher_dict:
        for key_size in __cipher_dict[cipher]["key_sizes"]:
            if __cipher_dict[cipher]["block_cipher"]:
                for mode in __mode_dict:
                    if __backend.cipher_supported(__cipher_dict[cipher]["algorithm"](b"0" * (key_size // 8)), __mode_dict[mode]["algorithm"](b"0" * __cipher_dict[cipher]["block_size"])):
                        ret[f"{cipher}-{key_size}-{mode}"] = (__cipher_dict[cipher], key_size, __mode_dict[mode])
            else:
                if __backend.cipher_supported(__cipher_dict[cipher]["algorithm"](b"0" * (key_size // 8)), None):
                    ret[f"{cipher}-{key_size}"] = (__cipher_dict[cipher], key_size, None)
    return ret


__ciphers = __supported_ciphers()
__kdfs = {x.name: x.value for x in KdfType}
__hashtypes = {x.name: x.value for x in HashType}


def cipher_list() -> Iterable[str]:
    return iter(__ciphers)


def kdf_list() -> Iterable[str]:
    return iter(__kdfs)


def hash_list() -> Iterable[str]:
    return iter(__hashtypes)


def __rand_bytes(length: int) -> bytes:
    return secrets.token_bytes(length)


def __make_key(
        salt: bytes,
        kdf: Callable,
        hashfunc: Callable,
        key_len: int,
        iterations: int,
) -> bytes:
    if (passphrase := os.environ.get("PASSPHRASE")) is None:
        passphrase = getpass("Enter passphrase: ")

    df = kdf(
        algorithm=hashfunc,
        length=key_len // 8,
        salt=salt,
        iterations=iterations,
        backend=__backend
    )

    return df.derive(bytes(passphrase, "utf-8"))


def __get_meta(cipher: str, kdf: str, hashfunc: str) -> Tuple[Dict, int, Dict, Dict, Dict]:
    try:
        cipher, key_len, mode = __ciphers[cipher.upper()]
    except KeyError:
        raise ValueError(f"Invalid cipher '{cipher}'. Must be one of: {', '.join(cipher_list())}")

    try:
        kdf = __kdfs[kdf.upper()]
    except KeyError:
        raise ValueError(f"Invalid KDF '{kdf}'. Must be one of: {' '.join(kdf_list())}")

    try:
        hashfunc = __hashtypes[hashfunc.upper()]
    except KeyError:
        raise ValueError(f"Invalid hash function '{hashfunc}'. Must be one of {' '.join(hash_list())}.")

    return cipher, key_len, mode, kdf, hashfunc


def __encrypt(
        input: Union[str, Iterable[bytes]],
        cipher: str = "AES-256-GCM",
        kdf: str = "PBKDF2",
        hashfunc: str = "SHA3_512",
        salt: Optional[bytes] = None,
        iv: Optional[bytes] = None,
        iterations: int = 100000,
        buf_size: int = 65536
) -> Iterable[bytes]:
    with BufferedReader(input) as istream:

        cipher, key_len, mode, kdf, hashfunc = __get_meta(cipher, kdf, hashfunc)

        if salt is None:
            salt = __rand_bytes(16)
        if iv is None:
            iv = __rand_bytes(cipher["block_size"])
        key = __make_key(salt, kdf["algorithm"], hashfunc["algorithm"], key_len, iterations)

        encryptor = Cipher(
            cipher["algorithm"](key),
            mode["algorithm"](iv) if mode else None,
            backend=__backend
        ).encryptor()

        yield len(salt).to_bytes(2, byteorder="little")
        yield salt
        if mode:
            yield iv

        padder = PKCS7(cipher["block_size"] * 8).padder()

        for buf in istream.chunks(buf_size):
            if mode["padded"]:
                yield encryptor.update(padder.update(buf))
            else:
                yield encryptor.update(buf)

        if mode["padded"]:
            yield encryptor.update(padder.finalize())
        yield encryptor.finalize()

        if mode["auth_tag"]:
            yield encryptor.tag


def encrypt(
        input: Union[str, Iterable[bytes]],
        output_file: Optional[str] = None,
        cipher: str = "AES-256-GCM",
        kdf: str = "PBKDF2",
        hashfunc: str = "SHA3_512",
        salt: Optional[bytes] = None,
        iv: Optional[bytes] = None,
        iterations: int = 100000,
        buf_size: int = 65536
) -> Optional[Iterable[bytes]]:
    if output_file:
        with open(output_file, "wb") as f:
            for buf in __encrypt(input, cipher, kdf, hashfunc, salt, iv, iterations, buf_size):
                f.write(buf)
    else:
        return __encrypt(input, cipher, kdf, hashfunc, salt, iv, iterations, buf_size)


def __decrypt(
        input: Union[str, Iterable[bytes]],
        cipher: str = "AES-256-GCM",
        kdf: str = "PBKDF2",
        hashfunc: str = "SHA3_512",
        iterations: int = 100000,
        buf_size: int = 65536
) -> Iterable[bytes]:
    with BufferedReader(input) as istream:

        cipher, key_len, mode, kdf, hashfunc = __get_meta(cipher, kdf, hashfunc)

        salt_len = int.from_bytes(istream.read(2), byteorder="little")
        salt = istream.read(salt_len)
        if len(salt) != salt_len:
            raise ValueError(
                f"Expected a salt of length {salt_len} but the file is not long enough. Most likely the file is corrupted or not encrypted using this cipher.")

        key = __make_key(salt, kdf["algorithm"], hashfunc["algorithm"], key_len, iterations)

        if mode:
            iv = istream.read(cipher["block_size"])
        else:
            iv = None

        decryptor = Cipher(
            cipher["algorithm"](key),
            mode["algorithm"](iv) if mode else None,
            backend=__backend
        ).decryptor()

        unpadder = PKCS7(cipher["block_size"] * 8).unpadder()

        buf = None
        while len(buf2 := istream.read(buf_size)) != 0:
            if buf:
                if mode["padded"]:
                    yield unpadder.update(decryptor.update(buf))
                else:
                    yield decryptor.update(buf)
            buf = buf2
        if mode["auth_tag"]:
            try:
                if mode["padded"]:
                    yield unpadder.update(decryptor.update(buf[:-mode["auth_tag"]]))
                    yield unpadder.update(decryptor.finalize_with_tag(buf[-mode["auth_tag"]:]))
                    yield unpadder.finalize()
                else:
                    yield decryptor.update(buf[:-mode["auth_tag"]])
                    yield decryptor.finalize_with_tag(buf[-mode["auth_tag"]:])
            except InvalidTag as e:
                raise ValueError("\nThe authentication token could not be verified. Most likely the data is corrupt or was not encrypted using the given cipher.") from e
        else:
            if mode["padded"]:
                yield unpadder.update(decryptor.update(buf))
                yield unpadder.update(decryptor.finalize())
                try:
                    yield unpadder.finalize()
                except ValueError as e:
                    raise ValueError("Could not finalize padding. Most likely the file is corrupt or was not encrypted using the given cipher.") from e
            else:
                yield decryptor.update(buf)
                yield decryptor.finalize()


def decrypt(
        input: Union[str, Iterable[bytes]],
        output_file: Optional[str] = None,
        cipher: str = "AES-256-GCM",
        kdf: str = "PBKDF2",
        hashfunc: str = "SHA3_512",
        salt: Optional[bytes] = None,
        iv: Optional[bytes] = None,
        iterations: int = 100000,
        buf_size: int = 65536
) -> Optional[Iterable[bytes]]:
    if output_file:
        with open(output_file, "wb") as f:
            for buf in __decrypt(input, cipher, kdf, hashfunc, iterations, buf_size):
                f.write(buf)
    else:
        return __decrypt(input, cipher, kdf, hashfunc, iterations, buf_size)


def main():
    parser = argparse.ArgumentParser(
        description="Encrypts or decrypts input. The $PASSPHRASE environment variable can be set to specify the password if you don't want to type it in.")
    parser.add_argument("action",
                        metavar="ACTION",
                        help="'enc' to encrypt, 'dec' to decrypt, 'ciphers' to list ciphers, 'hashes' to list hash functions, 'kdfs' to list kdfs.")
    parser.add_argument("-c", "--cipher",
                        dest="cipher",
                        metavar="CIPHER",
                        help="the encryption cipher to use (default 'AES-256-GCM')",
                        default="AES-256-GCM")
    parser.add_argument("-kdf", "--key-derivation",
                        dest="kdf",
                        metavar="KDF",
                        help="the key derivation function to use (default 'PBKDF2')",
                        default="PBKDF2")
    parser.add_argument("-kh", "--key-hash",
                        dest="key_hash",
                        metavar="HASH",
                        help="the hash function to use with the kdf (default 'SHA256')",
                        default="SHA256"),
    parser.add_argument("-ki", "--key-iterations",
                        type=int,
                        dest="key_iterations",
                        metavar="ITERATIONS",
                        help="the number of iterations the kdf should perform (default '100000')",
                        default=100000)
    parser.add_argument("-in", "--input",
                        dest="input",
                        metavar="FILE",
                        help="a file to encrypt. by default input is taken from stdin",
                        default=None)
    parser.add_argument("-iv", "--initialization-vector",
                        dest="initialization_vector",
                        metavar="IV",
                        help="the IV to use (with certain cipher modes). by default this is a randomly generated value of the correct length for the supplied cipher.",
                        default=None)
    parser.add_argument("-out", "--output",
                        dest="output",
                        metavar="FILE",
                        help="the file to output to. by default output is written to stdout",
                        default=None)
    parser.add_argument("-s", "--salt",
                        dest="salt",
                        metavar="SALT",
                        help="the salt to use with the kdf. by default this is a randomly generated 128-bit value.",
                        default=None)
    parser.add_argument("-v", "--verbose",
                        action="store_true",
                        dest="verbose",
                        help="display information to stderr",
                        default=False)

    options = parser.parse_args()

    actions = ["enc", "dec", "ciphers", "hashes", "kdfs"]
    if options.action not in actions:
        print(f"Action must be one of {actions}. Was '{options.action}'.", file=sys.stderr)
        exit(1)

    if options.action == "ciphers":
        print("\n".join(cipher_list()))
        exit(0)

    if options.action == "hashes":
        print("\n".join(hash_list()))
        exit(0)

    if options.action == "kdfs":
        print("\n".join(kdf_list()))
        exit(0)

    params = (options.input, options.output, options.cipher, options.kdf, options.key_hash, bytes(options.salt, "utf-8") if options.salt else None, bytes(options.initialization_vector, "utf-8") if options.initialization_vector else None, options.key_iterations)

    if options.action == "enc":
        encrypt(*params)
    else:
        decrypt(*params)


if __name__ == "__main__":
    main()
