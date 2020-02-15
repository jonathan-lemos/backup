from enum import Enum
from typing import Iterable
import zlib
import bz2
import lzma

class CompressionType(Enum):
    @staticmethod
    def fromstring(s: str) -> "CompressionType":
        try:
            return {
                "": CompressionType.NONE,
                "none": CompressionType.NONE,
                "gz": CompressionType.GZIP,
                "gzip": CompressionType.GZIP,
                "bz": CompressionType.BZIP2,
                "bz2": CompressionType.BZIP2,
                "bzip": CompressionType.BZIP2,
                "bzip2": CompressionType.BZIP2,
                "xz": CompressionType.XZ,
                "lzma": CompressionType.XZ
            }[s.lower()]
        except KeyError:
            raise ValueError(f"Compression type '{s}' is not supported.")

    NONE = "",
    GZIP = "gz",
    BZIP2 = "bz2",
    XZ = "xz"


def __compress_gzip(input: Iterable[bytes]):
    pass

