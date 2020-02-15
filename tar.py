import tarfile as tar
from options import Compression
from typing import Callable, Iterable, Optional


def make(filenames: Iterable[str],
         out_file: str,
         compression_algo: Compression = Compression.XZ,
         compression_level: Optional[int] = None):
    try:
        cstring = {
            Compression.XZ: "w:xz",
            Compression.GZIP: "w:gz",
            Compression.BZIP2: "w:bz2",
            Compression.NONE: "w"
        }[compression_algo]
    except KeyError:
        raise ValueError(f"Given compression algorithm '{compression_algo}' is not supported.")

    with tar.open(out_file, f"w{cstring}", compresslevel=compression_level)\
            if compression_level is not None\
        else tar.open(out_file, f"w{cstring}") as t:
        for i, filename in enumerate(filenames):
            t.add(filename)


def extract(in_file: str, out_dir: str = "."):
    with tar.open(in_file) as t:
        t.extractall(out_dir)
