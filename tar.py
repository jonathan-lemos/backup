import tarfile as tar
import asyncio
from typing import Callable, Iterable, Optional


def make(filenames: Iterable[str], out_file: str, callback: Optional[Callable[[str, int], bool]] = None):
    with tar.open(out_file, "w:xz", compressionlevel=3) as t:
        for i, filename in enumerate(filenames):
            if callback:
                if not callback(filename, i):
                    break
            t.add(filename)


def extract(in_file: str, out_dir: str = "."):
    with tar.open(in_file) as t:
        t.extractall(out_dir)

