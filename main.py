import os
import re
import signal
import zlib
from datetime import datetime
from functools import reduce
from typing import Callable, Collection, Iterable, Pattern, Union

import gpgcrypto
import tar
from metadata import Metadata
from options import Compression, Options

opt = Options()


def file_iter(base: Union[str, Iterable[str]]) -> Iterable[str]:
    if isinstance(base, str):
        base = [base]
    for path in base:
        for path, dirs, files in os.walk(path):
            yield from (os.path.join(path, file) for file in files)


def tar_iter(base: Union[str, Iterable[str]], excl: Collection[Pattern],
             callback: Union[Callable[[str], bool], Callable[[str], None], None] = None):
    for file in file_iter(base):
        if any(pat.fullmatch(file) for pat in excl):
            continue
        if callback:
            res = callback(file)
            if res is False:
                continue
        yield file


def gen_filename(compression_algo: Compression):
    dt = datetime.now()

    ext = {
        Compression.NONE: ".tar",
        Compression.GZIP: ".tar.gz",
        Compression.BZIP2: ".tar.bz2",
        Compression.XZ: ".tar.xz"
    }[compression_algo]

    return f"backup-{dt.year}-{str(dt.month).zfill(2)}-{str(dt.day).zfill(2)}-{str(dt.hour).zfill(2)}-{str(dt.minute).zfill(2)}-{str(dt.second).zfill(2)}{ext}"


if __name__ == "__main__":
    meta = Metadata()

    if not os.path.exists(opt.output_dir):
        os.mkdir(opt.output_dir)
    if not os.path.isdir(opt.output_dir):
        raise ValueError(f"Given output directory '{opt.output_dir}' is not a directory.")

    try:
        backup_meta = reduce(lambda a, c: a if a > c else c, filter(
            lambda path: os.path.isfile(path) and re.fullmatch(
                r"backup-\d{4}-\d{2}-\d{2}-\d{2}-\d{2}-\d{2}\.tar(\.xz|\.gz|\.bz2)?\.meta\.gpg",
                os.path.basename(path)), os.listdir(opt.output_dir)))
        backup = backup_meta.replace(".meta", "")
        if not os.path.isfile(backup):

        print(f"Most recent backup is {backup}. Making an incremental backup based on it.")
    except TypeError:
        backup = None

    filename = os.path.join(opt.output_dir, gen_filename(opt.compression_algo))
    metaname = filename + ".meta"
    filename_crypt = filename + ".gpg"
    metaname_crypt = filename + ".meta"


    def cleanup(sig, frame):
        try:
            os.remove(filename)
        except FileNotFoundError:
            pass
        try:
            os.remove(metaname)
        except FileNotFoundError:
            pass
        try:
            os.remove(filename_crypt)
        except FileNotFoundError:
            pass
        try:
            os.remove(metaname_crypt)
        except FileNotFoundError:
            pass


    signal.signal(signal.SIGINT, cleanup)

    try:

        def tar_cb(file: str):
            if os.path.getmtime(file)

            print(file)
            meta.add(file)


        tar.make(tar_iter(opt.dirs, opt.exclude_list, tar_cb),
                 filename,
                 compression_algo=opt.compression_algo,
                 compression_level=opt.compression_level)

        with open(metaname, "wb") as file:
            contents = zlib.compress(meta.serialize(), 9)
            file.write(contents)

        gpgcrypto.encrypt(filename, filename_crypt)
        gpgcrypto.encrypt(metaname, metaname_crypt)
    except Exception as e:
        cleanup(None, None)
        raise e
