import argparse
import os
import re
from enum import Enum
from typing import List, Pattern

VERSION = "1.0"


def truepath(s: str):
    return os.path.abspath(os.path.expanduser(s))


class Compression(Enum):
    NONE = "",
    GZIP = ".gz",
    BZIP2 = ".bz2",
    XZ = "xz"



class Options:
    def __init__(self):
        parser = argparse.ArgumentParser(description="A backup script.")
        parser.add_argument("dirs",
                            metavar="DIRECTORY",
                            nargs="*",
                            help="zero or more directories to back up.")
        parser.add_argument("-c", "--compression-algo",
                            dest="compression_algo",
                            metavar="ALGO",
                            help="a compression algorithm to use. must be one of ['gzip', 'bzip2', 'xz', 'none'] (default: 'xz').",
                            default="xz")
        parser.add_argument("-cl", "--compression-level",
                            dest="compression_level",
                            type=int,
                            metavar="LEVEL",
                            help="the compression level to use from 1-9",
                            default=None)
        parser.add_argument("-e", "--encryption-cipher",
                            dest="encryption_cipher",
                            metavar="CIPHER",
                            help="the gpg symmetric encryption cipher to use (default 'AES256')",
                            default="AES256")
        parser.add_argument("-i", "--include-list",
                            dest="include_list",
                            metavar="LIST",
                            help="a list of paths to include",
                            default=None)
        parser.add_argument("-o", "--output-dir",
                            dest="output_dir",
                            metavar="DIR",
                            help="the directory to output to (default '~/Backups').",
                            default="~/Backups")
        parser.add_argument("-x", "--exclude-list",
                            dest="exclude_list",
                            metavar="LIST",
                            help="a list of regular expressions to exclude",
                            default=None)

        args = parser.parse_args()
        self.dirs: List[str] = [truepath(path) for path in args.dirs]
        self.dirs += [] if args.include_list is None else [truepath(line) for line in
                                                           open(args.include_list, "r")]

        self.compression_algo: Compression = {
            "xz": Compression.XZ,
            "lzma": Compression.XZ,
            "gzip": Compression.GZIP,
            "gz": Compression.GZIP,
            "bzip": Compression.BZIP2,
            "bz2": Compression.BZIP2,
            "bzip2": Compression.BZIP2,
            "": Compression.NONE,
            "none": Compression.NONE
        }[args.compression_algo.lower()]

        self.compression_level: int = args.compression_level
        self.exclude_list: List[Pattern] = [] if args.exclude_list is None else [re.compile(pat) for pat in args.exclude_list]
        self.output_dir: str = args.output_dir
