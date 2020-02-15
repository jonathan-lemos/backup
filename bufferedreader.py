from typing import Iterable, Union


def combine(arr: Iterable[bytes]) -> bytearray:
    ret = bytearray()
    for b in arr:
        ret.extend(b)
    return ret


class BufferedReader:
    def __init__(self, arg: Union[bytes, str]):
        if isinstance(arg, str):
            self.file, self.bytes = open(self.file, "rb"), None
        else:
            self.file, self.bytes = None, arg
        self.index = 0

    def __enter__(self):
        return self

    def read(self, length: int = -1) -> bytes:
        if self.file:
            buf = self.file.read(length)
            self.index += len(buf)
            return buf
        else:
            buf = self.bytes[self.index:self.index+length]
            self.index += length
            return buf

    def chunks(self, size: int = 65536) -> Iterable[bytes]:
        while len(buf := self.read(size)) != 0:
            yield buf

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.file:
            self.file.close()
