from typing import Iterable, Union


def combine(*arr: Union[bytes, Iterable[bytes]]) -> bytearray:
    ret = bytearray()
    for b in arr:
        if isinstance(b, bytes):
            ret.extend(b)
        else:
            for ba in b:
                ret.extend(ba)
    return ret


class BufferedReader:
    def __init__(self, arg: Union[Iterable[bytes], str]):
        if isinstance(arg, str):
            self.file = open(self.file, "rb")
            self.bytestream, self.buf = None, None
        else:
            self.file = None
            self.bytestream, self.buf = iter(arg), bytearray()
        self.index = 0

    def __enter__(self):
        return self

    def read(self, length: int = -1) -> bytes:
        if self.file:
            ret = self.file.read(length)
            self.index += len(ret)
            return ret
        elif length < 0:
            return combine(self.buf, self.bytestream)
        else:
            try:
                while len(self.buf) < length and self.bytestream:
                    self.buf.extend(next(self.bytestream))
            except StopIteration:
                pass
            ret = self.buf[:length]
            self.buf = self.buf[length:]
            return ret

    def chunks(self, size: int = 65536) -> Iterable[bytes]:
        while len(buf := self.read(size)) != 0:
            yield buf

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.file:
            self.file.close()
