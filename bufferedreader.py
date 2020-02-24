from typing import Iterable, Union


def combine(*arr: Union[bytes, Iterable[bytes]]) -> bytes:
    def args():
        for b in arr:
            if isinstance(b, bytes):
                yield b
            else:
                for ba in b:
                    yield ba
    return b"".join(args())


class BufferedReader:
    def __init__(self, arg: Union[bytes, Iterable[bytes], str]):
        if isinstance(arg, str):
            self.file = open(arg, "rb")
            self.bytestream, self.buf = None, None
        elif isinstance(arg, bytes):
            self.file = None
            self.bytestream, self.buf = iter([arg]), bytearray()
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
            return bytes(ret)

    def chunks(self, size: int = 65536) -> Iterable[bytes]:
        while len(buf := self.read(size)) != 0:
            yield buf

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.file:
            self.file.close()
