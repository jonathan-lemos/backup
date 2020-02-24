import unittest
import os
from bufferedreader import combine, BufferedReader


class TestBufferedReader(unittest.TestCase):
    def tearDown(self) -> None:
        try:
            os.remove("test.txt")
        except FileNotFoundError:
            pass

    def test_file(self):
        testcontent1 = b"send nodes"
        testcontent2 = b"abcdef" * 100000

        with open("test.txt", "wb") as file:
            file.write(testcontent1)

        with BufferedReader("test.txt") as br:
            self.assertEqual(bytes(combine(br.chunks(1))), testcontent1)
        with BufferedReader("test.txt") as br:
            self.assertEqual(bytes(combine(br.chunks())), testcontent1)

        with open("test.txt", "wb") as file:
            file.write(testcontent2)

        with BufferedReader("test.txt") as br:
            self.assertEqual(bytes(combine(br.chunks(8))), testcontent2)

    def test_stream(self):
        def stream1():
            yield b"yeetus"

        def stream2():
            yield b"yeetus"
            for i in range(10):
                yield bytes(str(10 - i), "utf-8") + b"amdyolo" * 10000 + bytes(str(i), "utf-8")
            yield b"done"

        with BufferedReader(stream1()) as br:
            self.assertEqual(bytes(combine(stream1())), bytes(combine(br.chunks())))

        with BufferedReader(stream1()) as br:
            self.assertEqual(bytes(combine(stream1())), bytes(combine(br.chunks(1))))

        with BufferedReader(stream2()) as br:
            self.assertEqual(bytes(combine(stream2())), bytes(combine(br.chunks())))

        with BufferedReader(stream2()) as br:
            self.assertEqual(bytes(combine(stream2())), bytes(combine(br.chunks(7))))

    def test_thicc(self):
        test = b"amdyolo" * 1024 * 1024

        def stream():
            for _ in range(100):
                yield test

        with BufferedReader(stream()) as br:
            self.assertEqual(combine(br.chunks()), test * 100)
