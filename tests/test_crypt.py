import unittest
from crypt import encrypt, decrypt
from bufferedreader import BufferedReader, combine
import os


class TestCrypt(unittest.TestCase):
    def tearDown(self) -> None:
        for file in ["test.txt", "test2.txt", "test3.txt"]:
            try:
                os.remove(file)
            except FileNotFoundError:
                pass

    def test_default(self):
        buf1 = b"yeetus"
        buf2 = b"amdyolo" * 100000

        os.environ["PASSPHRASE"] = "deez nuts"
        enc = combine(encrypt(buf1))
        dec = decrypt(enc)

        self.assertEqual(buf1, combine(dec))

        enc = combine(encrypt(buf2))
        dec = decrypt(enc)

        self.assertEqual(buf2, combine(dec))

        enc = combine(encrypt(buf1))
        os.environ["PASSPHRASE"] = "got em"
        try:
            dec = decrypt(enc)
            self.assertNotEqual(buf1, combine(dec))
        except ValueError:
            pass
        else:
            self.fail("Decryption should have failed with differing passwords.")

        os.environ["PASSPHRASE"] = "deez nuts"
        enc = combine(encrypt(buf2))
        os.environ["PASSPHRASE"] = "got em"
        try:
            dec = decrypt(enc)
            self.assertNotEqual(buf2, combine(dec))
        except ValueError:
            pass
        else:
            self.fail("Decryption should have failed with differing passwords.")

    def test_file(self):
        os.environ["PASSPHRASE"] = "deez nuts"

        buf = b"amdyolo" * 100000

        encrypt(buf, output_file="test.txt")
        dec = decrypt("test.txt")

        self.assertEqual(buf, combine(dec))

        with open("test.txt", "wb") as f:
            f.write(buf)

        encrypt("test.txt", output_file="test2.txt")
        decrypt("test2.txt", output_file="test3.txt")

        with BufferedReader("test3.txt") as br:
            self.assertEqual(buf, combine(br.chunks()))

        with open("text.txt", "wb") as f:
            f.write(buf)

        enc = encrypt("test.txt")
        decrypt(enc, output_file="test2.txt")

        with BufferedReader("test2.txt") as br:
            self.assertEqual(buf, combine(br.chunks()))

    def test_ciphers(self):
        for cipher in ["AES-256-GCM", "CAMELLIA-256-GCM", "AES-256-CBC", "SEED-128-CTR"]:
            buf1 = b"yeetus"
            buf2 = b"amdyolo" * 100000

            os.environ["PASSPHRASE"] = "deez nuts"
            enc = combine(encrypt(buf1, cipher=cipher))
            dec = decrypt(enc, cipher=cipher)

            self.assertEqual(buf1, combine(dec))

            enc = combine(encrypt(buf2, cipher=cipher))
            dec = decrypt(enc, cipher=cipher)

            self.assertEqual(buf2, combine(dec))

            enc = combine(encrypt(buf1, cipher=cipher))
            os.environ["PASSPHRASE"] = "got em"
            try:
                dec = decrypt(enc, cipher=cipher)
                self.assertNotEqual(buf1, combine(dec))
            except ValueError:
                pass
            else:
                self.fail("Decryption should have failed with differing passwords.")

            os.environ["PASSPHRASE"] = "deez nuts"
            enc = combine(encrypt(buf2, cipher=cipher))
            os.environ["PASSPHRASE"] = "got em"
            try:
                dec = decrypt(enc, cipher=cipher)
                self.assertNotEqual(buf2, combine(dec))
            except ValueError:
                pass
            else:
                self.fail("Decryption should have failed with differing passwords.")
