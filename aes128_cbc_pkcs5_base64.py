#!/usr/bin/env python3

""" 
    Proof of concept decryption and encryption of SecureChatAnywhere data which
    uses AES-128/CBC/PKCS7Padding with Base64 encoding.

    This POC was hacked together with the help of online resources such as 
    Stack Overflow and GitHub, can't remember the source URLs now, sorry.

    Thanks goes to bobchomp for help with this and hanging out on IRC.

    Copyright (C) 2018  Robert V. <modrobert@gmail.com>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""

from base64 import b64decode
from base64 import b64encode
from base64 import b16decode
from Crypto.Cipher import AES
from Crypto import Random

BS = 16

# PKCS5Padding = PKCS7Padding for AES in java land
pad = lambda s: bytes(s + (BS - len(s) % BS) * chr(BS - len(s) % BS), "utf-8")
unpad = lambda s: s[0 : -(s[-1])]


class AESCipher:
    def __init__(self, key):
        """
        Requires hex encoded param as a key
        """
        self.key = b16decode(key.upper())

    def encrypt(self, plaintext):
        """
        Returns Base64 encoded encrypted string
        """
        plaintext = pad(plaintext)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return b64encode(iv + cipher.encrypt(plaintext))

    def decrypt(self, enc):
        """
        Requires bytearray to decrypt
        """
        iv = enc[:16]
        enc = enc[16:]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return unpad(cipher.decrypt(enc))


if __name__ == "__main__":
    hexkey = "76c1019d7c3b70309e97a637088895b8"
    ciphertext = "SCA-dRWopUwYadNur3d0x4MffKReiKWLor+R9VSf4vFypME="
    ciphertext = b64decode(ciphertext[4:])
    key = AESCipher(hexkey)
    # decrypt
    plaintext = key.decrypt(ciphertext)
    print("decrypted: %s" % plaintext)
    # encrypt with new random iv, ct != ciphertext
    pt = "hello bobchomp"
    ct = key.encrypt(pt)
    print("encrypted: SCA-" + ct.decode("utf-8"))
