""" this module contains non-cryptographic helper functions, such as basic I/O, b64 encoding, etc. """

import base64

def loadFile(fname: str):
    with open(fname, "r") as infile:
        return infile.read()

def saveFile(fname: str, s: str):
    with open(fname, "w") as outfile:
        outfile.write(s)

def saveBytes(fname: str, b: bytes):
    with open(fname, "wb") as outfile:
        outfile.write(b)

def loadBytes(fname: str):
    with open(fname, "rb") as infile:
        return infile.read()

def b64_encode(b: bytes):
    return base64.urlsafe_b64encode(b)

def b64_deocde(s: str):
    return base64.urlsafe_b64decode(s)
