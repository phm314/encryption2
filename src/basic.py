from getpass import getpass
import os
from pathlib import Path
# import sys
import time

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from utils import *

def kdf(salt: bytes):
    _kdf = PBKDF2HMAC(
            algorithm = hashes.SHA256(),
            length = 32,
            salt = salt,
            iterations = 390_000)
    return _kdf

def generateKey(password: bytes, salt: bytes):
    """ generates key to be used in Fernet """
    return kdf(salt).derive(password)

def hashBytes(b: bytes) -> bytes:
    digest = hashes.Hash(hashes.SHA256())
    digest.update(b)
    return digest.finalize()

def clearScreen() -> None:
    os.system("cls")

def main():

    saltPath = Path("salt.txt")
    hashPath = Path("hash.txt")

    # initialize app, create salt & hash files
    if not saltPath.is_file() or not hashPath.is_file():
        if not saltPath.is_file():
            print("creating new salt!")
            saveBytes(saltPath, os.urandom(32))

        if not hashPath.is_file():
            print("create new password")
            print("if you forget this password you will lose access to all encrypted files")
            newPassword = bytes(getpass("new password: "), "utf-8")
            newSalt = loadBytes(saltPath)
            saveBytes(hashPath, hashBytes(newPassword+newSalt))

        print("initialization completed!")
        
    bSalt = loadBytes(saltPath)
    bHash = loadBytes(hashPath)

    while True:
        n = input(">> ")
        if n == "q":
            break
        if n == "l":
            inputPassword = bytes(getpass("password: "), "utf-8")
            nHash = hashBytes(inputPassword+bSalt)
            #print(nHash)

            #compare hash TOOD
            if nHash != bHash:
                print("incorrect password . . .")
                time.sleep(1.5)
                continue

            enterApp(inputPassword, bSalt)

def decryptTokens(f: Fernet, tokenList: list) -> list:
    """ decrypts a list of Fernet encrypted tokens """
    return [f.decrypt(token) for token in tokenList]

def loadTokens(tokenFiles: list[str]):
    """ reads tokenfiles, which are saved as b64 strs """
    return [bytes(loadFile(tfile), "utf-8") for tfile in tokenFiles]

def createMultilineText() -> str:
    lineList = []
    # removes right spaces from lines, keeps blank lines
    print("creating text.\n<ctrl-z> (windows) or <ctrl-d> (linux) to finalize")

    while True:
        try:
            line = input("::")
            lineList.append(line.rstrip())
        except EOFError:
            print("input complete")
            break
    #print(lineList)
    return "\n".join(lineList)

def enterApp(password: bytes, salt: bytes):
    fileDir = Path("tokens")
    if not fileDir.is_dir():
        fileDir.mkdir()

    key = b64_encode(kdf(salt).derive(password))
    f = Fernet(key)

    tokenFiles = fileDir.iterdir()
    eTokens = loadTokens(tokenFiles)
    dTokens = decryptTokens(f, eTokens)
    print(f"{len(dTokens)} tokens successfully decrypted, app entered!")

    while True:
        print("c: create entry, q: close, s: display msg list")
        n = input(">> ")
        if n == "c":
            msg = createMultilineText()
            msg_enc = f.encrypt(bytes(msg, "utf-8"))
            saveBytes(fileDir / Path(f"{int(time.time())}.txt"), msg_enc)

        # DEBUG FUNC
        elif n == "!":
            while (i:=input("!!")) != "":
                exec(i)

        elif n == "q":
            clearScreen()
            print("session closed")
            return 0
        elif n == "s":
            print("displaying tokens:\n")
            for t in dTokens:
                print(t)
            print()

if __name__ == "__main__":
    main()
