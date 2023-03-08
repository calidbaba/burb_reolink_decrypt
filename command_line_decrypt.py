from Crypto.Cipher import AES
import base64
import hashlib
import sys

#check that all arguments are supplied
if len(sys.argv) < 6:
    print("missing arguments")
    exit(1)

password = sys.argv[1]
nonce = sys.argv[2]
cnonce = sys.argv[3]
iv = sys.argv[4]
decrypt_arg = sys.argv[5]
message = sys.argv[6]

def makeAesObject(nounce, password, cnounce, iv):
    key = hashlib.md5((nounce + "-" + password + "-" + cnounce).encode()).hexdigest().upper()[0:16].encode()
    return AES.new(key, AES.MODE_CFB, iv=iv.encode(), segment_size=128)

def decrypt(aesObject,msg):
    m = aesObject.decrypt(base64.b64decode(msg))
    return m

def encrypt(aesObject, msg):
    m = base64.b64encode(aesObject.encrypt(msg))
    return m
def removeNullBytes(msg):
    return bytes([i for i in msg if i != 0])

aes_object = makeAesObject(nonce, password, cnonce, iv)
if decrypt_arg == "True":
    msg = decrypt(aes_object, message)
    msg = removeNullBytes(msg)
    print(msg.decode("utf-8"))
else:
    msg = encrypt(aes_object, message.encode())
    print(msg.decode("utf-8"))
