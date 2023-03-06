from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64
import hashlib
import sys

#check that all arguments are supplied
if len(sys.argv) < 6:
    print("missing arguments")
    exit(1)

#carlerkul2 5dd1d26374f4c599a45e1bf7a05b1026df8a1ed82dce267c eaad082f442e554bb6a86b8a3e794812b35afcd55e4aa2b0 bcswebapp1234567 True tKgdR4KenWB4NE1K+52qpalnG80GYrUJJ7WHfGSjYfCKpUcyLhznYCN1uWcFn5tjgNypE6qvUjRIUjtkdjBCPlp4RvJJDql+Ech+YUQZujpKE71POzRrC+7lnWYDKkaP+nP/ZQJPYXQ/nB6JAYUjQO/qoqAzIOakGYm/tWdMt80=

# missing arguments

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
    # print(msg.rstrip().decode("utf-8"))
else:
    msg = encrypt(aes_object, message.encode())
    print(msg.decode("utf-8"))