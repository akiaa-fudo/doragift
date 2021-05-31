import base64
from getpass import getpass
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from Crypto.Util import Padding
import sys


def get_passphrase():
    passphrase = getpass('enter passphrase: \n')
    pass_confirm = getpass('confirm passphrase: \n')
    if passphrase == pass_confirm:
        return passphrase
    else:
        print('passwords do not match.')
        sys.exit(1)


def gen_key():
    password = get_passphrase()
    salt = b'\xd8~\xafLl3?\xbf\xc9\xe3\xc9`\x99\xef\x01\xff'
    secret_key = PBKDF2(password, salt, 16, count=1000000, hmac_hash_module=SHA256)
    return secret_key


def encrypt():
    secret_key = gen_key()
    cipher = AES.new(secret_key, AES.MODE_EAX)
    nounce = cipher.nonce
    wallet_privkey = input("input wallet private key: \n").encode('utf-8')
    cipher_text_raw = cipher.encrypt(wallet_privkey)
    cipher_text = base64.b64encode(cipher_text_raw).decode('utf-8')
    nonce = cipher.nonce
    return {'text': cipher_text, 'nonce': nonce}


def test(cipher_text_b64, nonce):
    key = gen_key()
    cipher = AES.new(key, AES.MODE_EAX, nonce)
    cipher_text = base64.b64decode(cipher_text_b64.encode('utf-8'))
    plaintext = cipher.decrypt(cipher_text)
    print(plaintext)


if __name__ == '__main__':
    result = encrypt()
    cipher_text = result.get('text')
    nonce = result.get('nonce')
    print(cipher_text)
    output = open('key_cipher.txt', 'w')
    output.write(cipher_text)
    test(cipher_text, nonce)
