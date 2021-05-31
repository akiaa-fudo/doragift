from Crypto.Random import get_random_bytes
import base64

if __name__ == '__main__':
    salt_raw = get_random_bytes(16)
    print(salt_raw)
    salt_b64 = base64.b64decode(salt_raw)
    print(salt_b64)
    # f = open("salt", "w")
    # f.write(salt_raw)
