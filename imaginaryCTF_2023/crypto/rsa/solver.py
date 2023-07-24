from Crypto.PublicKey import RSA
from Crypto.Util.number import bytes_to_long, long_to_bytes

# Read the encrypted flag:
flag_enc = bytes_to_long(open('handouts/flag.enc', "rb").read())
# Read and parse the private RSA key:
private_key = RSA.importKey(open('handouts/private.pem', "rb").read())
# Decrypt and print the flag:
flag = long_to_bytes(pow(flag_enc, private_key.d, private_key.n)).decode()
print(flag) # ictf{keep_your_private_keys_private}
