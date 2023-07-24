
# rsa

## Challenge
I think I did my RSA right...

### Attachments
- [flag.enc](./handouts/flag.enc)
- [private.pem](./handouts/private.pem)
```
-----BEGIN RSA PRIVATE KEY-----
MIICWwIBAAKBgQDJTzEROqf1384i18XiqfglU1VuCqQJaqhmiMGA3zNHLBojFklL
fe3cxDwdJMolmbdL//qUc0y9yGYSbLUURleS8VMCbWkhtI1SCCxAxkqbRSgWIeSc
d8+ed4JOUXfwTX2nCgO1Pxp1XbeDqba4nnR/agb1d6/4ciyo6w5bz0OcIwIDAQAB
AoGAOw2hDjXPuZ/an3v+j7xej8x/XhV/A0gneFSbtwtCxpkYXbyW6a9aTI3AOKhn
KFqMW54Oyud71pxn3PXItNbhrzJLgNhEYrz4N423gDxM7HgqeYogi6XTc0qVh8rB
fnb7s8JB5bGCLKs5tz2zQ99IYHhjQ8LXeMCwbvSaKSLqQqkCQQD+r7yXzewBv1r+
ir4oAtj07iF8Y3QMiHxykgQxEI6ZPcbzz+7WpBgwQ1z6nMCNJuAfs9/Fxt+DpIjo
3z2JdittAkEAylj7In1hwaA3s3L1SPME5GTqvqTcbtvKhPlrWJ7Ci4N/VU+zByM0
BpsYHFo5cRvFOxFlHDIZ4APLn+Wrs2obzwJADWBJdWeZR5Y3PzsmNY/AuUxwccn/
ZFEeyB2nHrSR6LZ35oI7NwazRoWjMn5dFoy+JKwbypVhU9amYiSnZLrSGQJAOxCC
Le0fbd+Qosb5plOZp/l1NDT3SzzI/su3c+TTsNmvf32GKp0yAIOhJBWKEuQiTD2l
n/dX6jXxaDkoR3S/rQJAd+rO4KvBwxurYGGYpN0vGHSJPPmVLyNxPRmyFYcC5CU/
5Z3FWqN+4eFPtujWig2gfkZ/SL3QuB3s5BG0dWN0gA==
-----END RSA PRIVATE KEY-----
```
- [public.pem](./handouts/public.pem)
 ```
-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDJTzEROqf1384i18XiqfglU1Vu
CqQJaqhmiMGA3zNHLBojFklLfe3cxDwdJMolmbdL//qUc0y9yGYSbLUURleS8VMC
bWkhtI1SCCxAxkqbRSgWIeScd8+ed4JOUXfwTX2nCgO1Pxp1XbeDqba4nnR/agb1
d6/4ciyo6w5bz0OcIwIDAQAB
-----END PUBLIC KEY-----
```

## Solution
In this challenge we are offered an encrypted flag and given the corresponding public and private keys as pem files.

To solve this challenge, we have to read the encrypted flag and convert it to an integer:
```python
flag_enc = bytes_to_long(open('handouts/flag.enc', "rb").read())
```

Next, we have to read and parse the private.pem file to obtain the private key values `private_key.d` and `private_key.n`.
```python
from Crypto.PublicKey import RSA
from Crypto.Util.number import bytes_to_long, long_to_bytes
private_key = RSA.importKey(open('handouts/private.pem', "rb").read())
```

Afterwards we can decrypt the flag and print it:
```python
flag = long_to_bytes(pow(flag_enc, private_key.d, private_key.n)).decode()
print(flag) # ictf{keep_your_private_keys_private}
```
