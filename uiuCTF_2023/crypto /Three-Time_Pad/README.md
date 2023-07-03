# Three-Time Pad

## Challenge
"We've been monitoring our adversaries' communication channels, but they encrypt their data with XOR one-time pads! However, we hear rumors that they're reusing the pads...
Enclosed are three encrypted messages. Our mole overheard the plaintext of message 2. Given this information, can you break the enemy's encryption and get the plaintext of the other messages?"

### Attachments
- [c1](./handouts/c1)
- [c2](./handouts/c2)
- [c3](./handouts/c3)
- [p2](./handouts/p2)

## Solution
A common issue with the encryption algorithm "One-Time Pad" is the reuse of the secret key. "One-Time Pad" uses a bitwise XOR between the message and the key to compute the ciphertext as well as XOR between the ciphertext and the key to restore the message. Thus computing message XOR ciphertext reveals the key.

 ```python
with open('c1', 'rb') as fc1:
	c1 = fc1.read()
with open('c2', 'rb') as fc2:
	c2 = fc2.read()
with open('c3', 'rb') as fc3:
	c3 = fc3.read()
with open('p2', 'rb') as fp2:
	p2 = fp2.read()

# In this specific case, the key is always at least as long as the data:
def compute_xor(data, key):
	return [data[i] ^ key[i] for i in range(len(data))]

def decrypt(data, key):
	bytes = compute_xor(data, key)
	return ''.join([chr(x) for x in bytes])

key = compute_xor(c2, p2)
p1  = decrypt(c1, key)
print(p1)
p3  = decrypt(c3, key)
print(p3)
```

Using this short python-script, the ciphertexts decrypt as follows:
| ciphertext | message |
| ----------- | ----------- |
| c1 | before computers, one-time pads were sometimes |
| c3 | uiuctf{burn_3ach_k3y_aft3r_us1ng_1t} |
