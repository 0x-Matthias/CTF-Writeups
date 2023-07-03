# Three-Time Pad

## Challenge
"We've been monitoring our adversaries' communication channels, but they encrypt their data with XOR one-time pads! However, we hear rumors that they're reusing the pads...
Enclosed are three encrypted messages. Our mole overheard the plaintext of message 2. Given this information, can you break the enemy's encryption and get the plaintext of the other messages?"

### Attachments
- [c1](./c1)
- [c2](./c2)
- [c3](./c3)
- [p2](./p2)

## Solution
A common issue with the encryption algorithm "One-Time Pad" is the reuse of the secret key. "One-Time Pad" uses a bitwise XOR between the message and the key to compute the ciphertext as well as XOR between the ciphertext and the key to restore the message. Thus computing message XOR ciphertext reveals the key.

{{embed './solver.py' 'python')}}

Using this short python-script, the ciphertexts decrypt as follows:
| ciphertext | message |
| ----------- | ----------- |
| c1 | before computers, one-time pads were sometimes |
| c3 | uiuctf{burn_3ach_k3y_aft3r_us1ng_1t} |
