# Real Smooth

## Challenge
I know you're not supposed to leave passwords in plain text so I encrypted them.

### Attachments
- [database.txt](./handouts/database.txt)
```
c13c9abda3220824f2dc11e8510fc249ad48
c1229ab7b6350824f2dc11e8510fc249ad48
d32b84b2af20630ef2dc11e8510fc249ad48
cd2b87b4a3350824f2dc11e8510fc249ad48
cb2b90f6f47f0824f2dc11e8510fc249ad48
[...]
d02f81a2b4216768bd923be8510fc249ad48
967cc6f2f0462224f2dc11e8510fc249ad48
d7278daea33f0824f2dc11e8510fc249ad48
e501a290891b0824f2dc11e8510fc249ad48
cb2183a2a7207565ab8f3be8510fc249ad48
```
- [main.py](./handouts/main.py)
```python
from Crypto.Cipher import ChaCha20
from Crypto.Random import get_random_bytes

def encrypt(key, nonce, plaintext):
    chacha = ChaCha20.new(key=key, nonce=nonce)
    return chacha.encrypt(plaintext)

def main():
    lines = open("passwords.txt", "rb").readlines()
    key = get_random_bytes(32)
    nonce = get_random_bytes(8)
    lines = [x.ljust(18) for x in lines]
    lines = [encrypt(key, nonce, x) for x in lines]
    open("database.txt", "wb").writelines(lines)

if __name__ == "__main__":
    main()
```

## Solution
In this challenge, we're given a bunch of data, that has been encrypted using the `ChaCha20` cipher using an unknown key and an unknown nonce. All the unencrypted data has been padded using spaces before encryption, such that it is 18 bytes long.

The `ChaCha20` cipher uses a key and a nonce to firstly produce a secondary key, which in turn is used to encrypt the actual data using XOR. So basically the secondary key is the key to a `one-time pad` and because we have multiple datasets using the same key, we can attack this encryption using the same attacks, that apply for the `one-time pad`.

### Key recovery part 1: The end of the key
Because the encryption routine did pad the data to 18 bytes of length before encrypting the data
 ```python
lines = [x.ljust(18) for x in lines]
```
we can assume, that ciphertexts with an identical suffix have been padded before encryption. Thus if we can find the longest common suffix among all the ciphertexts, 
```python
# read database
with open('./handouts/database.txt', 'r') as f:
	data = f.read().strip().split()
# ensure, that data is unique:
data = list(sorted(set(data)))

# check for the most common bytes from the end of the encrypted data:
most_common_bytes = ''
for i in range(36)[::-1]:
	# make a histogram of the character at index i
	counts = {}
	for v in "0123456789abcdef":
		counts[v] = 0
	# only include words, that share the previously computed suffix
	for word in [w for w in data if w.endswith(most_common_bytes)]:
		counts[word[i]] += 1
	# order by count ascending
	counts_sorted = sorted(counts.items(), key=lambda x:x[1])
	# prepend the most common character to the previous iteration
	most_common_bytes = counts_sorted[-1][0] + most_common_bytes
print('most common bytes:', most_common_bytes)

# check, how many of those common bytes (counting from the back) each word of data has in common
for common_suffix_byte_length in range(18):
	common_suffix = most_common_bytes[2 * common_suffix_byte_length:]
	print(common_suffix_byte_length, len([w for w in data if w.endswith(common_suffix)]))
```
we can assume this to represent the encrypted value of the padding and thus if we XOR this byte sequence with spaces, we can recover the suffix of the key:
```python
blank_word = b''.ljust(18)
most_common_word = bytes.fromhex(most_common_bytes)
# try to guess the key by XORing the blank word with the most common bytes
partial_key = [(blank_word[i] ^ most_common_word[i]) for i in range(18)]
print('partial key:', partial_key)
```

### Key recovery part 2: The middle bit of the key
If we try to decrypt the data using this partial key, we know, that the suffixes of all words will be decrypted correctly; just a few bytes at the beginning will most likely be off:
```python
for i in range(len(data)):
	word = data[i]
	word_bytes = bytes.fromhex(word)
	plain_numbers = [(partial_key[i] ^ word_bytes[i]) for i in range(18)]
	plain = ''.join([chr(x) for x in plain_numbers])
	print(plain)
```
If we now take a look at the partially decrypted data,
```
*(#9"$Zlan
)3+=:8Zink
)3+=:8Zrincess
```
we can make two deductions:

1. Some of the words are obviously wrong: `Zlan`, `Zink` and `Zrincess` should most likely end in `plan`, `pink` and `princess`, because we should keep in mind, that under the XOR decryption, the same character at the identical index across many words will always change to the same but different character if we change the key for that index. Thus we can make all of those `Z`s become `p`s simultaneously!
2. We can assume that the partial key is correct from index 7 onwards. Thus going forward we only have to recover the first 7 bytes of the 18 bytes long key.

For the sake of simplicity, we replace the `blank_word` with `base_word`, which only switches up the first seven bytes with their index digits.
```python
base_word = b'0123456'.ljust(18)
```

We can now modify the `base_word` to fix the byte at index 6 of the partial key to the value of `space` (the current value of the blank word) XOR `Z` (the previous decryption output) XOR `p` (the desired value) = `\x0A`:
```python
base_word = b'012345\x0A'.ljust(18)
most_common_word = bytes.fromhex(most_common_bytes)
# try to guess the key by XORing the blank word with the most common bytes
partial_key = [(base_word[i] ^ most_common_word[i]) for i in range(18)]
print('partial key:', partial_key)

# print the decrypted values again
for i in range(len(data)):
	word = data[i]
	word_bytes = bytes.fromhex(word)
	plain_numbers = [(partial_key[i] ^ word_bytes[i]) for i in range(18)]
	plain = ''.join([chr(x) for x in plain_numbers])
	print(plain)
```

Continuing the (known-)plaintext attack and considering, we're dealing with a list of encrypted passwords, we can guess the next letter of a couple of those partially decrypted words:
```
0ogs		-> dogs
-ousomuch	-> yousomuch
-ou22		-> you22
-ou13		-> you13
-ou!		-> you!
-ou			-> you
6oys		-> boys
```
All of those substitutions lead to the character at index 5 being an `a`:
```python
base_word = b'01234a\x0A'.ljust(18)
```

### Key recovery part 3: The start of the key
At this point, two partially decrypted values stick out, because they look like leet speak:
1. `+$?<!w3_d0_4_l177l`
2. `z☼74jwn_pl41n73x7}`

Assuming this is a two part flag, and having the `}` at the end of the second part, we can assume, that the first part should start with `bctf{` and thus fix our base word in its entirety and thus recover the 18 bytes long XOR key as well as all the plaintexts of the encrypted data.
```python
base_word = b'yanina\x0A'.ljust(18)
key = [(base_word[i] ^ most_common_word[i]) for i in range(18)]
print('key:', [hex(x)[2:] for x in key])
# ['a7', '4e', 'f5', 'c7', 'c6', '4c', '02', '04', 'd2', 'fc', '31', 'c8', '71', '2f', 'e2', '69', '8d', '68']
```
Finally we can assemble the flag from the two previously mentioned parts: `btcf{w3_d0_4_l177l3_kn0wn_pl41n73x7}`

### Note
Given the amount of encrypted data, we probably could have automated the xor key recovery process in a similar fashion as to how this would be done in a `Vigenère` cipher: Building a histogram for each index, comparing the frequency distribution of the encrypted characters with the one in the English language and try to deduce the key byte for that index by testing which of the 256 possible key bytes matches the frequency distribution best and thus assume this would be the correct key byte for that index. But because this would probably just yield an approximation of the real xor key and we would have had to manually fix some bytes anyways, we option for the previously mentioned approach.

## Resources
- [Wikipedia: ChaCha20-Poly1305](https://en.wikipedia.org/wiki/ChaCha20-Poly1305)
- [Wikipedia: One-time pad](https://en.wikipedia.org/wiki/One-time_pad)