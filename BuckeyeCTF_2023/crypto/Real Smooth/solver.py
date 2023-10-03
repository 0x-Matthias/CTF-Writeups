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

# because we know, that shorter words were (.ljust(18)) padded with spaces, we can recover the suffix of the key by XORing with spaces
blank_word = b''.ljust(18)
most_common_word = bytes.fromhex(most_common_bytes)
print('most common word:', most_common_word)
# try to guess the key by XORing the blank word with the most common bytes
partial_key = [(blank_word[i] ^ most_common_word[i]) for i in range(18)]
print('partial key:', partial_key)

# let's see, what the data decrypt to using the partial key
for i in range(len(data)):
	word = data[i]
	word_bytes = bytes.fromhex(word)
	plain_numbers = [(partial_key[i] ^ word_bytes[i]) for i in range(18)]
	plain = ''.join([chr(x) for x in plain_numbers])
	print(plain)

base_word = b'012345\x0A'.ljust(18)
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

base_word = b'yanina\x0A'.ljust(18)
# try to guess the key by XORing the blank word with the most common bytes
key = [(base_word[i] ^ most_common_word[i]) for i in range(18)]
print('key:', [hex(x)[2:] for x in key])

# print the decrypted flag parts
for i in range(len(data)):
	word = data[i]
	word_bytes = bytes.fromhex(word)
	plain_numbers = [(key[i] ^ word_bytes[i]) for i in range(18)]
	plain = ''.join([chr(x) for x in plain_numbers])
	if '{' in plain or plain.endswith('}'):
		print(plain)

# btcf{w3_d0_4_l177l
# 3_kn0wn_pl41n73x7}
# => btcf{w3_d0_4_l177l3_kn0wn_pl41n73x7}