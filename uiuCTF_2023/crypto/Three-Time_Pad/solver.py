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
