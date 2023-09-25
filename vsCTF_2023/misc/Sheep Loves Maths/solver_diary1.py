from oeis import *
import requests

# Assuming "res" is a sequence of 8 printable characters (that can be part of a URL), we can expect 32 <= ord(res[i]) <= 127 for all 0 <= i <= 7.

min = 0x20 # omit the non-printable characters
max = 0x7E # 0x7F is a weird char to put into a URL; >= 0x80 is ANSII stuff; probably not worth checking.

# independant possibilities
possibilities = {
	0 : [x for x in A000142[:10] if min <= x-1 and x <= max], # conditions for indices 0 and 2 (depending on 0)
	1 : [x for x in A004767[:100] if min <= x-1 and x <= max and x > A000203[36]], # conditions for indices 1 and 5 (depending on 1)
	3 : [x for x in A000045[:20] if min <= x and 2*(x+1) <= max], # conditions for indices 3 and 4 (depending on 3)
	6 : [x for x in A000217[13:20] if min <= x and x <= max], # conditions for index 6
	7 : [A000040[4] ** 2] # conditions for index 7
}
# dependencies
#possibilities[2] = [x-1 for x in possibilities[0]]
#possibilities[4] = [2*(x+1) for x in possibilities[3]]
#possibilities[5] = [x-1 for x in possibilities[1]]

for v0 in possibilities[0]:
	# The character with index 2 is dependant on the character with index 0.
	v2 = v0 - 1
	for v1 in possibilities[1]:
		# The character with index 5 is dependant on the character with index 3.
		v5 = v1 - 1
		for v3 in possibilities[3]:
			# The character with index 4 is dependant on the character with index 3.
			v4 = 2 * (v3 + 1)
			for v6 in possibilities[6]:
				for v7 in possibilities[7]:
					seq = [v0, v1, v2, v3, v4, v5, v6, v7]
					res = ''.join([chr(x) for x in seq])
					# check URL:
					url = 'https://challs.vsc.tf/sheep-diary-' + res + '/'
					r = requests.get(url)
					#print(res, seq, url, r.status_code)
					if r.status_code == 200:
						print(url)
