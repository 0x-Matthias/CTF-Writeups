from pwn import *
context.log_level = 'WARNING'

server = '83.136.248.36' #'192.168.178.79'
port = 52708 #1337

delimiter = b'\n___________________________________________________________\n'

def _answer_func(num_list):
	min = 1000
	max = -1000
	for num in num_list:
		if min > num:
			min = num
		if max < num:
			max = num
	return (min, max)

# Generate answer from above function and omit the first and last 8 bytes
# because these are the code_start and code_end on the server.
#solution = _answer_func.__code__.co_code[8:-8]

# Apparently different python versions use different byte codes, because Windows/python 3.10.4 does not work!
# Generated using Linux/python 3.11.6 and the test.py-script:
solution = b'\x97\x00d\x01}\x01d\x02}\x02|\x00D\x00]\x12}\x03|\x01|\x03k\x04\x00\x00\x00\x00r\x02|\x03}\x01|\x02|\x03k\x00\x00\x00\x00\x00r\x02|\x03}\x02\x8c\x13|\x01|\x02f\x02S\x00'
# reformat into a list of ints:
solution = ','.join([str(x) for x in solution])

def answerInt(val):
	global conn
	val = str(val)
	answerString(val)

def answerString(val):
	print(val)
	conn.sendline(val.encode())

conn = remote(server, port)
print(conn.readuntil(b'(Choose wisely) > ').decode())
answerInt(1)
print(conn.readuntil(b'(Answer wisely) > ').decode())
answerString(solution)
print(conn.readuntil(delimiter).decode())
print(conn.readuntil(delimiter).decode())
conn.close()