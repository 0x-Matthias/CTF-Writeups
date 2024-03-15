from pwn import *

server = '94.237.49.147'
port = 42129

def send(msg):
	global conn
	conn.sendline(msg.encode())

data = []

conn = remote(server, port)
print(conn.readuntil(b'> help').decode(), end='')
print(conn.readuntil(b'> ').decode(), end='')
# set the negated inputs to the opposite voltage that we want the ports to be:
send('set_ce_pin(6)')
print(conn.readuntil(b'> ').decode(), end='')
send('set_oe_pin(13)')
print(conn.readuntil(b'> ').decode(), end='')
send('set_we_pin(6)')
print(conn.readuntil(b'> ').decode(), end='')
for idx in range(0x7E0,0x800):
	cmd = 'set_address_pins([' + ','.join(['0' if d == '0' else '6' for d in bin(idx)[2:].zfill(11)]) + '])' # binary representation of idx, but with 6 instead of 1 to signal high voltage
	# Raise A9 to 12V to read device-identification.
	if cmd[20] == '6':
		cmd = cmd[:20] + '12' + cmd[21:]
	send(cmd)
	resp = conn.readuntil(b'> ').decode()
	send('read_byte()')
	line = conn.readline().decode()
	print(line, end='')
	line_parts = line.split()
	ind = int(line_parts[4], 16)
	assert(ind == idx) # check the provided index matches with the index returned in the response
	data += [int(line_parts[1], 16)]
	resp = conn.readuntil(b'> ').decode()

print(''.join([chr(d) for d in data])) # HTB{AT28C16_EEPROM_s3c23t_1d!!!}