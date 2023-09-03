import socket
import struct

def create_dns_query() -> bytes:
	# header (totals 12 bytes):
	header = struct.pack(
		'>2s2sHHHH', 
		#												 1  1  1  1  1  1
		#				#  0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
		b'\x03c',		# |               ID (random int)                 |
		b'om',			# |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
		1,				# |            QDCOUNT (num questions)            |
		0,				# |                    ANCOUNT                    |
		0,				# |                    NSCOUNT                    |
		0,				# |                    ARCOUNT                    |
	)
	# question:
	qname = b''
	qname += b'\x04free'
	qname += b'\x04flag'
	qname += b'\x03for'
	qname += b'\x04flag'
	qname += b'\x06loving'
	qname += b'\x04flag'
	qname += b'\x09capturers'
	qname += b'\x0cdownunderctf'
	question = qname + struct.pack(
		'>HHH',
		0xC000, # 0x02 bytes (0xC000 [marker for a pointer] + 0x00 [offset] = pointer to offset 0x00)
		0x0010,	# 0x02 bytes (qtype - TXT-record)
		0x0001	# 0x02 bytes (qclass - IN)
	)
	return header + question

# target domain = "free.flag.for.flag.loving.flag.capturers.downunderctf.com"
query = create_dns_query()
server = ("34.82.169.203", 8053)
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.sendto(query, server)
data, addr = sock.recvfrom(1024)
print(f"Response: {data}")