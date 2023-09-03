# mini dns server

## Challenge
This mini DNS server hands out free flags to fellow mini DNS enthusiasts.

### Attachments
- [mini_dns_server.py](./handouts/mini_dns_server.py)
```python
import time
from dnslib.server import DNSServer, BaseResolver
from dnslib import RR, TXT, QTYPE, RCODE

class Resolver(BaseResolver):
	def resolve(self, request, handler):
		reply = request.reply()
		reply.header.rcode = RCODE.reverse['REFUSED']
		
		print("number of requests:", len(handler.request))
		print("length of first request", len(handler.request[0]))
		print()
		print()
		if len(handler.request[0]) > 72:
			return reply

		if request.get_q().qtype != QTYPE.TXT:
			return reply

		qname = request.get_q().get_qname()
		if qname == 'free.flag.for.flag.loving.flag.capturers.downunderctf.com':
			FLAG = open('flag.txt', 'r').read().strip()
			txt_resp = FLAG
		else:
			txt_resp = 'NOPE'

		reply.header.rcode = RCODE.reverse['NOERROR']
		reply.add_answer(RR(qname, QTYPE.TXT, rdata=TXT(txt_resp)))
		return reply

server = DNSServer(Resolver(), port=8053)
server.start_thread()
while server.isAlive():
	time.sleep(1)
```

## Solution
In this challenge we are required to craft a dns query with the following requirements:
- We must query a _TXT_-record.
- The corresponding domain is _free.flag.for.flag.loving.flag.capturers.downunderctf.com_ .
- The query must not exceed 72 bytes in length.

To understand the message format of a dns-query, we can read section 4.1.1, 4.1.2 and 4.1.4 of RFC 1035.

The message header looks like this:
```
                                    1  1  1  1  1  1
      0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                      ID                       |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    QDCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    ANCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    NSCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    ARCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
```
which totals 12 bytes of data for the header alone.

The message body, containing the question, has the following structure:
```
                                    1  1  1  1  1  1
      0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                                               |
    /                     QNAME                     /
    /                                               /
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                     QTYPE                     |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                     QCLASS                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
```
Here `QNAME` has to be formatted in a special way and it contains the actual domain we want to query. Thus this field is of variable length.
```
A domain name represented as a sequence of labels, where each label consists of a length octet followed by that number of octets.  The domain name terminates with the zero length octet for the null label of the root. Note that this field may be an odd number of octets; no padding is used.
```
Which in essence means: split the domain string on the `.`-character, compute the byte-length of each part and format it all like
```
byte_length(part_1) as byte
part_1 as byte-string
byte_length(part_2) as byte
part_2 as byte-string
...
byte_length(part_n) as byte
part_n as byte-string
null-byte
```
Thus `free.flag.for.flag.loving.flag.capturers.downunderctf.com` would turn into the following sequence of bytes,
```
0x04
free
0x04
flag
0x03
for
0x04
flag
0x06
loving
0x04
flag
0x09
capturers
0x0b
downunderctf
0x03
com
0x00
```
having a length of 59 bytes; adding the `QTYPE` and `QCLASS`, the body totals 63 bytes and including the header we are having a total of 75 bytes. Unfortunately this exceeds the 72 byte length limit the challenge forces upon us.

Luckily there is a way to compress data in dns queries, where you can specify a prefix of a domain and a pointer, which specifies where to look for the rest of the domain. Such a pointer has the following byte sequence, where the offset is computed from the beginning of the request:
```
                                    1  1  1  1  1  1
      0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    | 1  1|                OFFSET                   |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
```
Such a pointer takes up an additional 2 bytes of space and thus we need to somehow move 75 (default request length) + 2 (pointer length) - 72 (max allowed length) = 5 bytes somewhere else.

After reading the docs and testing all of the header bytes, it turns out:
- The first two bytes are user controlled.
- The implementation of the dns server does not care about the bit flags (bytes 3 and 4) at all.
- The `QDCOUNT` specifies the number of questions per request; if we change this value, the parser of the dns server expects more data than we are allowed to send; thus these 2 bytes are fixed to 0x0001.
- Modifying the last 3 fields `ANCOUNT`, `NSCOUNT` or `ARCOUNT` seem to break the request as well; although these contain data relevant to a response; so these were the first bytes we did actually test.

Luckily we can control the first 4 bytes and the fith byte does match our requirement to be a null-byte, so we moved the 5 bytes
```
0x03
com
0x00
```
to the start of the header and crafted a pointer to point to offset 0x00.

```python
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
```

Running this script, one obtains a response of
```b'\x03c\xef\xe0\x00\x01\x00\x01\x00\x00\x00\x00\x04free\x04flag\x03for\x04flag\x06loving\x04flag\tcapturers\x0cdownunderctf\x03com\x00\x00\x10\x00\x01\xc0\x0c\x00\x10\x00\x01\x00\x00\x00\x00\x0032DUCTF{1ts.N0t.DNS.There1s.n0W4y.its_DNS.1tw4s.DNS}'```

and thus the flag `DUCTF{1ts.N0t.DNS.There1s.n0W4y.its_DNS.1tw4s.DNS}`.

## Resources 
- [RFC 1035: DNS-query message structure](https://datatracker.ietf.org/doc/html/rfc1035#section-4)
