from pwn import *
from base64 import b64encode
context.log_level = 'WARNING'

server = '83.136.255.150'
port = 32848

polyglot = open('polyglot.c').read().replace('\r\n', '\n')

conn = remote(server, port)
print(conn.readuntil(b'Enter the program of many languages: ').decode())
conn.writeline(b64encode(polyglot.encode()))
print(conn.readuntil(b'}').decode()) # HTB{7he_ComMOn_5yM8OL5_Of_l4n9U49E5_C4n_LE4d_7O_m4ny_PolY9lO7_WoNdeR5}
conn.close()