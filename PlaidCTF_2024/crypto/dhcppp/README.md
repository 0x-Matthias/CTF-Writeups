# Plaid CTF 2024 Writeup (Team: L3ak, 38rd Place)
Competition URL: https://plaidctf.com/
## Overview

| Challenge | Category | Points | Flag                                        |
| --------- | -------- | ------ | ------------------------------------------- |
| DHCPPP    | crypto   | 200    | PCTF{d0nt_r3u5e_th3_n0nc3_d4839ed727736624} |

## Challenge: DHCPPP
The local latin dance company is hosting a comp. They have a million-dollar wall of lava lamps and prizes so big this must be a once-in-a-lifetime opportunity.

*Hypotheses*. It's not DNS // There's no way it's DNS // It was DNS

### Attachment
- [dhcppp.py](./handout/dhcppp.py)
```python
import time, zlib
import secrets
import hashlib
import requests
from Crypto.Cipher import ChaCha20_Poly1305
import dns.resolver

CHACHA_KEY = secrets.token_bytes(32)
TIMEOUT = 1e-1

def encrypt_msg(msg, nonce):
    # In case our RNG nonce is repeated, we also hash
    # the message in. This means the worst-case scenario
    # is that our nonce reflects a hash of the message
    # but saves the chance of a nonce being reused across
    # different messages
    nonce = sha256(msg[:32] + nonce[:32])[:12]

    cipher = ChaCha20_Poly1305.new(key=CHACHA_KEY, nonce=nonce)
    ct, tag = cipher.encrypt_and_digest(msg)

    return ct+tag+nonce

def decrypt_msg(msg):
    ct = msg[:-28]
    tag = msg[-28:-12]
    nonce = msg[-12:]

    cipher = ChaCha20_Poly1305.new(key=CHACHA_KEY, nonce=nonce)
    pt = cipher.decrypt_and_verify(ct, tag)

    return pt

def calc_crc(msg):
    return zlib.crc32(msg).to_bytes(4, "little")

def sha256(msg):
    return hashlib.sha256(msg).digest()

RNG_INIT = secrets.token_bytes(512)

class DHCPServer:
    def __init__(self):
        self.leases = []
        self.ips = [f"192.168.1.{i}" for i in range(3, 64)]
        self.mac = bytes.fromhex("1b 7d 6f 49 37 c9")
        self.gateway_ip = "192.168.1.1"

        self.leases.append(("192.168.1.2", b"rngserver_0", time.time(), []))

    def get_lease(self, dev_name):
        if len(self.ips) != 0:
            ip = self.ips.pop(0)
            self.leases.append((ip, dev_name, time.time(), []))
        else:
            # relinquish the oldest lease
            old_lease = self.leases.pop(0)
            ip = old_lease[0]
            self.leases.append((ip, dev_name, time.time(), []))

        pkt = bytearray(
            bytes([int(x) for x in ip.split(".")]) +
            bytes([int(x) for x in self.gateway_ip.split(".")]) +
            bytes([255, 255, 255, 0]) +
            bytes([8, 8, 8, 8]) +
            bytes([8, 8, 4, 4]) +
            dev_name +
            b"\x00"
        )

        pkt = b"\x02" + encrypt_msg(pkt, self.get_entropy_from_lavalamps()) + calc_crc(pkt)

        return pkt

    def get_entropy_from_lavalamps(self):
        # Get entropy from all available lava-lamp RNG servers
        # Falling back to local RNG if necessary
        entropy_pool = RNG_INIT

        for ip, name, ts, tags in self.leases:
            if b"rngserver" in name:
                try:
                    # get entropy from the server
                    output = requests.get(f"http://{ip}/get_rng", timeout=TIMEOUT).text
                    entropy_pool += sha256(output.encode())
                except:
                    # if the server is broken, get randomness from local RNG instead
                    entropy_pool += sha256(secrets.token_bytes(512))

        return sha256(entropy_pool)

    def process_pkt(self, pkt):
        assert pkt is not None

        src_mac = pkt[:6]
        dst_mac = pkt[6:12]
        msg = pkt[12:]

        if dst_mac != self.mac:
            return None

        if src_mac == self.mac:
            return None

        if len(msg) and msg.startswith(b"\x01"):
            # lease request
            dev_name = msg[1:]
            lease_resp = self.get_lease(dev_name)
            return (
                self.mac +
                src_mac + # dest mac
                lease_resp
            )
        else:
            return None

class FlagServer:
    def __init__(self, dhcp):
        self.mac = bytes.fromhex("53 79 82 b5 97 eb")
        self.dns = dns.resolver.Resolver()
        self.process_pkt(dhcp.process_pkt(self.mac+dhcp.mac+b"\x01"+b"flag_server"))

    def send_flag(self):
        with open("flag.txt", "r") as f:
            flag = f.read().strip()
        curl("example.com", f"/{flag}", self.dns)

    def process_pkt(self, pkt):
        assert pkt is not None

        src_mac = pkt[:6]
        dst_mac = pkt[6:12]
        msg = pkt[12:]

        if dst_mac != self.mac:
            return None

        if src_mac == self.mac:
            return None

        if len(msg) and msg.startswith(b"\x02"):
            # lease response
            pkt = msg[1:-4]
            pkt = decrypt_msg(pkt)
            crc = msg[-4:]
            assert crc == calc_crc(pkt)

            self.ip = ".".join(str(x) for x in pkt[0:4])
            self.gateway_ip = ".".join(str(x) for x in pkt[4:8])
            self.subnet_mask = ".".join(str(x) for x in pkt[8:12])
            self.dns1 = ".".join(str(x) for x in pkt[12:16])
            self.dns2 = ".".join(str(x) for x in pkt[16:20])
            self.dns.nameservers = [self.dns1, self.dns2]
            assert pkt.endswith(b"\x00")

            print("[FLAG SERVER] [DEBUG] Got DHCP lease", self.ip, self.gateway_ip, self.subnet_mask, self.dns1, self.dns2)

            return None

        elif len(msg) and msg.startswith(b"\x03"):
            # FREE FLAGES!!!!!!!
            self.send_flag()
            return None

        else:
            return None

def curl(url, path, dns):
    ip = str(dns.resolve(url).response.resolve_chaining().answer).strip().split(" ")[-1]
    url = "http://" + ip
    print(f"Sending flage to {url}")
    requests.get(url + path)

if __name__ == "__main__":
    dhcp = DHCPServer()
    flagserver = FlagServer(dhcp)

    while True:
        pkt = bytes.fromhex(input("> ").replace(" ", "").strip())

        out = dhcp.process_pkt(pkt)
        if out is not None:
            print(out.hex())

        out = flagserver.process_pkt(pkt)
        if out is not None:
            print(out.hex())
```

## Analysis

At first glance, we can make out a couple of helper functions, a **main** function as well as two server classes: A **DhcpServer** and a **FlagServer**. Let's take a deep dive into the server code to understand the provided funtions.

### Main

Looking at the **main** function, we can see an instance of the **DhcpServer** class, an instance of the **FlagServer** class, which is using the DhcpServer instance, and an endless loop of reading hex encoded packet data from the command line, passing it two both server instances and printing their outputs / return values as hex. Additionally, we can see both servers declaring a `process_pkt(packet)` function, which seems to handle the incoming requests for the respective server.
```python
if __name__ == "__main__":
    dhcp = DHCPServer()
    flagserver = FlagServer(dhcp)

    while True:
        pkt = bytes.fromhex(input("> ").replace(" ", "").strip())

        out = dhcp.process_pkt(pkt)
        if out is not None:
            print(out.hex())

        out = flagserver.process_pkt(pkt)
        if out is not None:
            print(out.hex())
```

### Helper functions and static data

When analyzing the helper functions and static data, we can see two randomly generated byte strings, that are generated in a cryptographically secure way: The `CHACHA_KEY` and the `RNG_INIT` with lengths of 32 and 512 bytes respectively.
```python
import secrets

CHACHA_KEY = secrets.token_bytes(32)
RNG_INIT = secrets.token_bytes(512)
```

Additionally there are helper functions to compute a **crc32** checksum and a **SHA256** hash - nothing out of the ordinary.
```python
import zlib
import hashlib

def calc_crc(msg):
    return zlib.crc32(msg).to_bytes(4, "little")

def sha256(msg):
    return hashlib.sha256(msg).digest()
```

We also have some functions to encrypt and decrypt data using the **ChaCha20_Poly1305** algorithm, which uses a `key` and a `nonce` to encrypt a `message` and produces a `ciphertext` and an authentication `tag` (a.k.a. message authentication code or MAC for short - not to be confused with a *MAC address* though).
```python
from Crypto.Cipher import ChaCha20_Poly1305

def encrypt_msg(msg, nonce):
    # In case our RNG nonce is repeated, we also hash
    # the message in. This means the worst-case scenario
    # is that our nonce reflects a hash of the message
    # but saves the chance of a nonce being reused across
    # different messages
    nonce = sha256(msg[:32] + nonce[:32])[:12]

    cipher = ChaCha20_Poly1305.new(key=CHACHA_KEY, nonce=nonce)
    ct, tag = cipher.encrypt_and_digest(msg)

    return ct+tag+nonce

def decrypt_msg(msg):
    ct = msg[:-28]
    tag = msg[-28:-12]
    nonce = msg[-12:]

    cipher = ChaCha20_Poly1305.new(key=CHACHA_KEY, nonce=nonce)
    pt = cipher.decrypt_and_verify(ct, tag)

    return pt
```
A couple of things to note here:
- Typically you're able to reuse the key for ChaCha20_Poly1305, as long as you're using a different nonce for each message encryption; otherwise this algorithm is known to lose confidentiality for messages encrypted using the same nonce.
- Assuming an attacker can control the first 32 bytes of the `message` and the `nonce` parameters, the nonce used during the encryption can suffer from a `key and nonce reuse attack` depending on the provided parameters.
- The `decrypt_msg` function does not validate that the `nonce`, supplied with the encrypted message `msg`, does adhere to the pattern used to contruct the `nonce` in the `encrypt_msg` function.

Lastly there's the custom `curl` function, which looks like it's trying to resolve a domain using a specified **DNS server** instance and then sending an http **GET** request to the corresponding ip address. We'll come back to this once we analyze the **FlagServer**.
```python
import dns.resolver
import requests

def curl(url, path, dns):
    ip = str(dns.resolve(url).response.resolve_chaining().answer).strip().split(" ")[-1]
    url = "http://" + ip
    print(f"Sending flage to {url}")
    requests.get(url + path)
```

### DhcpServer

After taking a look at the helper funcitons, let's come back to the server classes: Starting off with the **DhcpServer**.

The `__init__` function of this class seems to declare two lists `leases` and `ips`, which will contain the provided leases and the available ips for this DhcpServer. Additionally it's setting its **MAC address** to the static hex value `1b 7d 6f 49 37 c9`, its gateway to be `192.168.1.1` and it also leases out the ip address `192.168.1.2` to a server named `rngserver_0`.
```python
import time

class DHCPServer:
    def __init__(self):
        self.leases = []
        self.ips = [f"192.168.1.{i}" for i in range(3, 64)]
        self.mac = bytes.fromhex("1b 7d 6f 49 37 c9")
        self.gateway_ip = "192.168.1.1"

        self.leases.append(("192.168.1.2", b"rngserver_0", time.time(), []))
```

Let's now analyze the `process_pkt` function:
- We can deduce some of the structure of the packet data: Each packet is supposed to start with 6 bytes of MAC address corresponding to the sender of the packet, followed by an other 6 bytes of MAC address of the receiver of the packet and the rest of the packet will contain the actual message.
- The DhcpServer will only process packets that are meant to be routed to it and don't originate from itself.
- If the message does not start with a `0x01`-byte, the DhcpServer will reject the packet.
- Otherwise it will interpret the message-content following the `0x01`-byte, which is reminiscent of a **DHCP discovery message**, as the server name, try to lease an ip address to it and construct and return a response packet, that follows the same structure of sender MAC address followed by receiver MAC address and the actual message, to the sender of the current packet.
```python
    def process_pkt(self, pkt):
        assert pkt is not None

        src_mac = pkt[:6]
        dst_mac = pkt[6:12]
        msg = pkt[12:]

        if dst_mac != self.mac:
            return None

        if src_mac == self.mac:
            return None

        if len(msg) and msg.startswith(b"\x01"):
            # lease request
            dev_name = msg[1:]
            lease_resp = self.get_lease(dev_name)
            return (
                self.mac +
                src_mac + # dest mac
                lease_resp
            )
        else:
            return None
```

The `get_lease` function, which processes the **DHCP discovery message**, will try to handout any unused ip address from the `ips`-list first and if all of them are in use, it will relinquish the oldest lease and reuse and handout that same ip address once more.

**Note**: If an actual DHCP server was to behave like this, modern networks would break all the time, because multiple devices would use the same ip address, which is supposed to be unique to a single device for the timeframe of the lease, which this DhcpServer implementation does not respect.

Finally this function will construct a response packet similar to a **DHCP offer message** even replying with some of the possible **DHCP options**.
- The main difference to the official **DHCP protocol** being, that most of the response is being encrypted and it'll attach a checksum, computed on the unencrypted packet, to the end of the response.
- An other notable piece of information are the two DNS server ip addresses given inside the response packet, which are statically set to `8.8.8.8` and `8.8.4.4` by the **DhcpServer**. We'll come back to this when analyzing the FlagServer.
```python
    def get_lease(self, dev_name):
        if len(self.ips) != 0:
            ip = self.ips.pop(0)
            self.leases.append((ip, dev_name, time.time(), []))
        else:
            # relinquish the oldest lease
            old_lease = self.leases.pop(0)
            ip = old_lease[0]
            self.leases.append((ip, dev_name, time.time(), []))

        pkt = bytearray(
            bytes([int(x) for x in ip.split(".")]) +
            bytes([int(x) for x in self.gateway_ip.split(".")]) +
            bytes([255, 255, 255, 0]) +
            bytes([8, 8, 8, 8]) +
            bytes([8, 8, 4, 4]) +
            dev_name +
            b"\x00"
        )

        pkt = b"\x02" + encrypt_msg(pkt, self.get_entropy_from_lavalamps()) + calc_crc(pkt)

        return pkt
```
Taking a deeper dive into the packet encryption, we'll notice two things:
1. The `dev_name` part of the response packet is fully controlled by the sender of the **DHCP discovery message**, as we'll see when analyzing the **FlagServer** and the intended structure of such a discovery message. The only pseudo restriction on this part is a trailing `0x00`-byte, which the sender is not supposed to change, but there's no actual check for that byte.
2. The `nonce` passed into the `encrypt_msg` function is generated using the `get_entropy_from_lavalamps` function, which we'll take a look at right now:

There's two cases for this function:
1. If the **DhcpServer** instance does not contain an active `lease` for a server containing `rngserver` in the server name, then the `get_entropy_from_lavalamps` function will just return `sha256(RNG_INIT)`.
2. On the other hand, if the **DhcpServer** does contain an active `lease` for a server containing `rngserver` in its name, then the result of the `get_entropy_from_lavalamps` function will be altered by appending some additional data to the argument of the SHA256 computation.

Thus for the sake of simplicity, we should try to achieve the first case and thus get a static return value from this funtion to maybe be able to pull of a **key and nonce reuse** in the `encrypt_msg` function. 
```python
    def get_entropy_from_lavalamps(self):
        # Get entropy from all available lava-lamp RNG servers
        # Falling back to local RNG if necessary
        entropy_pool = RNG_INIT

        for ip, name, ts, tags in self.leases:
            if b"rngserver" in name:
                try:
                    # get entropy from the server
                    output = requests.get(f"http://{ip}/get_rng", timeout=TIMEOUT).text
                    entropy_pool += sha256(output.encode())
                except:
                    # if the server is broken, get randomness from local RNG instead
                    entropy_pool += sha256(secrets.token_bytes(512))

        return sha256(entropy_pool)
```

### FlagServer

Finally let's analyze the **FlagServer**:

Similarly to the **DhcpServer**, the **FlagServer** also initializes its own **MAC address**. Additionally it sets up its own **DNS resolver** and initializes this `dns` instance and its own network settings by talking to the **DhcpServer** and asking it for the appropriate settings.
```python
class FlagServer:
    def __init__(self, dhcp):
        self.mac = bytes.fromhex("53 79 82 b5 97 eb")
        self.dns = dns.resolver.Resolver()
        self.process_pkt(dhcp.process_pkt(self.mac+dhcp.mac+b"\x01"+b"flag_server"))
```

The **FlagSever** is going to process the response of the **DhcpServer** using its own `process_pkt` function. This function, similarly to the **DhcpServer**'s analogue, also parses the first 12 bytes into two different **MAC addresses** and checks those to see if it even has to process the received packet - in the same way, the **DhcpServer** does. And again, the remainder of the packet data is being considered the actual message part of the packet.

Besides that, the **FlagServer** can execute two functions depending on the incoming message `msg`.
-  If the `msg` starts with a `0x02`-byte, it will parse and process the supplied **DHCP offer message**:
    1. After stripping the static `0x02`-byte from the front and the checksum from the end of the message, the **FlagServer** decrypts the provided ciphertext packet `pkt` and veryfies the contained `tag` using the also contianed `nonce` and the previously defined `decrypt_msg` function with the shared static encryption key `CHACHA_KEY`.
    2. After decrypting the **DHCP offer message** `pkt`, the **FlagServer** also verifies the **checksum** attached to the message.
    3. If all the checks pass, the **FlagServer** will then continue to configure its own settings based on the **DHCP offer message** and also configure their `dns` server to use the supplied **DNS server ip addresses**.
- If the `msg` starts with a `0x03`-byte, then the **FlagServer** is reading the file `flag.txt` and sending a http **GET** request to `http://example.com/{flag}` using its own **DNS server**.
- Any other message will be rejected by this server.
```python
    def process_pkt(self, pkt):
        assert pkt is not None

        src_mac = pkt[:6]
        dst_mac = pkt[6:12]
        msg = pkt[12:]

        if dst_mac != self.mac:
            return None

        if src_mac == self.mac:
            return None

        if len(msg) and msg.startswith(b"\x02"):
            # lease response
            pkt = msg[1:-4]
            pkt = decrypt_msg(pkt)
            crc = msg[-4:]
            assert crc == calc_crc(pkt)

            self.ip = ".".join(str(x) for x in pkt[0:4])
            self.gateway_ip = ".".join(str(x) for x in pkt[4:8])
            self.subnet_mask = ".".join(str(x) for x in pkt[8:12])
            self.dns1 = ".".join(str(x) for x in pkt[12:16])
            self.dns2 = ".".join(str(x) for x in pkt[16:20])
            self.dns.nameservers = [self.dns1, self.dns2]
            assert pkt.endswith(b"\x00")

            print("[FLAG SERVER] [DEBUG] Got DHCP lease", self.ip, self.gateway_ip, self.subnet_mask, self.dns1, self.dns2)

            return None

        elif len(msg) and msg.startswith(b"\x03"):
            # FREE FLAGES!!!!!!!
            self.send_flag()
            return None

        else:
            return None

    def send_flag(self):
        with open("flag.txt", "r") as f:
            flag = f.read().strip()
        curl("example.com", f"/{flag}", self.dns)
```

## Solution

After trying to puzzle all of the pieces together, we're left with a clear plan of action:
1. Forge a **DHCP offer message** and send it to the **FlagServer** to reconfigure their **DNS server** settings and have them point to us.
2. Setup our own **DNS server**, which maliciously tells the **FlagServer** that the domain `example.com` also belongs to us.
3. Setup our own web server, which is supposed to receive the messages send to `example.com` - coming from the **FlagServer**.
4. Send an other request to the **FlagServer** - this time using the `0x03`-byte message type - to make the **FlagServer** send the flag to, what they think is, `example.com`, i.e. us.
5. Receive the flag.

Now let's explore the details of each of those steps in a slightly different order - we'll start off by setting up the required infrastructure:

### The infrastructure

#### 1. Our DNS server
To be able to receive the flag, we'll need to trick the **FlagServer** into thinking we're their actual **DNS server**, such that we can also tell it that all the requests meant for `example.com` should be send to us - including the flag!

So let's set up our own **DNS server**, using a somewhat easy to configure DNS-Server implemented in python, that perfectly suits our needs:

#### 1.1. Clone the respective git repository:
```bash
$ git clone https://github.com/akapila011/DNS-Server.git && cd DNS-Server/
```

#### 1.2. Configure the server to run on the appropriate ip address:
```bash
$ vim Server.py
```

I'm running the entire exploit on a Kali virtual machine, which is configured to be **bridged** on my host machine, thus I'll have to use my `eth0`-interface ip `192.168.178.79` of that VM in this case.
```python
#!/usr/bin/env python3
import socket
from dns_generator import ClientHandler

# Global variables
IP = "192.168.178.79" # <-- Change this ip address to suit your needs
PORT = 53 # Default UPD port number for DNS; don't change this without knowingwhat you're doing, otherwise the FlagServer might not be able to reach you.

def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((IP, PORT))
    print("DNS Listening on {0}:{1} ...".format(IP, PORT))
    while True:
        data, address = sock.recvfrom(650)
        client = ClientHandler(address, data, sock)
        client.run()

if __name__ == "__main__":
    main()
```

#### 1.3. Configure a **Zone** file for the `example.com` domain, such that the **DNS server** will actually respond to requests for `example.com` and will return our public ip address:
```bash
$ vim ./Zones/example.com.zone
```
Replace the ip address `127.0.0.1` in the **A record** with your public iaddress! **Note**, in my setup, this is not the same as the ip address used fomy virtual machine!
```
{
    "$origin": "example.com",
    "$ttl": 3600,

    "a": [
        {"name": "@",
        "ttl": 400,
        "value": "127.0.0.1"
        }
    ]
}
```

#### 1.4. Running the **DNS server**
```bash
$ sudo python ./Server.py
```

#### 2. Our web server
Running our own web server is as simple as running the following command:
```python
$ python -m http.server 80
```

#### 3. Port forwarding
If you're sitting behind a firewall, you'll need to configure it to forward the ports following ports to your machine - in my case to the VM: `80/tcp` and `53/udp`. Based on your firewall/hardware configuration, you'll have to find your own instructions on how to do this.

### The logic

#### 4. Forge a **DHCP offer message** and send it to the **FlagServer** to reconfigure their **DNS server** settings and have them point to us

#### 4.1. Retrieve a **KeyStream** of the desired length including the corresponding `nonce`, that we want to reuse

// TODO

#### 4.2. Forge a message to the **FlagServer** to override their DNS-server entries

#### 4.2.1. Craft the desired packet

// TODO

#### 4.2.2. Encrypt the desired packet

// TODO

#### 4.3. Attempt to forge the **tag** for the encrypted message, compute the corresponding **checksum** and send the message to the **FlagServer**

// TODO Suvoni






#### 5. Send an other request to the **FlagServer** - this time using the `0x03`-byte message type - to make the **FlagServer** send the flag to, what they think is, `example.com`, i.e. us.

```python
# Tell the FlagServer to send the flag:
print('Make FlagServer transmit the flag to (- what they think is -) http://example.com/{flag}')
message_to_flag_server = bytearray(
	dhcp_server_mac + # src mac
	flag_server_mac + # dst mac
	b'\x03'
)
send_message_to_flag_server(message_to_flag_server)
```

#### 6. Receive the flag.

After sending the previous request to the **FlagServer**, we'll receive an incoming request to our **DNS server**:
```bash
└─$ python Server.py        
DNS Listening on 192.168.178.79:53 ...
Request from ('44.203.85.176', 57501) for example.com
```

Right after that, we'll notice an incoming request to our **web server**:
```bash
└─$ python -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
44.203.85.176 - - [15/Apr/2024 01:15:58] code 404, message File not found
44.203.85.176 - - [15/Apr/2024 01:15:58] "GET /PCTF%7Bd0nt_r3u5e_th3_n0nc3_d4839ed727736624%7D HTTP/1.1" 404 -
```

Of course, we won't know the flag in advance, so we couldn't setup a file named like the flag; thus the **web server** will clearly respond with a **404** when being asked for the specified ressource, but we can still extract the name of the requested ressource and url-decode it to receive the flag:
```python
from urllib.parse import unquote
print(unquote('PCTF%7Bd0nt_r3u5e_th3_n0nc3_d4839ed727736624%7D'))
```

And finally, there we go: `PCTF{d0nt_r3u5e_th3_n0nc3_d4839ed727736624}`

## Resources
### Networking related
- [Wikipedia: DHCP - Dynamic Host Configuration Protocol](https://en.wikipedia.org/wiki/Dynamic_Host_Configuration_Protocol)
- [Wikipedia: DNS - Domain Name System](https://en.wikipedia.org/wiki/Domain_Name_System)
- [Wikipedia: IP address](https://en.wikipedia.org/wiki/IP_address)
- [Wikipedia: MAC address](https://en.wikipedia.org/wiki/MAC_address)

### Crypto related
- [Wikipedia: SHA256](https://en.wikipedia.org/wiki/SHA-2)
- [Wikipedia: ChaCha20-Poly1305](https://en.wikipedia.org/wiki/ChaCha20-Poly1305)
- [Wikipedia: Poly1305](https://en.wikipedia.org/wiki/Poly1305)
- [Wikipedia: MAC - Message authentication code](https://en.wikipedia.org/wiki/Message_authentication_code)
