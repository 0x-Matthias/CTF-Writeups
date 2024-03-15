import json
import requests

baseURI = 'http://94.237.53.26:37873/'

def regenerate():
	'''
	Reset the entire game.
	'''
	requests.post(baseURI + 'regenerate')

def newMap():
	'''
	Requests the data for the current map.
	'''
	resp = requests.post(baseURI + 'map')
	if resp.status_code != 200:
		print('Failed request in newMap:', resp.text)
	return json.loads(resp.text)

def make_move(move):
	'''
	Make a move [U(p), D(own), L(eft), R(ight)] and receive the updated map.
	'''
	if move not in ['U', 'D', 'L', 'R']:
		print('ERROR: Invalid move', move)
	resp = requests.post(baseURI + 'update', json = { 'direction' : move })
	if resp.status_code != 200:
		print('Failed request in move:', resp.text)
	return json.loads(resp.text)

class Tile:
	def __init__(self, x, y, terrain, has_weapon):
		self.x = x
		self.y = y
		self.terrain = terrain
		self.has_weapon = has_weapon
		self.total_cost = -1
		self.origin = None
		self.move_to_get_here = None

def parseTiles(tilesJson, width, height):
	'''
	Parses the json of the tiles property.
	'''
	return [[Tile(x, y, tilesJson[f'({x}, {y})']['terrain'], tilesJson[f'({x}, {y})']['has_weapon']) for y in range(height)] for x in range(width)]

class MovementInfo:
	def __init__(self, target, origin, move, cost):
		self.target = target
		self.origin = origin
		self.move = move
		self.cost = cost

def getMovementCost(origin, target, move):
	'''
	Return -1 for invalid moves.
	Return the movement cost, if the move is valid.
	'''
	if target.terrain == 'E':
		return -1
	elif target.terrain == 'C' and move in ['L', 'U']:
		return -1
	elif target.terrain == 'G' and move in ['R', 'D']:
		return -1
	# Pains <-> Mountain
	elif origin.terrain == 'P' and target.terrain == 'M':
		return 5
	elif origin.terrain == 'M' and target.terrain == 'P':
		return 2
	# Plains <-> Sand
	elif origin.terrain == 'P' and target.terrain == 'S':
		return 2
	elif origin.terrain == 'S' and target.terrain == 'P':
		return 2
	# Plains <-> River
	elif origin.terrain == 'P' and target.terrain == 'R':
		return 5
	elif origin.terrain == 'R' and target.terrain == 'P':
		return 5
	# Mountain <-> Sand
	elif origin.terrain == 'M' and target.terrain == 'S':
		return 5
	elif origin.terrain == 'S' and target.terrain == 'M':
		return 7
	# Mountain <-> River
	elif origin.terrain == 'M' and target.terrain == 'R':
		return 8
	elif origin.terrain == 'R' and target.terrain == 'M':
		return 10
	# Sand <-> River
	elif origin.terrain == 'S' and target.terrain == 'R':
		return 8
	elif origin.terrain == 'R' and target.terrain == 'S':
		return 6
	else:
		return 1

def addNeighbourTiles(origin, tiles, exploration_stack, height, width):
	if origin.x > 0:
		move = 'L'
		new_tile = tiles[origin.x - 1][origin.y]
		cost = getMovementCost(origin, new_tile, move)
		if cost >= 0:
			exploration_stack += [MovementInfo(new_tile, origin, move, cost)]
	if origin.y > 0:
		move = 'U'
		new_tile = tiles[origin.x][origin.y - 1]
		cost = getMovementCost(origin, new_tile, move)
		if cost >= 0:
			exploration_stack += [MovementInfo(new_tile, origin, move, cost)]
	if origin.x < width - 1:
		move = 'R'
		new_tile = tiles[origin.x + 1][origin.y]
		cost = getMovementCost(origin, new_tile, move)
		if cost >= 0:
			exploration_stack += [MovementInfo(new_tile, origin, move, cost)]
	if origin.y < height - 1:
		move = 'D'
		new_tile = tiles[origin.x][origin.y + 1]
		cost = getMovementCost(origin, new_tile, move)
		if cost >= 0:
			exploration_stack += [MovementInfo(new_tile, origin, move, cost)]

def solveMap():
	'''
	Solves a single map.
	'''
	# Get and parse map:
	map = newMap()
	height = map['height']
	width = map['width']
	player_start_pos_x = map['player']['position'][0]
	player_start_pos_y = map['player']['position'][1]
	max_time = map['player']['time']
	tiles = parseTiles(map['tiles'], width, height)
	# Find a way to a weapon (depth first search):
	tiles[player_start_pos_x][player_start_pos_y].total_cost = 0 # player position
	exploration_stack = []
	addNeighbourTiles(tiles[player_start_pos_x][player_start_pos_y], tiles, exploration_stack, height, width)
	while len(exploration_stack) > 0:
		current = exploration_stack.pop()
		# Only update and process current.target, if we improve and stay within the max_time constraint.
		if (current.target.total_cost == -1 or current.target.total_cost > current.origin.total_cost + current.cost) and max_time >= current.origin.total_cost + current.cost:
			current.target.total_cost = current.origin.total_cost + current.cost
			current.target.origin = current.origin
			current.target.move_to_get_here = current.move
			addNeighbourTiles(current.target, tiles, exploration_stack, height, width)
			if current.target.has_weapon:
				break
	# Backtrack the solution:
	solution = []
	current_tile = current.target
	while current_tile.origin != None:
		solution = [current_tile.move_to_get_here] + solution
		current_tile = current_tile.origin
	for move in solution:
		resp = make_move(move)
		#print(resp)
	print(f'Solution #{resp["maps_solved"]}:', solution)
	# After sending all moves, the last response should specify the current map 'solved':
	if resp['maps_solved'] == 0 or resp['solved'] != True:
		print('ERROR Did not solve the map:', resp)
		exit()
	if resp['maps_solved'] == 100:
		print('Flag:', resp['flag']) #HTB{i_h4v3_mY_w3ap0n_n0w_dIjKStr4!!!}
		exit()

# Restart the challenge
regenerate()
# Solve 100 maps:
for _ in range(100):
	solveMap()
