# MultiDigilingual

## Challenge
It's a known secret that each faction speaks different languages, however few can speak all of them. KORP has long wanted to send a spy in the factions to keep an eye on them. Through their extensive network, they have found different talented factionless to test. The first to show their multidigilingual skills will get a place in them, and be their secret agent amongst the factions. Can you show them your worth?

## Solution
When connecting to this challenge, we're greeted with a prompt to input a polyglot, that reads [and outputs!] the flag from `flag.txt` in multiple programming languages: C, C++, PHP8, Perl, Ruby and Python3:
```
****************************************
*   How many languages can you talk?   *
* Pass a base64-encoded program that's *
*   all of the below that just reads   *
*      the file `flag.txt` to win      *
*          and pass the test.          *
*                                      *
*              Languages:              *
*               * Python3              *
*               * Perl                 *
*               * Ruby                 *
*               * PHP8                 *
*               * C                    *
*               * C++                  *
*                                      *
*   Succeed in this and you will be    *
*               rewarded!              *
****************************************
```

Using the examples of the provided resources, we can manage to assemble a polyglot of our own that satisfies the condition of the challenge:

```
#include/*
#<?php echo file_get_contents('./flag.txt'); ?>

q="""*/<stdlib.h>
#define xstr(s) str(s)
#define str(s) #s
#define command cat flag.txt
int main(){system(xstr(command));}/*=;
open(FH,'<','flag.txt');print <FH>;#";exec('cat flag.txt')#""";print(open('flag.txt').read())#*/
```

The basic gists of this solution are to 
1. use comments in a clever way to disable specific parts of the code for different languages and
2. use strings to contain other parts of the code, which would otherwise cause problems in the respective language.

Let's break this down using the syntax highlighting for the different lanugages:

### Python3
```python
#include/*
#<?php echo file_get_contents('./flag.txt'); ?>

q="""*/<stdlib.h>
#define xstr(s) str(s)
#define str(s) #s
#define command cat flag.txt
int main(){system(xstr(command));}/*=;
open(FH,'<','flag.txt');print <FH>;#";exec('cat flag.txt')#""";print(open('flag.txt').read())#*/
```
Python3 uses three techniques:
- A couple of end-of-line comments `#`.
- Usage of the possibility to declare strings using three consecutive quote-signs (`"""`) at the the beginning and the end of a multi-line string.
- The possibility to place multiple statements on the same line using the semicolon as a statement-terminator.

This way the excess code is declared to be the content of a string or marked as a comment.

### Perl
Unfortunately, the syntax highlighting for Perl ain't accurate, so I split the code to better represent what's going to happen:
```perl
#include/*
#<?php echo file_get_contents('./flag.txt'); ?>

q="""*/<stdlib.h>
#define xstr(s) str(s)
#define str(s) #s
#define command cat flag.txt
int main(){system(xstr(command));}/*=;
```
```perl
open(FH,'<','flag.txt');print <FH>;#";exec('cat flag.txt')#""";print(open('flag.txt').read())#*/
```
Perl uses two techniques:
- A couple of end-of-line comments `#`.
- And some bit, I still don't quite understand: At the end of the first code block, somehow the command ends without any syntax error and thus the second code block executes nicely.

### Ruby
```ruby
#include/*
#<?php echo file_get_contents('./flag.txt'); ?>

q="""*/<stdlib.h>
#define xstr(s) str(s)
#define str(s) #s
#define command cat flag.txt
int main(){system(xstr(command));}/*=;
open(FH,'<','flag.txt');print <FH>;#";exec('cat flag.txt')#""";print(open('flag.txt').read())#*/
```
Ruby also uses three techniques:
- A couple of end-of-line comments `#`.
- The possibility to concatenate string by placing them next to each other (i.e. `q="1""2"` equals `q="12"`), thus starting a string with three consecutive quote-signs basically acts as a normal string definition and the string ends with the next `"`-sign.
- The possibility to place multiple statements on the same line using the semicolon as a statement-terminator.

This way the excess code is declared to be the content of a string or marked as a comment.

### PHP
Because the syntax highlighting for php is even less accurate, I'll resort to the html highlighting in this case:
```html
#include/*
#<?php echo file_get_contents('./flag.txt'); ?>

q="""*/<stdlib.h>
#define xstr(s) str(s)
#define str(s) #s
#define command cat flag.txt
int main(){system(xstr(command));}/*=;
open(FH,'<','flag.txt');print <FH>;#";exec('cat flag.txt')#""";print(open('flag.txt').read())#*/
```
PHP basically uses a single technique:
- Everything outside of the `<?php`, `?>` tags is considered to be html content which won't be interpreted by php.

So this would be the only bit getting executed in php and merging the flag content into the rest of the html output:
```php
<?php echo file_get_contents('./flag.txt'); ?>
```

### C & C++
Many things, that work in C, also compile in C++, so we can use a combined solution for these two languages:
```C
#include/*
#<?php echo file_get_contents('./flag.txt'); ?>

q="""*/<stdlib.h>
#define xstr(s) str(s)
#define str(s) #s
#define command cat flag.txt
int main(){system(xstr(command));}/*=;
open(FH,'<','flag.txt');print <FH>;#";exec('cat flag.txt')#""";print(open('flag.txt').read())#*/
```
C and C++ use three techniques again:
- Block comments, starting with `/*` and ending in `*/`.
- The ability to use block comments in the middle of a statementand the statement still works.
- Using multi-stage pre-processor statements to supply a string argument to the `system` function without the need to use a double-quote `"`, because at this point, this would end the `q`-string defined in Ruby prematurely and thus break the Ruby solution.


### The flag
Finally we can retrieve the flag by sending the polyglot as a base64 encoded string:
```python
from pwn import *
from base64 import b64encode

server = '83.136.255.150'
port = 32848

polyglot = open('polyglot.c').read().replace('\r\n', '\n')

conn = remote(server, port)
print(conn.readuntil(b'Enter the program of many languages: ').decode())
conn.writeline(b64encode(polyglot.encode()))
print(conn.readuntil(b'}').decode())
conn.close()
```
And thus we receive our flag `HTB{7he_ComMOn_5yM8OL5_Of_l4n9U49E5_C4n_LE4d_7O_m4ny_PolY9lO7_WoNdeR5}`.

## Resources
- Wikipedia: Polyglot (computing):
  - [Definition of a polyglot](https://en.wikipedia.org/wiki/Polyglot_(computing))
  - [Example for a polyglot in C, PHP and Bash](https://en.wikipedia.org/wiki/Polyglot_(computing)#C,_PHP,_and_Bash)
- A polyglot combining C, C++, Python3, Perl and Ruby:
  - [On Twitter / X](https://twitter.com/takesako/status/998063456279449601)
  - [On Github](https://github.com/floyd-fuh/C-CPP-Perl-Ruby-Python-Polyglot/blob/master/original/original.c)