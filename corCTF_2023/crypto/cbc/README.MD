
# cbc

## Challenge
who on earth is putting CLASSICAL BORING CRYPTOGRAPHY in my ctf

### Attachments
- [cbc_output.txt](./handouts/cbc_output.txt)
```
iv = 'RLNZXWHLULXRLTNP'
ct = 'ZQTJIHLVWMPBYIFRQBUBUESOOVCJHXXLXDKPBQCUXWGJDHJPQTHXFQIQMBXNVOIPJBRHJQOMBMNJSYCRAHQBPBSMMJWJKTPRAUYZVZTHKTPUAPGAIJPMZZZDZYGDTKFLWAQTSKASXNDRRQQDJVBREUXFULWGNSIINOYULFXLDNMGWWVSCEIORQESVPFNMWZKPIYMYVFHTSRDJWQBTWHCURSBPUKKPWIGXERMPXCHSZKYMFLPIAHKTXOROOJHUCSGINWYEILFIZUSNRVRBHVCJPVPSEGUSYOAMXKSUKSWSOJTYYCMEHEUNPJAYXXJWESEWNSCXBPCCIZNGOVFRTGKYHVSZYFNRDOVPNWEDDJYITHJUBVMWDNNNZCLIPOSFLNDDWYXMYVCEOHZSNDUXPIBKUJIJEYOETXWOJNFQAHQOVTRRXDCGHSYNDYMYWVGKCCYOBDTZZEQQEFGSPJJIAAWVDXFGPJKQJCZMTPMFZDVRMEGMPUEMOUVGJXXBRFCCCRVTUXYTTORMSQBLZUEHLYRNJAAIVCRFSHLLPOANFKGRWBYVSOBLCTDAUDVMMHYSYCDZTBXTDARWRTAFTCVSDRVEENLHOHWBOPYLMSDVOZRLENWEKGAWWCNLOKMKFWWAZJJPFDSVUJFCODFYIMZNZTMAFJHNLNMRMLQRTJJXJCLMQZMOFOGFPXBUTOBXUCWMORVUIIXELTVIYBLPEKKOXYUBNQONZLPMGWMGRZXNNJBUWBEFNVXUIAEGYKQSLYSDTGWODRMDBHKCJVWBNJFTNHEWGOZFEZMTRBLHCMHIFLDLORMVMOOHGXJQIIYHZFMROGUUOMXBTFMKERCTYXFIHVNFWWIUFTGLCKPJRFDRWDXIKLJJLNTWNQIOFWSIUQXMFFVIIUCDEDFEJNLKLQBALRKEYWSHESUJJXSHYWNRNPXCFUEFRJKSIGXHFTKNJXSYVITDOGYIKGJIOOHUFILWYRBTCQPRPNOKFKROTFZNOCZXZEYUNWJZDPJDGIZLWBBDGZJNRQRPFFGOTGFBACCRKLAPFLOGVYFXVIIJMBBMXWJGLPOQQHMNBCINRGZRBVSMLKOAFGYRUDOPCCULRBE'
```
- [cbc.py](./handouts/cbc.py)
```python
import random

def random_alphastring(size):
    return "".join(random.choices(alphabet, k=size))

def add_key(key, block):
    ct_idxs = [(k_a + pt_a) % len(alphabet) for k_a, pt_a in zip([alphabet.index(k) for k in key], [alphabet.index(pt) for pt in block])]
    return "".join([alphabet[idx] for idx in ct_idxs])

def cbc(key, plaintext):
    klen = len(key)
    plaintext = pad(klen, plaintext)
    iv = random_alphastring(klen)
    blocks = [plaintext[i:i+klen] for i in range(0, len(plaintext), klen)]
    prev_block = iv
    ciphertext = ""
    for block in blocks:
        block = add_key(prev_block, block)
        prev_block = add_key(key, block)
        ciphertext += prev_block
    return iv, ciphertext
    
def pad(block_size, plaintext):
    plaintext += "X" * (-len(plaintext) % block_size)
    return plaintext

alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
bs = 16

message = open("message.txt").read().upper()
message = "".join([char for char in message if char in alphabet])
flag = open("flag.txt").read()
flag = flag.lstrip("corctf{").rstrip("}")
message += flag
assert all([char in alphabet for char in message])

key = random_alphastring(bs)
iv, ct = cbc(key, pad(bs, message))
print(f"{iv = }")
print(f"{ct = }")
```

## Solution
In this challenge we are offered an encrypted flag and given the cource code for the encryption, which uses a random encryption key.

### Analysis
Analyzing the source code and the output, we can determine some constants, that we are going to use to decrypt the ciphertext:
```python
alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
bs = 16
iv = 'RLNZXWHLULXRLTNP'
ciphertext = 'ZQTJIHLVWMPBYIFRQBUBUESOOVCJHXXLXDKPBQCUXWGJDHJPQTHXFQIQMBXNVOIPJBRHJQOMBMNJSYCRAHQBPBSMMJWJKTPRAUYZVZTHKTPUAPGAIJPMZZZDZYGDTKFLWAQTSKASXNDRRQQDJVBREUXFULWGNSIINOYULFXLDNMGWWVSCEIORQESVPFNMWZKPIYMYVFHTSRDJWQBTWHCURSBPUKKPWIGXERMPXCHSZKYMFLPIAHKTXOROOJHUCSGINWYEILFIZUSNRVRBHVCJPVPSEGUSYOAMXKSUKSWSOJTYYCMEHEUNPJAYXXJWESEWNSCXBPCCIZNGOVFRTGKYHVSZYFNRDOVPNWEDDJYITHJUBVMWDNNNZCLIPOSFLNDDWYXMYVCEOHZSNDUXPIBKUJIJEYOETXWOJNFQAHQOVTRRXDCGHSYNDYMYWVGKCCYOBDTZZEQQEFGSPJJIAAWVDXFGPJKQJCZMTPMFZDVRMEGMPUEMOUVGJXXBRFCCCRVTUXYTTORMSQBLZUEHLYRNJAAIVCRFSHLLPOANFKGRWBYVSOBLCTDAUDVMMHYSYCDZTBXTDARWRTAFTCVSDRVEENLHOHWBOPYLMSDVOZRLENWEKGAWWCNLOKMKFWWAZJJPFDSVUJFCODFYIMZNZTMAFJHNLNMRMLQRTJJXJCLMQZMOFOGFPXBUTOBXUCWMORVUIIXELTVIYBLPEKKOXYUBNQONZLPMGWMGRZXNNJBUWBEFNVXUIAEGYKQSLYSDTGWODRMDBHKCJVWBNJFTNHEWGOZFEZMTRBLHCMHIFLDLORMVMOOHGXJQIIYHZFMROGUUOMXBTFMKERCTYXFIHVNFWWIUFTGLCKPJRFDRWDXIKLJJLNTWNQIOFWSIUQXMFFVIIUCDEDFEJNLKLQBALRKEYWSHESUJJXSHYWNRNPXCFUEFRJKSIGXHFTKNJXSYVITDOGYIKGJIOOHUFILWYRBTCQPRPNOKFKROTFZNOCZXZEYUNWJZDPJDGIZLWBBDGZJNRQRPFFGOTGFBACCRKLAPFLOGVYFXVIIJMBBMXWJGLPOQQHMNBCINRGZRBVSMLKOAFGYRUDOPCCULRBE'
blocks = [ciphertext[i:i+bs] for i in range(0, len(ciphertext), bs)]
```

Additionally we can analyze the encryption logic (c.f. [cbc.py](./handouts/cbc.py)); here are some observations:
1. The algorithm uses a block-size of 16 characters: `bs = 16`.
2. The alphabet used in this cipher is only using uppercase letters.
3. The plaintext is being padded with "X" until its length equals a multiple of 16, as can be seen in the `pad`-function.
4. The `key` and the initial-vector `iv` are generated randomly; both of which are of length `16`; conforming to the block-size.
    ```python
    iv = random_alphastring(klen)
    [...]
    key = random_alphastring(bs)
    ```
5. Looking at the `cbc`-function,
    ```python
    prev_block = iv
    for block in blocks:
        block = add_key(prev_block, block)
        prev_block = add_key(key, block)
    ```
    we can deduce
    - ... the usage of a cipher block chaining mode; meaning that the initial-vector is used to encrypt the first block of the message and the ciphertext of the first block is used to encrypt the second block and so on.
    - ... that the same function `add_key` is used to process the current message block with their respective `initial-vector` and the `key`.
6. Having a closer look at the `add_key`-function, we can see, that this is just a simple rotational substitution-cipher, reminding us of the `Vigenère`-cipher.
```python
def add_key(key, block):
    ct_idxs = [(k_a + pt_a) % len(alphabet) for k_a, pt_a in zip([alphabet.index(k) for k in key], [alphabet.index(pt) for pt in block])]
    return "".join([alphabet[idx] for idx in ct_idxs])
```
The tricky bit about this implementation though is the fact, that we are using two keys (`iv` and `key`), and the `iv` is changing with each block.

### Strategy for decryption
As typical with rotational ciphers, when you use the same cipher to perform 2 encryption passes with different keys `key1` and `key2`, you can instead swap the order of encryptions because addition is commutative. Thus the following expressions will always evaluate to the same value:
```python
add_key(iv, add_key(key, block))
add_key(key, add_key(iv, block))
add_key(block, add_key(iv, key)) # not used in this solution
```
This means, that we can reverse the `iv` encryption separately from the `key` encryption. Therefore we can write an inverse functions for `add_key`:
```python
def subtract_key(key, block):
	ct_idxs = [(pt_a - k_a) % len(alphabet) for k_a, pt_a in zip([alphabet.index(k) for k in key], [alphabet.index(pt) for pt in block])]
	return "".join([alphabet[idx] for idx in ct_idxs])
```

Now we can compute the differences (using `subtract_key`) between adjacent blocks to decode the iv encryption for each block:
```python
def differences(iv, blocks):
	ds = []
	prev_block = iv
	for block in blocks:
		d = subtract_key(prev_block, block)
		ds += [d]
		prev_block = block
	return ds

block_differences = differences(iv, blocks)
print(''.join(block_differences)) # IFGKLLEKCBSKNPSCRLBSMXHTSJNIJPSUHCQOHMKGJBEAWKMETQXIEAGWPFRESHZATIKKEAGWPLQWXKUCRGZUGLEALXJASVNAANIYGYBVYKTLQWRJIPRNEAGWPFRJTVZLORBHTLBPYPXOYGLSNVLYMKXNXYTPWCSFETXDHLAGJCQAJENKPQKUGLHHSCTHQAESNEQYHFBPYDMQXARREOJQWWNUWCTHGASFEIKKVGKGDFAOXJDJLWQYEAMKWPZJIXHRANPOLLXOULLLTPDLTUZEFHKKKFMCFHTJLQPQLVXHAKDZGAOMSKUCTFREGJOQYGQSSGOIKMGCELCEKKDBVGOIBGGQXQGALPTQYUQUFWOGJVCWDYHRHQRJKWTNAWHJLKSRHTLKZZTRWZTHNCQRUTKEYWOGFQRPMGUCRUFEGGYIFRVDNEGGSYFTXDRWKBCPTFZWIULVMWGESIKAINHLUZXDWETPQLEEYUTQETPQKWGQLXVWWGSFAVFJBKUCKFBWQNXRHGDDNKRULBLZJXDJORBTUQMJWDMQUTNHEEQJAWKGJBZHQAHQANFDNPTPVQGAXGOCORIUTJXWKFMCNVASTKQYLBNULXOWWVNDTJBIRKMGEQGADWRCLKKKQALVZBJAWPDJTJBFKGZTSJHJYJDQYUQUFLACLXKHTEZREUQXXETEZFMAXTDQOWOSXKMQLEDKYJDPPTLWKSFULEZPDQTPUPQXXCXTFBKEXCMCSUBDMATNHXQPTHZLORBHTLBPYPXOYGLZUVRIXDXUKYXEYUDJFKQSTFHPDVEQSESGOPFDMZXEGKSACVNDAELCIDXVWLOAWCSGNIPOLLXODFMQCKRLOTJQEDRWKBCESENKBKKQMAHPOFSDYJDENWLFXJTVAKFODUSCMVEUPZHNWPXOYGLGSDXIBUTNDVFJZYHRHNFDNPTFVBCKWIMSLKKKQSENLEDOTEZJLGABBFNZVFRPWKASTKLDLSKGJBZHQACGSVOYUMMKGKRKKIMSLKKKQSGAOXXDJTDAOOBIMZXHDXFEYUDTETVJAAGISCSAWVGGSCQBXSLVAQRJTVZEEPBHBUKQLQGEWVDCNEEQEDXPYBHCZGRQ
```

At this point `block_differences` is only encrypted using the unknown `key`, so we are dealing with a classical `Vigenère`-cipher.

Now there's two options to proceed:

#### Option 1: The manual way
The first step in breaking the Vigenère cipher is to determine the key length, which we already know is 16.

The next step involves grouping all characters of the cipher-text by their `index % 16` (the key-length). At this point, we're left with 16 different groups of letters, where each group corresponds to the one character of `key` that shares their index. Thus the group `i` would correspond to `key[i]`:
```python
group_i = [block_differences[x] for x in range(len(block_differences)) if x % 16 == i]
```

This allows us to break 16 individual `Caesar`-ciphers using the letter-frequencies of the english language and the letters contained in this group, by trying to guess the `key[i]` s.t. the letter frequencies between both the english language and the letters contained of group i align best. Repeat this process for each group to recover the entire `key`.

After recovering the entire `key`, one can simply decode the `block_differences` by applying the key to each block separately:
```python
decoded_blocks = [subtract_key(key, block) for block in block_differences]
print(''.join(decoded_blocks))
```

#### Option 2: The automated way
There are plenty of tools available to automatically break and decrypt a ciphertext, that has been encrypted using the `Vigenère`-cipher.

My tool of choice, called [CrypTool](https://www.cryptool.org/en/), cracked the Vigenère part with ease and determined the key to be `ACXQTSTCSXZWFCZY` and thus the message:

`IDJUSTLIKETOINTERJECTFORAMOMENTWHATYOUREREFERINGTOASLINUXISINFACTGNULINUXORASIVERECENTLYTAKENTOCALLINGITGNUPLUSLINUXLINUXISNOTANOPERATINGSYSTEMUNTOITSELFBUTRATHERANOTHERFREECOMPONENTOFAFULLYFUNCTIONINGGNUSYSTEMMADEUSEFULBYTHEGNUCORELIBSSHELLUTILITIESANDVITALSYSTEMCOMPONENTSCOMPRISINGAFULLOSASDEFINEDBYPOSIXMANYCOMPUTERUSERSRUNAMODIFIEDVERSIONOFTHEGNUSYSTEMEVERYDAYWITHOUTREALIZINGITTHROUGHAPECULIARTURNOFEVENTSTHEVERSIONOFGNUWHICHISWIDELYUSEDTODAYISOFTENCALLEDLINUXANDMANYOFITSUSERSARENOTAWARETHATITISBASICALLYTHEGNUSYSTEMDEVELOPEDBYTHEGNUPROJECTTHEREREALLYISALINUXANDTHESEPEOPLEAREUSINGITBUTITISJUSTAPARTOFTHESYSTEMTHEYUSELINUXISTHEKERNELTHEPROGRAMINTHESYSTEMTHATALLOCATESTHEMACHINESRESOURCESTOTHEOTHERPROGRAMSTHATYOURUNTHEKERNELISANESSENTIALPARTOFANOPERATINGSYSTEMBUTUSELESSBYITSELFITCANONLYFUNCTIONINTHECONTEXTOFACOMPLETEOPERATINGSYSTEMLINUXISNORMALLYUSEDINCOMBINATIONWITHTHEGNUOPERATINGSYSTEMTHEWHOLESYSTEMISBASICALLYGNUWITHLINUXADDEDORGNULINUXALLTHESOCALLEDLINUXDISTRIBUTIONSAREREALLYDISTRIBUTIONSOFGNULINUXANYWAYHERECOMESTHEFLAGITSEVERYTHINGAFTERTHISATLEASTITSNOTAGENERICROTTHIRTEENCHALLENGEIGUESS`

Unfortunately there is no punctuation in the message, so we have to carefully read the text to determine the value of the flag, which, according to the `cbc.py` was stripped of its tags `corctf{` and `}`. This process yields us the flag:

`corctf{ATLEASTITSNOTAGENERICROTTHIRTEENCHALLENGEIGUESS}`