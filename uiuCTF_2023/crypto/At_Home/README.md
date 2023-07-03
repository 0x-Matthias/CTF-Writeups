
# At Home

## Challenge
Mom said we had food at home

### Attachments
- [chal.py](./handouts/chal.py)
 ```python
from Crypto.Util.number import getRandomNBitInteger

flag = int.from_bytes(b"uiuctf{******************}", "big")

a = getRandomNBitInteger(256)
b = getRandomNBitInteger(256)
a_ = getRandomNBitInteger(256)
b_ = getRandomNBitInteger(256)

M = a * b - 1
e = a_ * M + a
d = b_ * M + b

n = (e * d - 1) // M

c = (flag * e) % n

print(f"{e = }")
print(f"{n = }")
print(f"{c = }")
 ```
- [chal.txt](./handouts/chal.txt)
```
e = 359050389152821553416139581503505347057925208560451864426634100333116560422313639260283981496824920089789497818520105189684311823250795520058111763310428202654439351922361722731557743640799254622423104811120692862884666323623693713
n = 26866112476805004406608209986673337296216833710860089901238432952384811714684404001885354052039112340209557226256650661186843726925958125334974412111471244462419577294051744141817411512295364953687829707132828973068538495834511391553765427956458757286710053986810998890293154443240352924460801124219510584689
c = 67743374462448582107440168513687520434594529331821740737396116407928111043815084665002104196754020530469360539253323738935708414363005373458782041955450278954348306401542374309788938720659206881893349940765268153223129964864641817170395527170138553388816095842842667443210645457879043383345869
```

## Solution
In this challenge we are offered an encrypted flag `c = (flag * e) % n` and given the values for `c`, `e` and `n`. Solving these kinds of equations may be computationally expensive if not for the fact, that in this case `flag * e < n` holds and thus the flag can be easily computed by rearranging the aforementioned equation: `flag = c / e`.

### Proof of `flag * e < n`
Assuming each asterisks in the fake flag `flag = int.from_bytes(b"uiuctf{******************}", "big")` corresponds to exactly one ascii character in the flag, the biggest interger we could possibly achieve for `flag` is replacing all the asterisks with the byte 0x7f, thus:
```python
maxFlag = int.from_bytes(b"uiuctf{\x7f\x7f\x7f\x7f\x7f\x7f\x7f\x7f\x7f\x7f\x7f\x7f\x7f\x7f\x7f\x7f\x7f\x7f}", "big")
print((maxFlag * e).bit_length()) # 973
print(n.bit_length()) # 1022
```
Because the bit-length of an integer directly correlates to their maximum value, `(maxFlag * e) < n` holds. ∎

### Computing the flag
```python
integerFlag = (c // e)
print(integerFlag.to_bytes(len(b"uiuctf{******************}"), 'big').decode('ascii')) # uiuctf{W3_hav3_R5A_@_h0m3}
```
