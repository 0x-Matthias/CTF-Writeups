# The PROM

## Challenge
After entering the door, you navigate through the building, evading guards, and quickly locate the server room in the basement. Despite easy bypassing of security measures and cameras, laser motion sensors pose a challenge. They're controlled by a small 8-bit computer equipped with AT28C16 a well-known EEPROM as its control unit. Can you uncover the EEPROM's secrets?

## Solution
In this challenge we are given virtual access to an AT28C16 EEPROM and need to find the flag hidden inside that device.

First we need to set READ-mode on the device, to be able to read data from it. According to the documentation of the eeprom, `!CE` and `!OE` need to be low and `!WE` needs to be set to high voltage. To achieve this, we have access to the commands `set_ce_pin`, `set_oe_pin` and `set_we_pin`. Note, that these commands set CE, OE and WE directly, whereas the documentation specifies the values for their inverted inputs! After looking up the proper voltages for the respective pins, we need to call these three commands to achieve READ-mode:
```
set_ce_pin(6)
set_oe_pin(13)
set_we_pin(0)
```
NOTE: Contrary to the actual CTF, during the after-party event of the CTF, these functions did change their behaviour and set the voltages on the inverted pins! Thus we'd need to call this set of commands instead!
```
set_ce_pin(0)
set_oe_pin(0)
set_we_pin(6)
```

To read a single byte of the memory, we first need to set the address, that we want to read from using `set_address_pins(A10, A9, A8, A7, A6, A5, A4, A3, A2, A1, A0)`, where `Ai` needs to be replaced with the voltage for the respective address pin (A10 being the most significant bit). Turns out, we can use `0` for the low voltage and `6` for the high voltage again, which corresponds to a set address bit. Afterwards we can call `read_byte()` to receive the value of the corresponding byte.

Looping through the entire memory of the device, each byte returns the value `0`.

Turns out, the at28c16 has a special memory region used for device identification containing 32 bytes. To access this, we must set the address pin `A9` to 13 volts and otherwise read the memory addresses 0x7E0 up to and excluding 0x800. Printing the data read from this memory region yields the flag: `HTB{AT28C16_EEPROM_s3c23t_1d!!!}`

## Resources
- [Python solver script (CTF version)](./solver.py)
- [Data sheet for the EEPROM at28c16 (hosted by CVA Group, Stanford University)](http://cva.stanford.edu/classes/cs99s/datasheets/at28c16.pdf)