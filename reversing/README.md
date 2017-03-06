# Reversing 100 - Jumpy

The following description is given for this challenge:


> We really need access to this lab protected with an Arduino-based access control system. Our operatives obtained a flash dump from a non-personalized engineering sample, but we are having trouble reverse engineering it.
> 
> Can you help us get the password to get through?

Interacting with the board only yields an Input prompt, followed by 'Better luck next time!' every time some input is tried.

```
Input: test

Better luck next time!
```

For this challenge the unencrypted firmware file is provided so it can be analyzed. Like with any reverse engineering challenge it would be most interesting if static and dynamic analysis can be combined. For dynamic analysis it would be most conveniant to have an emulator that can interface with gdb. Luckily such an emulator exists in the form of [simavr](https://github.com/buserror/simavr/tree/master/examples/board_simduino) combined with the 'simduino' example which emulates an Arduino. 

The simduino binary will boot a provided flash ROM image.

Loading the Jumpy binary can either be done by flashing it to simduino or by creating a 'pre-flashed' flash ROM image. The pre-flashed image is much faster. The [srec_cat](http://srecord.sourceforge.net/) tool can be used to combine the bootloader image with the challenge binary.

```
srec_cat ATmegaBOOT_168_atmega328.ihex -intel Jumpy.bin -binary -o combined.hex -intel
```

The resulting 'combined.hex' file can be loaded in simduino:

```
% simduino -v -d combined.hex
read_ihex_chunks: combined.hex, unsupported check type 05
AVR: 'combined.hex' ihex contains more chunks than loaded (2)
atmega328p booloader 0x00000: 3574 bytes
avr_special_init
avr_gdb_init listening on port 1234
uart_pty_init bridge on port *** /dev/ttys009 ***
uart_pty_connect: /tmp/simavr-uart0 now points to /dev/ttys009
note: export SIMAVR_UART_XTERM=1 and install picocom to get a terminal
```

In order to get the application to run we need to attach to it using avr-gdb:

```
% /Applications/Arduino.app/Contents/Java/hardware/tools/avr/bin/avr-gdb -q
(gdb) target remote localhost:1234
Remote debugging using localhost:1234
0x00000000 in ?? ()
(gdb) c
Continuing.
```

After running this the program shows output via the /tmp/simavr-uart0 emulated serial port.

```
% picocom -fh -b19200 /tmp/simavr-uart0
Terminal ready
Input:
Better luck next time!
```

AVR is an architecture a bit different to generic Intel or ARM. 

In order to facilitate debugging I created a gdb init script [init.gdb](init.gdb). This script provides the following AVR specific functionality:

* Each time the program hits a breakpoint the AVR context r16-r30 is shown including all the AVR registers. It will also show the value of the 'meta registers X, Y and Z' which are used as data pointers in various instructions.
* A disassembly is shown automatically.
* Internally the AVR uses word aligned addresses, some tools will also use these addresses.
* GDB's standard break function does not work properly, to replace it I have created to convenience functions ab (AVR break) and wb (Word break) which can be used to set breakpoints at an AVR address or a word aligned address.

With this init.gdb file AVR debugging using avr-gdb and simduino is possible.

In order to solve the challenge the program needs to be reverse engineered. First we need to understand how the program reads it's input string to memory and where it will be stored.

To figure this out I used the following technique:

* Make sure the program is in the input loop before we press enter.
* Hit ctrl-c in gdb to pause the program
* Step through the program using the gdb single step ('nexti') function
* Identify how input is read.

Doing this yields the following piece of AVR assembly code:

```
   0x2b2:       call    0x288   ;  0x288
=> 0x2b6:       and     r24, r24
   0x2b8:       breq    .-8             ;  0x2b2
   0x2ba:       ldi     r24, 0xC6       ; 198
   0x2bc:       ldi     r25, 0x00       ; 0
   0x2be:       movw    r30, r24
   0x2c0:       ld      r24, Z
   0x2c2:       pop     r29
   0x2c4:       pop     r28
   0x2c6:       ret
```

Basically this code keeps calling the function at 0x288 until it returns a non-zero value in r24. Once it returns a non-zero value in r24 the it does some magic and loads a value from memory into register r24 and returns. It is assumed that this will be the input.

We can test this assumption by putting a breakpoint on 0x2c6 the function return instruction, typing something into the virtual serial port and seeing if the value we type indeed ends up in r24.

We set the breakpoint using the 'ab' function from init.gdb

```
(gdb) ab 0x2c6
Breakpoint 1 at 0x2c6
(gdb) c
Continuing.
```

Now we type the letter X into the virtual serial port and observe indeed the breakpoint is triggered:

```
Note: automatically using hardware breakpoints for read-only addresses.
   0x2bc:       ldi     r25, 0x00       ; 0
   0x2be:       movw    r30, r24
   0x2c0:       ld      r24, Z
   0x2c2:       pop     r29
   0x2c4:       pop     r28
=> 0x2c6:       ret
<SNIP>
Word PC: 0x163 r16: 0x0 r17: 0x1 r18: 0x0 r19: 0xff r20: 0x7f r21: 0x8e r22: 0xa0 r23: 0xf r24: 0x58 r25: 0x0 r26: 0x0 r27: 0x0 r28: 0xf2 r29: 0x2 r30: 0xc6 X: 0x0000 Y: 0x02f2 Z: 0x00c6
```

The value of the input character X which corresponds to ASCII character 0x58 ends up in r24. Meaning that we correctly identified the function which reads a single character from the serial input.

If we continue the program with a single instruction the ret instruction is executed and the context where the input is read can be seen:

```
   0x2da:       call    0x2a8   ;  0x2a8
=> 0x2de:       std     Y+3, r24        ; 0x03
   0x2e0:       ldd     r24, Y+3        ; 0x03
   0x2e2:       cpi     r24, 0x0A       ; 10
   0x2e4:       breq    .+38            ;  0x30c
   0x2e6:       ldd     r24, Y+3        ; 0x03
   0x2e8:       cpi     r24, 0x0D       ; 13
   0x2ea:       breq    .+32            ;  0x30c
<SNIP>
Word PC: 0x16f r16: 0x0 r17: 0x1 r18: 0x0 r19: 0xff r20: 0x7f r21: 0x8e r22: 0xa0 r23: 0xf r24: 0x58 r25: 0x0 r26: 0x0 r27: 0x0 r28: 0xf2 r29: 0x2 r30: 0xc6 X: 0x0000 Y: 0x02f2 Z: 0x00c6
```

This shows that the input is stored on address Y+3 which corresponds to 0x02f2+3 = 0x02f5. The code repeats reading an input character until an enter (0x0a or 0x0d) is read. Once an enter is pressed it will jump to address 0x30c to process the input.

Unfortunately there is a bug in simduino that causes only the first input byte on the serial port to be properly read. We can work around this bug by providing the input via gdb instead of via the serial port.

To simulate input via gdb I cooked up the following gdb script:

```
set $input_str = "ABC\n"
set $input_count = 0

# Fake a character was pressed
ab 0x2b6
commands
    silent
    set $r24 = 0x1
    c
end

ab 0x2c2
commands
    silent
    set $r24 = $input_str[$input_count]
    printf "Sending fake input: %c\n", $r24
    set $input_count = $input_count + 1
    c
end
```

This will send the string ABC\n to the board.

We can now run the program until it detects the \n in the input by putting a breakpoint at 0x30c:

```
Breakpoint 1 at 0x2b6
Breakpoint 2 at 0x2c2
(gdb) ab 0x30c
Breakpoint 3 at 0x30c
(gdb) c
<SNIP>
=> 0x30c:       ldd     r24, Y+1        ; 0x01
   0x30e:       ldd     r25, Y+2        ; 0x02
   0x310:       subi    r24, 0xD2       ; 210
   0x312:       sbci    r25, 0xFE       ; 254
   0x314:       movw    r30, r24
   0x316:       st      Z, r1
   0x318:       pop     r0
   0x31a:       pop     r0
   0x31c:       pop     r0
   0x31e:       pop     r29
   0x320:       pop     r28
   0x322:       ret
```

We can continue executing this for a while using single step until we get to the first check on the input:

```
   0x346:       ld      r24, Z
   0x348:       and     r24, r24
   0x34a:       brne    .-24            ;  0x334
   0x34c:       ldd     r24, Y+1        ; 0x01
=> 0x34e:       cpi     r24, 0x0D       ; 13
```

This code calculates the length of the input and compares it to 13. Now we know the correct password should have a length of 13 characters.

In input.gdb update ```set $input_str = "ABC\n"``` to ```set $input_str = "ABCDEFGHIJKLM\n"```

Now we can run the code again to see what the next check after this input length = 13 will be.

The next check we found is this:

```
=> 0x37a:       in      r28, 0x3d       ; 61
   0x37c:       in      r29, 0x3e       ; 62
   0x37e:       lds     r24, 0x0135
   0x382:       mov     r18, r24
   0x384:       ldi     r19, 0x00       ; 0
   0x386:       lds     r24, 0x0136
   0x38a:       mov     r24, r24
   0x38c:       ldi     r25, 0x00       ; 0
   0x38e:       add     r24, r18
   0x390:       adc     r25, r19
   0x392:       cpi     r24, 0xD3       ; 211
   0x394:       cpc     r25, r1
   0x396:       brne    .+20            ;  0x3ac
```

This code reads a byte from memory address 0x0135 and from address 0x0136 these values are added together and compared with 0xd3.

We can see what is at these addresses as follows:
```
(gdb) x/s 0x0135
0x800135:       "HIJKLM"
(gdb) x/s 0x0136
0x800136:       "IJKLM"
```

So what the check does is add input byte 7 and input byte 8 and check if this is equal to 0xd3. Converted to python this check is ```i[7] + i[8] == 0xd3```

For now we can fake this check is passed by putting a breakpoint at 0x392 and modifying the r24 register to 0xd3 so the check will pass.

```
(gdb) ab 0x392
Breakpoint 4 at 0x392
(gdb) c
<SNIP>
Breakpoint 4, 0x00000392 in ?? ()
(gdb) set $r24 = 0xd3
```

After stepping a bit more we can find a second check:

```
=> 0x6c4:       lds     r24, 0x0136
   0x6c8:       mov     r20, r24
   0x6ca:       ldi     r21, 0x00       ; 0
   0x6cc:       lds     r24, 0x0137
   0x6d0:       mov     r18, r24
   0x6d2:       ldi     r19, 0x00       ; 0
   0x6d4:       mul     r20, r18
   0x6d6:       movw    r24, r0
   0x6d8:       mul     r20, r19
   0x6da:       add     r25, r0
   0x6dc:       mul     r21, r18
   0x6de:       add     r25, r0
   0x6e0:       eor     r1, r1
   0x6e2:       cpi     r24, 0xC0       ; 192
   0x6e4:       sbci    r25, 0x15       ; 21
   0x6e6:       brne    .+20            ;  0x6fc
```

Translating this check to python yields: ```i[8] * i[9] == 0x15c0```

By repeating this same flow a number of times we can record all the checks that are performed, these turn out to be:

```
i[7] + i[8] == 0xd3
i[8] * i[9] == 0x15c0
i[0] * i[1] == 0x13b7
i[2] * i[3] == 0x1782
i[3] + i[4] == 0x92
i[6] * i[7] == 0x2b0c
i[5] + i[6] == 0xa5
i[9] + i[10] == 0x8f
i[1] + i[2] == 0xa7
i[10] * i[11] == 0x2873
i[12] * 13 == 0x297
i[4] * i[5] == 0x122f
i[11] + i[12] == 0xa0
```

Using z3 an input string that satisfies all these checks can be found easily. Refer to [jumpy.py](jump.py) for full solution.

```
% python jumpy.py
g1v3_1t_t0_m3
```

Entering this string into the simulator yields an empty flag on the real board it yields the flag:

```
Input: g1v3_1t_t0_m3
FLAG:a22b5049a14b23fbe81fdc329e036272
```

# Reversing 300 - The Imposter

The following description is given for this challenge:

> We have found this binary in an abandoned building. The police suspect someone set the building on fire by accident but we KNOW it was arson. Someone was trying to hide a secret plan of attack against the Republic of Wadiya. We think the binary contains the key to a safe that we were able to recover. Reverse the binary and help us find the secret key. You can be the hero we know you are!
> 
> But beware, not everything is what it seems! Wadiyan soldiers are masters of disguise so we might have an impostor on the run.

The same techniques as described above were used to get a binary that can be run using the simduino simulator. A similar approach was used to identify the input loop and the code that processes the input.

The program is a lot more complex this time and does not contain any simple checks on the input. After lots of painful debugging I identified that the binary appears to be some kind of emulator for a different architecture. I tried to identify the architecture but was unsuccesful.

A short summary of what I found during many hours of stepping through the code:

* At address 0x956 an instruction is fetched for the virtual machine
* At address 0x95c the opcode is decoded
* At address 0x972 this instruction is dispatched to a dispatcher
* The virtual architecture seems to have 8 32-bit registers and at least a zero flag (ZF)

I used this information to build a tracer script in gdb that can be used to log the execution of the code in the virtual machine.

```
set $input_count = 0
set $input_str = "ABCDEFGHIJKLMNOP\r\n"

target remote localhost:1234
set height 0
define wb
    break *(void (*)()) ($arg0*2)
end
define ab
    break *(void (*)()) ($arg0)
end

ab 0x11ca # fake serial input received
    commands
    silent
    set $r24 = 0xa
    c
end

ab 0x11d6
commands
    silent
    set $r24 = $input_str[$input_count]
    set $input_count = $input_count + 1
    c
end

wb 0x4ab # Fetch
commands
    silent
    printf "[0x%.2x%.2X] ", $r13, $r12
    c
end


wb 0x4b9 # Dispatch
commands
    silent
    printf "r0: %.8x ", * (unsigned long long*) ($r3*256 + $r2)
    printf "r1: %.8x ", * (unsigned long long*) ($r3*256 + $r2+1*4)
    printf "r2: %.8x ", * (unsigned long long*) ($r3*256 + $r2+2*4)
    printf "r3: %.8x ", * (unsigned long long*) ($r3*256 + $r2+3*4)
    printf "r4: %.8x ", * (unsigned long long*) ($r3*256 + $r2+4*4)
    printf "r5: %.8x ", * (unsigned long long*) ($r3*256 + $r2+5*4)
    printf "r6: %.8x ", * (unsigned long long*) ($r3*256 + $r2+6*4)
    printf "r7: %.8x ", * (unsigned long long*) ($r3*256 + $r2+7*4)
    printf "ZF: %.2x ", $r5
    c
end


wb 0x4ae # Fetched opcode
commands
    silent
    printf"OPCODE: 0x%.2x%.2X ", $r19, $r18
    c
end

wb 0x30d # Actual dispatch jump
commands
	silent
	printf "DISPATCH: 0x%.2x%.2X\n", $r31, $r30
	set $disp = $r31*256 + $r30
	if $disp == 0x0522
	    printf "Jump if zero\n"
	end
	c
end

```

Using this tracer the execution for various inputs can be obtained and compared. By comparing the trace for input ```'A'*16``` with that of ```'B'*16``` it can be observed what the program does.

```
grep ': 0x0522' AAAAAAAAAAAAAAAA.txt BBBBBBBBBBBBBBBB.txt
AAAAAAAAAAAAAAAA.txt:[0x039A] OPCODE: 0xd105 r0: 00000041 r1: 373d3943 r2: b4524b17 r3: fc791d6b r4: 00000000 r5: 00000000 r6: 00000000 r7: 2000085c ZF: ff DISPATCH: 0x0522
AAAAAAAAAAAAAAAA.txt:[0x0544] OPCODE: 0xd105 r0: 00000041 r1: 373d3943 r2: b4524b17 r3: 795f34a2 r4: 00000000 r5: 00000000 r6: 00000000 r7: 2000085c ZF: ff DISPATCH: 0x0522
AAAAAAAAAAAAAAAA.txt:[0x0562] OPCODE: 0xd101 r0: 00000041 r1: 373d3943 r2: 00000000 r3: 00000000 r4: 00000000 r5: 00000000 r6: 00000000 r7: 2000085c ZF: ff DISPATCH: 0x0522
BBBBBBBBBBBBBBBB.txt:[0x039A] OPCODE: 0xd105 r0: 00000042 r1: 373d3943 r2: c0670e2e r3: fc791d6b r4: 00000000 r5: 00000000 r6: 00000000 r7: 2000085c ZF: ff DISPATCH: 0x0522
BBBBBBBBBBBBBBBB.txt:[0x0544] OPCODE: 0xd105 r0: 00000042 r1: 373d3943 r2: c0670e2e r3: 795f34a2 r4: 00000000 r5: 00000000 r6: 00000000 r7: 2000085c ZF: df DISPATCH: 0x0522
BBBBBBBBBBBBBBBB.txt:[0x0562] OPCODE: 0xd101 r0: 00000042 r1: 373d3943 r2: 00000000 r3: 00000000 r4: 00000000 r5: 00000000 r6: 00000000 r7: 2000085c ZF: ff DISPATCH: 0x0522
```

It calculates a checksum based on the input and then compares that to a static 'good' checksum. For 'A'*16 this checksum is 'b4524b17' which is compared against good checksum 'fc791d6b'. The checksum is calculated in two 8 byte parts.

By analyzing the trace and correlating this with disassembly of the binary the checksum algorithm can be obtained:

```
import struct, sys
magic = [0x373d3943, 0xe2a21b5b, 0xe2a21b5b, 0x8e06fd73, 0x8e06fd73, 0x396bdf8b, 0x396bdf8b, 0xf7354e81, 0xe4d0c1a3, 0xa29a3099, 0x9035a3bb, 0x4dff12b1, 0x3b9a85d3, 0xf963f4c9, 0xe6ff67eb, 0x5ba7d770, 0x92644a03, 0x070cb988, 0x3dc92c1b, 0xb2719ba0, 0xe92e0e33, 0x5dd67db8, 0x9492f04b, 0x0c83d59b, 0x3ff7d263, 0xb7e8b7b3, 0xeb5cb47b, 0x634d99cb, 0x96c19693, 0x0eb27be3, 0x422678ab, 0xed8b5ac3, 0xed8b5ac3, 0x98f03cdb, 0x98f03cdb, 0x44551ef3, 0x44551ef3, 0xefba010b, 0xefba010b, 0xad837001, 0x9b1ee323, 0x58e85219, 0x4683c53b, 0x044d3431, 0xf1e8a753, 0x669116d8, 0x9d4d896b, 0x11f5f8f0, 0x48b26b83, 0xbd5adb08, 0xf4174d9b, 0x68bfbd20, 0x9f7c2fb3, 0x176d1503, 0x4ae111cb, 0xc2d1f71b, 0xf645f3e3, 0x6e36d933, 0xa1aad5fb, 0x199bbb4b, 0x4d0fb813, 0xf8749a2b, 0xf8749a2b, 0xa3d97c43]
my_input = sys.argv[1]
inp = list(struct.unpack("<LLLL", my_input))

for x in range(63):
    a1 = (inp[1] << 4) & 0xffffffff
    a2 = (inp[1] >> 5)
    a3 = a1 ^ a2
    a4 = (a3 + inp[1]) & 0xffffffff
    a5 = a4 ^ magic[min(x,63)]

    a6 = a5 + inp[0] & 0xffffffff
    inp[0] = inp[1]
    inp[1] = a6
print "Checksum:", hex(a6)
```

This code indeed yields the correct checksum for the given input.

```
% python checksum.py AAAAAAAAAAAAAAAA
Checksum: 0xb4524b17
% python checksum.py BBBBBBBBBBBBBBBB
Checksum: 0xc0670e2e
```

However we still do not have sufficient information to reverse the algorithm. With the current checksum implementation an 8 byte input yields a 4 byte checksum, which results in a very large number of false positives. However we do not see an additional check in the log files.

It turns out this is because when the checksum is not correct the second check on the checksum is not performed. We can work around this by manipulating the gdb trace script so that the program thinks the first input is correct.

By changing trace.gdb as follows we can alter the execution of the 0x0522 (Jump if zero) opcode.

```
wb 0x30d # Actual dispatch jump
commands
        silent
        printf "DISPATCH: 0x%.2x%.2X\n", $r31, $r30
        set $disp = $r31*256 + $r30
        if $disp == 0x0522
            printf "Jump if zero\n"
    else
        c
        end
end
```

The program now breaks as follows:
```
[0x0396] OPCODE: 0x6fBB r0: 00000042 r1: 373d3943 r2: c0670e2e r3: 2000086c r4: 00000000 r5: 00000000 r6: 00000000 r7: 2000085c ZF: 6c DISPATCH: 0x04F1
[0x0398] OPCODE: 0x429A r0: 00000042 r1: 373d3943 r2: c0670e2e r3: fc791d6b r4: 00000000 r5: 00000000 r6: 00000000 r7: 2000085c ZF: 6c DISPATCH: 0x04DB
[0x039A] OPCODE: 0xd105 r0: 00000042 r1: 373d3943 r2: c0670e2e r3: fc791d6b r4: 00000000 r5: 00000000 r6: 00000000 r7: 2000085c ZF: ff DISPATCH: 0x0522
Jump if zero
(gdb)
```

We can now set the zero flag (mapped to $r5) to zero:
```
(gdb) set $r5 = 0
```

By doing this a new check appears:

```
[0x03A6] OPCODE: 0xd003 r0: 00000042 r1: 373d3943 r2: 05e15995 r3: 924e6c8f r4: 00000000 r5: 00000000 r6: 00000000 r7: 2000085c ZF: ff DISPATCH: 0x0522
```

What happens is the checksum algorithm runs for an additional round and checks the output against '924e6c8f'.

This means for the first 8 bytes of input there are two checksums:

* After 63 rounds the checksum should be fc791d6b
* After 64 rounds the checksum should be 924e6c8f

For the second 8 bytes we find two checks as well:

* After 63 rounds the checksum should be 795f34a2
* After 64 rounds the checksum should be 0edae901

Now we finally have enough input to contruct a solution, see [imposter.py](imposter.py) for the final solution.

```
% python imposter.py
4rM_c0rT3xM0_4vR
```

Providing this input to the board yields the real flag:

```
Please enter your password
4rM_c0rT3xM0_4vR
FLAG:3f272891072dde378dee841a08c4014b
```

# Reversing 400 - FridgeJIT

Refer to the [FridgeJIT](fridgejit/README.md) section.