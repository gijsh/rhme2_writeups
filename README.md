# Introduction

From November 2016 till February 2017 Riscure ran the 'first embedded hardware CTF, round two.' also called RHME2. RHME2 is a hardware based CTF where Riscure ships each participant an Arduino Nano board containing a custom bootloader that can be used to flash encrypted challenges to the board. These challenges need to be solved using various hardware and software techniques.

I participated in this CTF and got second place after the HydraBus team. This repository contains [my](https://twitter.com/gijs_h) writeups for the [Riscure RHME2](http://rhme.riscure.com/) Challenge.

# Writeups

The writeups are split up per category:

* [Exploitation](exploit/README.md)
* [Reversing](reversing/README.md)
* [Side channel analysis](sca/README.md)
* [Crypto](crypto/README.md)
* [Fault injection](fi/README.md)
* [Misc](misc/README.md)
* [FridgeJIT](fridgejit/README.md)

# Interfacing with the board

There are various ways to interface with the board. The technique I used almost everywhere is to create a TCP to serial bridge using [socat](http://www.dest-unreach.org/socat/) and then interfacing over TCP, mostly using hellman's [sock.py library](https://github.com/hellman/sock). Most of the exploit code in this repository assumes that there is a socat TCP to serial bridge running on port 1235. If you want to try the exploits the following socat command can be used to run this bridge:

```
socat -v -x file:/dev/ttyUSB0,b19200,raw tcp-listen:1235,reuseaddr
```