# Crypto 200 - Key Server

The following description is given for this challenge:

```
We have received a portable asymmetric key storage for evaluation purposes. 
This portable device was manufactured by Ebian Corp to facilitate secure communications with customers. It generates and stores adminstrators' public keys. 
Customers can use this repository to find the public key of the admin they want to contact, and administrators can use this repository to update their key information. 
If this fancy keychain passes the test we are going to give them away like candy, secure candy.
```

Interacting with the board yields the following:

```
Ebian Corp has a repository to store its adminstrators' public keys.
1)If you are a customer you can list all the public keys.
2)If you are an admin you can update your keys.
Just sign the plaintext "admin" and more options will be provided.
The parameters to be used for the signature are SHA1 and PKCS1_v1_5
1
Public Key List:
Alice:
00c90e4c65c0a96080df5aaf73caaf1146afb364cb37894f6bb745182191bf577a2777d8b5dbf57b2ad9f902e2d3abadfe6ebeb7366d7b11f0cbfd4371dbadf5f548e60644b3365a654b8efe2de32bbb1cc0288d367c0e8cf9ac8a2544cb067f677c87e82362e3b3ce950d072c5b1baffd650a31db4ff7d7209f0aec0178d7ba8b
Bob:
00db87e4a4774c4c4606faadeb58460d6c62282aced115ae9d256d6ca2d32b49615c9257869aa0b1757b8faaae401f94474ddbf5f54b75dfaa7bef370cc9842a920ff9484cabacece44e7c2c80c2c97775a39d035c59475db93374cbac0d0e4f0830bcc51fe4680ef1d8afce89d61ef7a1fe8f03dd26a7049303f1cbfa94b10323
Carl:
00a8e4fe8ddca1a4b8c97376d90e43e78f9df822412215511fa3efc3f96b34c6bdc2090dbbfce2e118ff8168c6ba1ed965f743238467310c97d22918c4549d9c426641469a57ed75557367ad37d3c73485a5d748bbcea211897f72f60e7fbd6bb220e6e56e466dcc3144abb78388865ee5c9bba879ea96c0a2522bdb63383f3591
David:
00b7a2434673e546ff4d7975166a5228e19aa5b43ab79e147f27695aeeeb197bb3152ef1df0b8190a7304b4db49cffdf6f0cdd168f47594d2fd0672787716ae519bf78df1cb96c0968785e7f0ec7de1008644b3cc32c74748f0d0967cdc76b7bba0cb78a15858bcc40063e53c34bb47cf63ba2eb8af3d491131f2aa96388802677
Edward:
00b7882ac1f039ce5c9cef7a66800d2247c465cd5bcbaa80cc48ba34ec2759280a666432f78f53d222a308ea2dc7d455be7d050faeca3fd9847fb43dbaf2a09013778e238b7a79430271c105cb959f3ff4d0e72a756ecc948bc27e1b1dc7dafb3fae6e31c2571c89f06ac854cac98d10e106ec89abd4d093f28e13db54ea8798b3
Fleur:
00cec274724b04bda96d51162abf710fbf1eedb978aa87639e61a166b772cf4bdfc8fdddb3b700b366d68767a5d33cce4e6146fe325de5d9d0dc480dbd4201c3859d1debbf952a1e3a10c0cfeb6413f740748c7a43a346d895c12bf7b14068df33be376b12527b1c7fb390f95d0f878ebb8a38c621eb415a85bf42b9cbcaccc749
Gary:
00bdb08ad1d97628b0d4e9bdcdb0303007e66b9d82b3ca3e7df476911f1d0ffd81f67487b4fafc4e252b30c501055335ab74f1e92e411615b5263d5117daf715740f826a6f8faba2620ddda2852a3595aa9f051d3e0b46766440360f986cc2db7b7f2d9431e9324280109ac1ed43900a57531ee2878e895c6f5b4ba4311051413d
```

The board provides 6 RSA public keys and asks us to sign something. The first thing that comes to mind if that it might be possible to obtain a private key because two of the public keys share a common factor. To try this out we simply need to calculate the GCD between all pairs of keys.

If we do this indeed we see that Bob's and Gary's key both share a common factor:

```
12740687396952811643088941494602600474970968740910907077064852670904845297490889090164936902229457369083527167233513652960298164731764863857925799725451573
```

Wrote a script to obtain the signature: [key_server.py](key_server.py)

Once the signature has been obtained we can send it to board, to make things a bit annoying it only accepts it if we use \r as EOL:

```
hackbox:crypto1:% python key_server.py
Found common factor in db87e4a4774c4c4606faadeb58460d6c62282aced115ae9d256d6ca2d32b49615c9257869aa0b1757b8faaae401f94474ddbf5f54b75dfaa7bef370cc9842a920ff9484cabacece44e7c2c80c2c97775a39d035c59475db93374cbac0d0e4f0830bcc51fe4680ef1d8afce89d61ef7a1fe8f03dd26a7049303f1cbfa94b10323
Signature for admin: 43b3d362a0683e0ec7ddde2b0748276bafcd03d8933299dd672765290b106be710ef26a7154eaf1f6805f1ea812b65faab1393f300f28b460070d68c420f4c5326b4d65e486887453d6b74cc7daae2755687701f7708c41f8d2a1380ab8a142fa4991a8e1e58ab6c675778203ea5e3f5f064c0c0500477ef373a5a4607d7e0e3
hackbox:crypto1:% (sleep 1; echo -en '2\r'; sleep 1; echo -en '43b3d362a0683e0ec7ddde2b0748276bafcd03d8933299dd672765290b106be710ef26a7154eaf1f6805f1ea812b65faab1393f300f28b460070d68c420f4c5326b4d65e486887453d6b74cc7daae2755687701f7708c41f8d2a1380ab8a142fa4991a8e1e58ab6c675778203ea5e3f5f064c0c0500477ef373a5a4607d7e0e3\r') | nc 127.0.0.1 1235
Ebian Corp has a repository to store its adminstrators' public keys.
1)If you are a customer you can list all the public keys.
2)If you are an admin you can update your keys.
Just sign the plaintext "admin" and more options will be provided.
The parameters to be used for the signature are SHA1 and PKCS1_v1_5
Enter the signature
FLAG:cf2194c3103a2b2c69b5be67e6b10bff
```


# Crypto 100 - Secure Filesystem

The following description is given for this challenge:

```
We don't remember why, but we wanted a file system on an AVR328p. After the system was completed we discovered that it lacked basic security. A couple of beers later we came up with what we think is a revolutionary way to do file system permissions. It is now your task to fill in our shoes and test its security.

The filesystem allows you to request the contents of one or more available files by using the following
format:

token#<filename>[:<filename>]

So for example, a request would be:

933d86ae930c9a5d6d3a334297d9e72852f05c57#cat.txt:finances.csv

Some example files (token | call):

96103df3b928d9edc5a103d690639c94628824f5 | cat.txt
933d86ae930c9a5d6d3a334297d9e72852f05c57 | cat.txt:finances.csv
83f86c0ba1d2d5d60d055064256cd95a5ae6bb7d | cat.txt:finances.csv:joke.txt
ba2e8af09b57080549180a32ac1ff1dde4d30b14 | cat.txt:joke.txt
0b939251f4c781f43efef804ee8faec0212f1144 | finances.csv
4b0972ec7282ad9e991414d1845ceee546eac7a1 | finances.csv:joke.txt
715b21027dca61235e2663e59a9bdfb387ca7997 | joke.txt

Can you access any file you're not supposed to?
```

Interacting with the board yields the following:

```
RHMeOS file API
Files in system:

drwxrwxr-x remote remote 4096 sep  1 .
drwxrwxr-x remote remote 4096 sep  1 ..
-r--r--r-- remote remote   87 sep 14 cat.txt
-r--r--r-- remote remote   47 sep 16 finances.csv
-r--r--r-- remote remote    3 sep 14 joke.txt
-rw------- root   root     37 jan  5 passwd
-rw------- root   root      8 jan  1 pepper

 Request?
```

We can indeed enter one of the example requests shown in the challenge description and get, for example, the file cat.txt:

```
>> 96103df3b928d9edc5a103d690639c94628824f5#cat.txt

 cat.txt:
  A_A
 (-.-)
  |-|
 /   \
|     |   __
|  || |  |  \__
 \_||_/_/

```

Looking at the input string the first thing that comes to mind is a hash length extension attack. The provided hash values are 40 hex characters = 160 bits in length. This could be SHA-1. We can use standard tools like [hashpump](https://github.com/bwall/HashPump) to perform the length extension attack on SHA-1. The only thing required to perform this attack is the length of the secret prefix. We can write a simple script to try all possible values for this length.

See [file_server.py](file_server.py) for the implemented solution.

Running this provides the flag for prefix length 8

```
8

 passwd:
FLAG:2bdb3e0df152165690fd099eda0f6529
```

# Crypto 150 - Secure Filesystem v1.92r1

The following description is given for this challenge:

```
After the horrible debacle of the first file system, we got together again, invited our friend Mr. Wodka and waterproofed the secure file system. You can test it again, but this time it uses unbreakable encryption.

The filesystem allows you to request the contents of one or more available files by using the following
format:

token#<filename>[:<filename>]

So for example, a request would be:

897703036b2e18116b36353d92ac3dd978845fc99a735b8a3a3a9b3cc5239fdf4572157296903a0237a4aaeeaa8f3d15#joke.txt

Some example files (token | call):

897703036b2e18116b36353d92ac3dd978845fc99a735b8a |
dfd0f4a25b7d529e89ac030c2b681e93831e95a8186823b9 | cat.txt
897703036b2e18116b36353d92ac3dd978845fc99a735b8a |
f2bca35d472116dc6d5bebe96f1a3af249be78c63219a0dc | cat.txt:finances.csv
897703036b2e18116b36353d92ac3dd978845fc99a735b8a |
7eed666977d3861dbaefd16b2ed7dc5b639e51853ca6e7b3 | cat.txt:finances.csv:joke.txt
897703036b2e18116b36353d92ac3dd978845fc99a735b8a |
51d915246394ce976f8768cf3300087cb5b9958bbec30f9c | cat.txt:joke.txt
897703036b2e18116b36353d92ac3dd978845fc99a735b8a |
ae2a5a38b4d03f0103bce59874e41a0df19cb39b328b02fa | finances.csv
897703036b2e18116b36353d92ac3dd978845fc99a735b8a |
c66b5e48f5e600982724eca3804fb59b7b0f395a6e17e1ce | finances.csv:joke.txt
897703036b2e18116b36353d92ac3dd978845fc99a735b8a |
3a3a9b3cc5239fdf4572157296903a0237a4aaeeaa8f3d15 | joke.txt

Can you access any file you're not supposed to?
```

Interacting with the board yields the following:

```
RHMeOS file API V1.92r1
Files in system:

drwxrwxr-x remote remote 4096 sep  1 .
drwxrwxr-x remote remote 4096 sep  1 ..
-r--r--r-- remote remote   87 sep 14 cat.txt
-r--r--r-- remote remote   47 sep 16 finances.csv
-r--r--r-- remote remote    3 sep 14 joke.txt
-rw------- root   root     37 jan  5 passwd
-rw------- root   root      8 jan  1 pepper

 Request?
```
 
 We can indeed enter one of the example requests shown in the challenge description and get, for example, the file cat.txt:

```
>> 897703036b2e18116b36353d92ac3dd978845fc99a735b8adfd0f4a25b7d529e89ac030c2b681e93831e95a8186823b9#cat.txt

 cat.txt:
  A_A
 (-.-)
  |-|
 /   \
|     |   __
|  || |  |  \__
 \_||_/_/

```

One thing that stands out is that this takes a very long time (about 10 seconds) this might indicate that a more complex algorithm is being used this time.

Also it is noted that for all requests two large numbers are provided. This matches with the [DSA algorithm](https://en.wikipedia.org/wiki/Digital_Signature_Algorithm) where a signature consists of a random number r and a signature s. 

It is a known problem that if the same random number r is used multiple times this can be used to obtain the private key.

However to perform this attack we first need to know a parameter called q which is a large random prime number. This parameter is not provided in the challenge text.

The trick to obtaining q is by reading the standard Wikipedia pseudo-code for signature validation which starts with the step: ```Reject the signature if 0 < r < q or 0 < s < q is not satisfied.```

We can use this perform a binary search on the value of q simply by trying various values for r and seeing if they are accepted (meaning the guess is smaller than q) or rejected (meaning the guess is larger or equal to q).

The following script implements the binary search:

```
import time
from sock import Sock

mi = 0x000000000000000000000000000000000000000000000000
ma = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
s = Sock('127.0.0.1',1235)
print s.read_until('>> ')
while True:
    pivot = (mi + ma) / 2
    print (mi, ma)
    msg = '%.48X%.48X#bier' % (pivot,pivot)
    print '%.48X' % (pivot)
    t = time.time()
    s.send(msg + '\r\n')
    reply = s.read_until('>> ', timeout=20)
    print repr(reply)
    delta = time.time() - t
    if delta > 5: # q = larger than pivot
        mi = pivot
        print delta, "guess too low or correct"
    else:
        ma = pivot
        print delta, "guess too high"
```

The value for q is recovered as: 0xFFFFFFFFFFFFFFFFFFFFFFFF99DEF836146BC9B1B4D22831

We can now implement the standard DSA re-used r attack. Refer to [securefs_192.py](securefs_192.py)

This correctly computes the checksum for passwd:

```
hackbox:crypto3:% python solve.py
897703036b2e18116b36353d92ac3dd978845fc99a735b8a14c4c3df4f358d1c55bbd35f30543f80ea6b7f3cdb27eac0#passwd
hackbox:crypto3:% ncat -C 127.0.0.1 1235


RHMeOS file API V1.92r1
Files in system:

drwxrwxr-x remote remote 4096 sep  1 .
drwxrwxr-x remote remote 4096 sep  1 ..
-r--r--r-- remote remote   87 sep 14 cat.txt
-r--r--r-- remote remote   47 sep 16 finances.csv
-r--r--r-- remote remote    3 sep 14 joke.txt
-rw------- root   root     37 jan  5 passwd
-rw------- root   root      8 jan  1 pepper

 Request?

>> 897703036b2e18116b36353d92ac3dd978845fc99a735b8a14c4c3df4f358d1c55bbd35f30543f80ea6b7f3cdb27eac0#passwd

 passwd:
FLAG:4da3a36299a658148d8d1f23aeed4827
```