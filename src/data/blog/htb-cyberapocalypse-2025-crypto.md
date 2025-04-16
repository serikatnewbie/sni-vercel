---
author: azuketto
pubDatetime: 2025-04-17T14:00:00Z
title: HTB Cyber Apocalypse 2025 - Cryptography
slug: htb-cyberapocalpyse-2025-cryptography
featured: false
draft: false
tags:
  - write-up
description:
  HTB Cyber Apocalypse 2025 Cryptography writeup by azuketto
---


# Cyber Apocalypse CTF 2025

I participated in this CTF with team [SNI](https://ctftime.org/team/279998/), and I managed to solve all of the Cryptography problems presented. We finished at the 9th place, and we managed to get some prizes. This is a brief write up for those challenges, and they are ordered based on which challenges were solved first.

## Table of contents

## Cry/Prelim
This is a challenge regarding a decryption of a permutation group.
```python=
from random import shuffle
from hashlib import sha256
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

n = 0x1337
e = 0x10001

def scramble(a, b):
    return [b[a[i]] for i in range(n)]

def super_scramble(a, e):
    b = list(range(n))
    while e:
        if e & 1:
            b = scramble(b, a)
        a = scramble(a, a)
        e >>= 1
    return b

message = list(range(n))
shuffle(message)

scrambled_message = super_scramble(message, e)

flag = pad(open('flag.txt', 'rb').read(), 16)

key = sha256(str(message).encode()).digest()
enc_flag = AES.new(key, AES.MODE_ECB).encrypt(flag).hex()

with open('tales.txt', 'w') as f:
    f.write(f'{scrambled_message = }\n')
    f.write(f'{enc_flag = }')
```

As usual when dealing with unusual groups, we can just calculate the order of the group, and do decryption by getting the *power* of the element to be `1` modulo the order. In this case, we can calculate a multiple of the order easily, which is `n!`, as this takes into account all possible permutation cycle lengths of the members of the array.

```python=
from hashlib import sha256
from random import shuffle
from Crypto.Cipher import AES
from tqdm import trange

def scramble(a, b):
    return [b[a[i]] for i in range(n)]

def super_scramble(a, e):
    b = list(range(n))
    while e:
        if e & 1:
            b = scramble(b, a)
        a = scramble(a, a)
        e >>= 1
    return b

def decrypt_flag(original_message, enc_flag):
    key = sha256(str(original_message).encode()).digest()
    cipher = AES.new(key, AES.MODE_ECB)
    enc_flag_bytes = bytes.fromhex(enc_flag)
    flag = cipher.decrypt(enc_flag_bytes)

    return flag

scrambled_message = []
enc_flag = b'' 
buf = open('tales.txt').read()
exec(buf)
e = 0x10001
n = 0x1337

pr = 1
for c in trange(1,n):
    pr *= c

d = pow(e, -1, pr)

original = super_scramble(scrambled_message, d)
print(decrypt_flag(original, enc_flag))


# HTB{t4l3s_fr0m___RS4_1n_symm3tr1c_gr0ups!}
```

## Cry/Traces
This is similar to a classical cipher challenge, where we must do some manual decryption. The only thing we need to realize in the challenge is that the encryption done for all messages are done with the same stream from the AES CTR.

```python=
def encrypt(self, msg):
        encrypted_message = AES.new(self.key, AES.MODE_CTR, counter=Counter.new(128)).encrypt(msg)
        return encrypted_message
    
def join_channel(self, args):
        channel = args[1] if len(args) > 1 else None
        
        if channel not in CHANNEL_NAMES:
            err(f':{self.host} 403 guest {channel} :No such channel')
            return

        key = args[2] if len(args) > 2 else None

        channel = channel[1:]
        requires_key = CHANNELS[channel]['requires_key']
        channel_key = CHANNELS[channel]['key']

        if (not key and requires_key) or (channel_key and key != channel_key):
            err(f':{self.host} 475 guest {channel} :Cannot join channel (+k) - bad key')
            return
        
        for message in MESSAGES[channel]:
            timestamp = message['timestamp']
            sender = message['sender']
            print(f'{timestamp} <{sender}> : ', end='')
            self.output_message(message['body'])
        
        while True:
            warn('You must set your channel nickname in your first message at any channel. Format: "!nick <nickname>"')
            inp = input('guest > ').split()
            if inp[0] == '!nick' and inp[1]:
                break

        channel_nickname = inp[1]
        while True:
            timestamp = datetime.now().strftime('%H:%M')
            msg = input(f'{timestamp} <{channel_nickname}> : ')
            if msg == '!leave':
                break
```

Then, we see multiple encrypted messages when joining a channel. We know that they will exit the channel by typing `!leave`, and enter the channel by typing `!nick <nickname>`, and we can get some initial data for manual decryption with this.

Eventually, after A LOT of time, I managed to decrypt messages from the general channel and the secret channel.

```
Known all: b'!nick Doomfang'
Known all: b'!nick Stormbane'
Known all: b'!nick Runeblight'
Known all: b"We've got a new tip about the rebels. Let's keep our chat private."
Known all: b'Understood. Has there been any sign of them regrouping since our last move?'
Known buf: b"Not yet, but I'm checking some unusual signals. If they sense us, we might have to chan"
Known all: b"This channel is not safe for long talks. Let's switch to our private room."
Known all: b'Here is the passphrase for our secure channel: %mi2gvHHCV5f_kcb=Z4vULqoYJ&oR'
Known all: b'Got it. Only share it with our most trusted allies.'
Known all: b'Yes. Our last move may have left traces. We must be very careful.'
Known all: b"I'm checking our logs to be sure no trace of our actions remains."
Known all: b"Keep me updated. If they catch on, we'll have to act fast."
Known buf: b"I'll compare the latest data with our backup plan. We must erase any sign we were here."
Known all: b'If everything is clear, we move to the next stage. Our goal is within reach.'
Known all: b"Hold on. I'm seeing strange signals from outside. We might be watched."
Known all: b"We can't take any risks. Let's leave this channel before they track us."
Known all: b'Agreed. Move all talks to the private room. Runeblight, please clear the logs here.'
Known buf: b"Understood. I'm disconnecting now. If they have seen us, we must disappear immediately."
Known all: b'!leave'
Known all: b'!leave'
Known all: b'!leave'
```

```
Known all: b'!nick Doomfang'
Known all: b'!nick Stormbane'
Known all: b'!nick Runeblight'
Known all: b'We should keep our planning here. The outer halls are not secure, and too many eyes watch the open channels.'
Known all: b"Agreed. The enemy's scouts grow more persistent. If they catch even a whisper of our designs, they will move against us. We must not allow their seers or spies to track our steps."
Known buf: b"I've been studying the traces left behind by our previous incantations, and something feels wrong. Our network of spells has sent out signals to an unknown beacon-one that none of "
Known buf: b"I'm already cross-checking our spellwork against the ancient records. If this beacon was part of an older enchantment, I'll find proof. But if it is active now, then we have a prob"
Known buf: b"We cannot afford hesitation. If this is a breach, then the High Council's forces may already be on our trail. Even the smallest mistake could doom our entire campaign. We must conf"
Known buf: b'Exactly. And even if we remain unseen for now, we need contingency plans. If the Council fortifies its magical barriers, we could lose access to their strongholds. Do we have a sec'
Known all: b'Yes, but we must treat it only as a last resort. If we activate it too soon, we risk revealing its location. It is labeled as: HTB{Crib_Dragging_Exploitation_With_Key_Nonce_Reuse!}'
Known buf: b'Good. No record of it must exist in the written tomes. I will ensure all traces are erased, and it shall never be spoken of openly. If the enemy ever learns of it, we will have no '
Known all: b'Agreed. The more we discuss it, the greater the risk. Every moment we delay, the Council strengthens its defenses. We must act soon before our window of opportunity closes.'
Known buf: b'We should end this meeting and move to a more secure sanctum. If their mages or spies are closing in, they may intercept our words. We must not take that chance. Let this be the la'
Known all: b'!leave'
Known all: b'!leave'
Known all: b'!leave'
```

## Cry/Copperbox
This is a straightforward coppersmith challenge.
```python=
import secrets

p = 0x31337313373133731337313373133731337313373133731337313373133732ad
a = 0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef
b = 0xdeadc0dedeadc0dedeadc0dedeadc0dedeadc0dedeadc0dedeadc0dedeadc0de

def lcg(x, a, b):
    while True:
        yield (x := a*x + b)

flag = open('flag.txt', 'rb').read()
x = int.from_bytes(flag + secrets.token_bytes(30-len(flag)), 'big')
gen = lcg(x, a, b)

h1 = next(gen) * pow(next(gen), -1, p) % p
h2 = next(gen) * pow(next(gen), -1, p) % p

with open('output.txt', 'w') as o:
    trunc = 48
    # oops, i forgot the last part
    o.write(f'hint1 = {h1 >> trunc}\n')
    o.write(f'hint2 = {h2 >> trunc}\n')
```

We know `256-48` bits of `h1` and `h2`, and we have relations of the lcg on one variable `x`. We just find resultants on `x`, then do coppersmith on unknowns of `h1` and `h2`. After recovering `h1` and `h2`, we can do simple equation manipulation to recover the flag.
```python=
p = 0x31337313373133731337313373133731337313373133731337313373133732ad

a = 0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef
b = 0xdeadc0dedeadc0dedeadc0dedeadc0dedeadc0dedeadc0dedeadc0dedeadc0de

def lcg(x, a, b):
    while True:
        yield (x := a*x + b)

P.<X, Y, Z> = PolynomialRing(ZZ)
hint1 = 77759147870011250959067600299812670660963056658309113392093130 * pow(2, 48)
hint2 = 50608194198883881938583003429122755064581079722494357415324546 * pow(2, 48)
hx1 = hint1 + Y
hx2 = hint2 + Z
k1 = a * X + b
k2 = a * k1 + b
k3 = a * k2 + b
k4 = a * k3 + b

eq1 = k2 * hx1 - k1
eq2 = k4 * hx2 - k3

print("Getting resultant")
eq = eq1.resultant(eq2, X)
print("Resultant found")

print("Changing ring")
eq = eq.change_ring(Zmod(p))
print("AAA")
print(eq)
eql = list(eq)
print(eql)
print(eql[0][0])
P2.<A, B> = PolynomialRing(Zmod(p))
eq = A * B * int(eql[0][0]) + A * int(eql[1][0]) + B * int(eql[2][0]) + int(eql[3][0])

rs1 = coppersmith_multivariate_heuristic(eq, [2**48, 2**48], beta=1)
print(rs1)
guess = int(rs1[0][0] % p)
print(guess)
print(int(rh1) - int(h1))

h1 = guess + hint1

lhs = power_mod(h1, -1, p) - a
lhs = lhs * power_mod(b, -1, p)
k1 = power_mod(lhs, -1, p)
x = (k1 - b) * power_mod(a, -1, p) % p

from libnum import n2s
print(n2s(int(x)))
```

## Cry/Hourcle
Another AES oracle that feels very similar to decryption oracle.
```python=
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import os, string, random, re

KEY = os.urandom(32)

password = ''.join([random.choice(string.ascii_letters+string.digits) for _ in range(20)])

def encrypt_creds(user):
    padded = pad((user + password).encode(), 16)
    IV = os.urandom(16)
    cipher = AES.new(KEY, AES.MODE_CBC, iv=IV)
    ciphertext = cipher.decrypt(padded)
    return ciphertext

def admin_login(pwd):
    return pwd == password

def show_menu():
    return input('''
=========================================
||                                     ||
||   🏰 Eldoria's Shadow Keep 🏰       ||
||                                     ||
||  [1] Seal Your Name in the Archives ||
||  [2] Enter the Forbidden Sanctum    ||
||  [3] Depart from the Realm          ||
||                                     ||
=========================================

Choose your path, traveler :: ''')

def main():
    while True:
        ch = show_menu()
        print()
        if ch == '1':
            username = input('[+] Speak thy name, so it may be sealed in the archives :: ')
            pattern = re.compile(r"^\w{16,}$")
            if not pattern.match(username):
                print('[-] The ancient scribes only accept proper names-no forbidden symbols allowed.')
                continue
            encrypted_creds = encrypt_creds(username)
            print(f'[+] Thy credentials have been sealed in the encrypted scrolls: {encrypted_creds.hex()}')
        elif ch == '2':
            pwd = input('[+] Whisper the sacred incantation to enter the Forbidden Sanctum :: ')
            if admin_login(pwd):
                print(f"[+] The gates open before you, Keeper of Secrets! {open('flag.txt').read()}")
                exit()
            else:
                print('[-] You salt not pass!')
        elif ch == '3':
            print('[+] Thou turnest away from the shadows and fade into the mist...')
            exit()
        else:
            print('[-] The oracle does not understand thy words.')

if __name__ == '__main__':
    main()
```

Our input is appended with the password, and we are given the decryption output. IV is not given, but as input length is not limited, it is not an issue. Notice that we can get the AES block decryption value of each block of input other than the first, simply by xoring the block with the previous block.

The strategy is similar to AES decryption oracle, and we can recover one (the first) character as follows. Craft some `junk = '0'*15`, and create payload `block + (junk + guess_ch) + junk`. The third block will have `junk + first_pw_char`, and we can just change guesses until it matches the second AES block decryption.

```python=
from azunyan.conn import remote, process
from tqdm import tqdm
from pwn import xor
import string
charset = string.ascii_letters+string.digits

# r = process(['python3', 'server.py'])
r = remote('94.237.52.11', 37585)
k = r.recvline().strip().decode()
print(k)
def oracle(uname: str):
    r.sendlineafter(b'::', b'1')
    r.sendlineafter(b'::', uname.encode())
    res = r.recvafter(b':', bytes)
    return res
    
known = ''
while len(known) < 16:
    for char in tqdm(charset):
        guess = known + char
        junk = '0' * (16 - len(guess))
        
        data = '0' * 16 + junk + guess + junk
        
        res = oracle(data)
        
        data = data.encode()
        dec2 = xor(data[:16], res[16:32])
        dec3 = xor(data[16:32], res[32:48])
        if dec2 == dec3:
            known = guess
            print(f"Known = {known}")
            break
            
while len(known) < 20:
    f = False
    for char in tqdm(charset):
        guess = known + char
        guess = guess[-16:]
        junk = '0' * (31 - len(known))
        data = '0' * 16 + guess + junk
        
        # datapw = data + k
        # print(data[:16], data[16:32], datapw[32:48], datapw[48:64], datapw[64:])
        # exit(0)
        res = oracle(data)

        data = data.encode() + known.encode()
        dec2 = xor(data[:16], res[16:32])
        dec3 = xor(data[16:32], res[32:48])
        dec4 = xor(data[32:48], res[48:64])
        if dec2 == dec4:
            f = True
            known += char
            print(f"Known2 = {known}")
            break
    if not f:
        print("Fail")
        break
    
    
r.sendlineafter(b'::', b'2')
r.sendlineafter(b'::', known.encode())
r.interactive()
#HTB{encrypting_with_CBC_decryption_is_as_insecure_as_ECB___they_also_both_fail_the_penguin_test_b1b752b3539859e1de6d2d782d120ec0}
```

## Cry/Twin Oracles
Chall is centered around two LSB oracles, an RSA LSB oracle that is obsfucated by an LCG LSB oracle.

```python=
from Crypto.Util.number import *

FLAG = bytes_to_long(open('flag.txt', 'rb').read())

MENU = '''
The Seers await your command:

1. Request Knowledge from the Elders
2. Consult the Seers of the Obsidian Tower
3. Depart from the Sanctum
'''

class ChaosRelic:
    def __init__(self):
        self.p = getPrime(8)
        self.q = getPrime(8)
        self.M = self.p * self.q
        self.x0 = getPrime(15)
        self.x = self.x0
        print(f"The Ancient Chaos Relic fuels the Seers' wisdom. Behold its power: M = {self.M}")
        
    def next_state(self):
        self.x = pow(self.x, 2, self.M)
        
    def get_bit(self):
        self.next_state()
        return self.extract_bit_from_state()
    
    def extract_bit_from_state(self):
        return self.x % 2


class ObsidianSeers:
    def __init__(self, relic):
        self.relic = relic
        self.p = getPrime(512)
        self.q = getPrime(512)
        self.n = self.p * self.q
        self.e = 65537 
        self.phi = (self.p - 1) * (self.q - 1)
        self.d = pow(self.e, -1, self.phi)

    def sacred_encryption(self, m):
        return pow(m, self.e, self.n)

    def sacred_decryption(self, c):
        return pow(c, self.d, self.n)

    def HighSeerVision(self, c):
        return int(self.sacred_decryption(c) > self.n//2)
    
    def FateSeerWhisper(self, c):
        return self.sacred_decryption(c) % 2
    
    def divine_prophecy(self, a_bit, c):
        return self.FateSeerWhisper(c) if a_bit == 0 else self.HighSeerVision(c)
        
    def consult_seers(self, c):
        next_bit = self.relic.get_bit()
        response = self.divine_prophecy(next_bit, c)
        return response
    


def main():
    print("You stand before the Seers of the Obsidian Tower. They alone hold the knowledge you seek.")
    print("But be warned—no force in Eldoria can break their will, and their wisdom is safeguarded by the power of the Chaos Relic.")
    my_relic = ChaosRelic()
    my_seers = ObsidianSeers(my_relic)
    counter = 0

    while counter <= 1500:
        print(MENU)
        option = input('> ')

        if option == '1':
            print(f"The Elders grant you insight: n = {my_seers.n}")
            print(f"The ancient script has been sealed: {my_seers.sacred_encryption(FLAG)}")
        elif option == '2':
            ciphertext = int(input("Submit your encrypted scripture for the Seers' judgement: "), 16)
            print(f'The Seers whisper their answer: {my_seers.consult_seers(ciphertext)}')
        elif option == '3':
            print("The doors of the Sanctum close behind you. The Seers watch in silence as you depart.")
            break
        else:
            print("The Seers do not acknowledge your request.")
            continue

        counter += 1

    print("The stars fade, and the Seers retreat into silence. They shall speak no more tonight.")

if __name__ == '__main__':
    main()
```

Solving is pretty straightforward. Notice that the seed for the LCG is very small, we can just bruteforce this and match the output of the overall oracle. We can extract the LCG state by sending decryption of `1`, where outputs are clearly always `0` or `1` and can be mapped to the LCG state. Then, it is a simple RSA LSB oracle.

```python=
from Crypto.Util.number import *
from azunyan.conn import remote, process

possible_x = []

for i in range(2 ** 14 + 1, 2 ** 15):
    if isPrime(i) and i.bit_length() == 15:
        possible_x.append(i)
        
# possible_x = [0]
        
#r = process(['python3', 'server.py'])#, level='debug')
r = remote('83.136.249.227', 39892)
M = r.recvafter(b'M =', int)

class RNG:
    def __init__(self, seed: int):
        self.M = M
        self.x = seed
        
    def next_state(self):
        self.x = pow(self.x, 2, self.M)
        
    def get_bit(self):
        self.next_state()
        return self.extract_bit_from_state()
    
    def extract_bit_from_state(self):
        return self.x % 2


def transform():
    global possible_x
    x_ = []
    for x in possible_x:
        num = pow(x, 2, M)
        x_.append(num)
    possible_x = x_
    
def check(lsb: int):
    global possible_x
    x_ = set()
    for x in possible_x:
        if x % 2 == lsb:
            x_.add(x)
    possible_x = list(x_)

def get_ct():
    r.sendlineafter(b'>', b'1')
    n = r.recvafter(b'n =', int)
    ct = r.recvafter(b':', int)
    return n, ct

def oracle(ct: int):
    r.sendlineafter(b'>', b'2')
    r.sendlineafter(b':', hex(ct).encode())
    res = r.recvafter(b':', int)
    return res

n, ct = get_ct()

while len(possible_x) > 1:
    res = not oracle(1)
    transform()
    check(res)
    print('x', len(possible_x))
    
x = possible_x[0]
print(f'{x=}')
rng = RNG(x)
for _ in range(2):
    k = rng.get_bit()
    res = not oracle(1)
    assert k ==res

lower = 0
upper = n - 1

i = 0
while lower < upper:
    mid = (lower + upper) // 2
    k = rng.get_bit()
    if k == 1:
        res = oracle(ct)
    ct = (pow(2, 0x10001, n) * ct) % n
    if k == 0:
        res = oracle(ct)

    if res == 0: upper = mid
    else: lower = mid + 1
    i += 1
    print(i, end='\r')
    
from libnum import n2s
print(n2s(lower-1))

#HTB{1_l0v3_us1ng_RS4_0r4cl3s___3v3n_4_s1ngl3_b1t_1s_3n0ugh_t0_g3t_m3_t0_3ld0r14!_d433bdfb1211dd52622c7b7dff636f10}
```

## Cry/Verilicious
This chall is very straightforward, simple HNP.

```python=
from Crypto.Cipher import PKCS1_v1_5
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA
from Crypto.Util.number import getPrime, long_to_bytes as l2b, bytes_to_long as b2l
from random import seed, randbytes
from data import R, s

seed(s)

class Verilicious:
    def __init__(self):
        self.key = RSA.import_key(open('privkey.pem', 'rb').read())
        self.cipher = PKCS1_v1_5.new(self.key, randbytes)

    def verify(self, c):
        c = b'\x00'*(self.key.n.bit_length()//8-len(c)) + c
        return int(self.cipher.decrypt(c, sen := get_random_bytes(self.key.n.bit_length()//8)) != sen)

    def encrypt(self, m):
        return self.cipher.encrypt(m)

orac = Verilicious()

enc_flag = orac.encrypt(open('flag.txt', 'rb').read()).hex()

assert all(orac.verify(l2b(pow(r, orac.key.e, orac.key.n) * int(enc_flag, 16) % orac.key.n)) for r in R)

import os ; os.system('openssl rsa -in privkey.pem -pubout -out pubkey.pem')

with open('output.txt', 'w') as f:
    f.write(f'{enc_flag = }\n')
    f.write(f'{R = }\n')

```

Notice the equation `r * Flag = int(b'\x00\x02...') % n` because of the PKCSv1 padding verification. This is exactly the definition of HNP.

```python=
from sage.all import *
from azunyan.sage.lll import babai_cvp
from Crypto.PublicKey import RSA
from libnum import n2s, s2n

pub = RSA.import_key(open('pubkey.pem', 'rb').read())
n = pub.n
print(f"Import key {n.bit_length()}")
enc_flag = ''
R = []
buf = open('output.txt').read()
exec(buf)

print("Exec done")
R = R[:]
M = [R]
for i in range(len(R)):
    l = [0] * len(R)
    l[i] = n
    M.append(l)
    
M = Matrix(ZZ, M)
print("Matrix formed")
lower = s2n(b'\x00\x02' + b'\x00' * 126)
upper = s2n(b'\x00\x02' + b'\xff' * 126)
lb = [lower] * len(R)
ub = [upper] * len(R)
target = [(lower + upper) // 2] * len(R)

print("Starting LLL")
L = M.LLL()
target = vector(ZZ, target)
res = babai_cvp(L[1:], target)
flag1 = res[0] * pow(R[0], -1, n) % n
flag2 = res[1] * pow(R[1], -1, n) % n
assert(flag1 == flag2)
print(n2s(int(flag1)))
```

## Cry/Kewiri
THis is such a time consuming blackbox problem. There are basically six subproblems that we must solve:
1. Given prime `p`, what is its bit length?
2. Given group `GF(p)` find factorization of its order.
3. Given elements of `GF(p)`, determine whether the element is a generator.
4. Given Weisstrass params of a curve, determine the EC order.
5. Find factorization of the same curve in `GF(p^3)`.
6. Solve ECDLP on said curve.

Problems one through four are simple enough to solve with sagemath. Problem five is a bit tricky with the time constrant, but is precomputable with values from the first curve as curve params are static. Problem six is solvable as given curve as trace of frobenius equal to one, and thus is susceptible to Smart's attack.

```python=
from azunyan.conn import remote
import logging
from math import gcd
from azunyan.sage.curve import smart_attack
from sage.all import *

r = remote('83.136.252.13', 54456, level='debug')

p = r.recvafter(b'p =', int)
p = 21214334341047589034959795830530169972304000967355896041112297190770972306665257150126981587914335537556050020788061

r.sendlineafter(b'>', str(p.bit_length()))
fac = factor(p-1)
print(fac)
payload = ''
for c in list(fac):
    payload += f'{c[0]},{c[1]}_'
payload = payload[:-1]

r.sendlineafter(b'>', payload)

r.recvuntil(b'[3]')
r.recvline()

nums = []
for _ in range(17):
    num = r.recvuntil(b'?')[:-1]
    num = int(num.decode())
    nums.append(num)

    payload = 1
    for c in list(fac):
        if pow(num, (p-1)//c[0], p) == 1:
            payload = 0
        
    r.sendlineafter(b'>', str(payload))

a = r.recvafter(b'a =', int)
b = r.recvafter(b'b =', int)

E = EllipticCurve(GF(p), [a, b])
n = E.order()
t = p + 1 - n # trace of frobenius
t3 = t * (t ** 2 - 3 * p) # chat gpt?? trace of frobenius of fp3
print(f"Presend curve1 {int(n)}")
r.sendlineafter(b'>', str(int(n)))

print(f"Got order {n}")
n3 = p ** 3 + 1 - t3
print(f"Got order2 {n3}, {int(n3).bit_length()}")
# fac = factor(n3) #FACTORING 1150 BITS???, but this is static..

fac = [(2, 2), (7, 2), (21214334341047589034959795830530169972304000967355896041112297190770972306665257150126981587914335537556050020788061, 1), (2296163171090566549378609985715193912396821929882292947886890025295122370435191839352044293887595879123562797851002485690372901374381417938210071827839043175382685244226599901222328480132064138736290361668527861560801378793266019, 1)]
print(fac)
payload = ''
for c in list(fac):
    payload += f'{c[0]},{c[1]}_'
payload = payload[:-1]

r.sendlineafter(b'>', payload)

G = r.recvafter(b':', int)
A = r.recvafter(b':', int)
print(f'{G=}')
print(f'{A=}')
K = GF(p)
G = E.lift_x(K(G))
A = E.lift_x(K(A))

d = smart_attack(G, A)
r.sendlineafter(b'>', str(d))

r.interactive()
```