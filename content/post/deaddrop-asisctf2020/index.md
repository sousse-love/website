---
title: Dead Drop (ASISCTF2020)
date: 2020-07-06T18:31:00+09:00
lastmod: 2020-07-11T19:43:45+09:00
math: true
authors:
  - kiona
tags:
  - crypto
  - asisctf2020
image:
  placement: 3
---

# Introduction

I participated in ASIS CTF 2020, and really enjoyed solving crypto stuffs. 
Here is the writeup for Dead Drop1/2, which is a crypto problem with the least solved whole team.

# The challenge (Dead Drop 1)

For Dead Drop1, the following program is given.
```
from Crypto.Util.number import *
import random
from flag import flag

p = 22883778425835100065427559392880895775739

flag_b = bin(bytes_to_long(flag))[2:]
l = len(flag_b)

enc = []
for _ in range(l):
        a = [random.randint(1, p - 1) for _ in range(l)]
        a_s = 1
        for i in range(l):
                a_s = a_s * a[i] ** int(flag_b[i]) % p
        enc.append([a, a_s])

f = open('flag.enc', 'w')
f.write(str(p) + '\n' + str(enc))
f.close()
```
So we have $l$-exponential equations with $b_i$.

$$a_{s_j}=\prod_{i=0}^{l-1} {a_{i_j}}^{b_i} \mod{p}$$

If the equations were defined on the real field, we can solve the equations by creating linear equations with taking logarithms.
Unfortunately, the equation is defined on some integer residue class ring.
(Normally, computing discrete logarithm is hard...)

After thinking some time, I came up with some idea.
We do not have to solve discrete logarithm with the group which has large order.
If you taking proper $t$ power on the both sides, we can compute discrete logorithm easily.

Let's find soltion step by step.

First, I factored $p$ by [factordb](http://factordb.com/index.php?query=22883778425835100065427559392880895775739).

$$ p = 19 * 113 * 2657 * 6823 * 587934254364063975369377416367 $$

The $a_{s_j}$ equations can be defined on the smaller ring with the divisor of $p$.
I took the number $pp=587934254364063975369377416367$.
(Note that the selection had no meaning... I simply took large one first, and it worked well.)

Next, I factored $pp-1$ by [factordb](http://factordb.com/index.php?query=587934254364063975369377416366) again.

$$ pp - 1 = 2 * 19 * 157 * 98547478103262483300264401 $$

Since the subgroup whose order is $157$ may be promising, take $t=2\*19\*98547478103262483300264401$.

I took the primitive root, that is, the base of discrete log, as $5 \mod pp$.
And, I created a table for $(5^t)^i \mod pp$ for computing discrete log.
Then, we can create the linear equation and find ${b_i}$ by solving the equation.

[Here](answer.py) is whole code. The following is main part. (Note that I prefer for Pari/GP than Sage.)
```
pari = cypari2.Pari()
pari.allocatemem(16000000)

l = len(enc)
pp = 587934254364063975369377416367
ppgen = pari.Mod(5, pp)
t = 98547478103262483300264401 * 2 * 19
assert (pp - 1) % t == 0
ppsubgen = ppgen ** t
ppsubgenord = (pp - 1) // t

logdict = {pari.Mod(pow(ppsubgen, i, pp), pp):i for i in range(ppsubgenord)}

mat = []
vect = []
for i in range(l):
    matele = []
    for j in range(l):
        try:
            ai_idx = logdict[pari.Mod(pow(enc[i][0][j], t, pp), pp)]
        except:
            continue
        matele.append(pari.Mod(ai_idx, ppsubgenord))
    try:
        as_idx = logdict[pari.Mod(pow(enc[i][1], t, pp), pp)]
    except:
        continue
    mat.append(matele)
    vect.append(pari.Mod(as_idx, ppsubgenord))

mat_coeff = pari.matid(l)
for i in range(l):
    for j in range(l):
        mat_coeff[i, j] = mat[i][j]

vect_coeff = pari.mattranspose(pari.Mat(vect))

sol = pari.matsolve(mat_coeff, vect_coeff)

flag_b = ''
for i in range(l):
    flag_b += str(sol[i,0].lift())

print(long_to_bytes(int(flag_b, 2)))
```

# Dead Drop 2
Most code for Dead Drop 1 can be applied to Dead Drop 2!

(modification: $pp=q$, $t=2\*103\*14621\*21622810159\*52792444681\*1553877481309\*18616484120267152928623$)


