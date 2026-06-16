---
title: DiceCTF 2026 Quals Writeups
toc: true
date: 2026-03-08 18:53:28
description: Writeups for DiceCTF 2026 Quals
categories:
    - Writeups
tags:
    - CTF
    - Binary Exploitation (pwn)
    - Digital Forensics
    - Web Exploitation
    - Cryptography
    - Reverse Engineering
    - Cyber Security
cover: dicectf_logo.webp
---

> **TL;DR**
My team **Nusahack** participated in **DiceCTF 2026 Quals**, which took place during the first weekend of March 2026. We finished **181st out of 497 teams**, and during the competition I managed to solve several challs. In this post I’ll go through the several challs I solved and how I solved them.

{% asset_img dicectf_scoreboard.webp "DiceCTF 2026 Quals scoreboard" %}

---

## Miscellaneous

### good-vibes

#### Challenge Info
- **Category:** Misc  
- **Points:** 109
- **Solves:** 262  
- **Author:** jammy  
- **File:** `misc_good-vibes.tar.gz`

#### Description
> operating on good vibes has no real consequences... surely...
> Updated handout - the challenge now includes vibepn-client.zip. The password for this zip is the characters in the last part of the relevant URL in the pcap.
> For example, if the url in the pcap was `https://filehosting.com/d/Dices123` , the password would be `Dices123`.

#### Analysis
I opened `challenge.pcap` in **Wireshark** to inspect the traffic.

{% asset_img wireshark_overview.webp Wireshark Overview%}

There are around 2k packets. My first instinct, to save time, was to try extracting files directly from the capture using:
`File → Export Objects → HTTP`

{% asset_img http_object_blank.webp HTTP object list empty%}

This suggests that the relevant data is likely embedded somewhere else in the traffic rather than being transferred as a normal HTTP file download.

Next, I checked the **I/O Graph** in Wireshark to identify unusual traffic spikes.

{% asset_img io_graph.webp Wireshark IO graph %}

Most of the traffic near the end of the capture shows a large spike, but it turns out to be **dummy traffic** and does not contain anything useful. However, there is a **smaller spike around packet ~150**, which looks much more interesting. To investigate further, I selected packets around that spike and **applied them as a display filter**.

Inspecting those packets reveals a TCP conversation between two hosts.

Following the TCP stream:
`Right Click → Follow → TCP Stream`

{% asset_img tcp_stream_chat.webp TCP stream hidden conversation %}

The stream shows a chat conversation between two individuals discussing a VPN client. Toward the end of the conversation, one of them sends a link: `https://gofile.io/d/l6XqnD`

According to the challenge description, the password for the zip archive is **the last part of the URL**.

Therefore the password is: `l6XqnD`

Using this password, we can successfully extract the contents of `vibepn-client.zip`, which contains the files needed for the next stage of the challenge.

After extracting the archive using the password obtained from the PCAP, we obtain the binary: `vibepn-client`

To understand what this file is, we first check its type.

The output shows:
{% asset_img file_vibepn_check.webp file check %}

A few important observations:
- ELF → standard executable format on Linux
- x86-64 → compiled for 64-bit systems
- not stripped → symbol names are still present

The last point is particularly helpful because it makes reverse engineering much easier.

Since the binary is not stripped, we can list the available symbols.

```text
[camelot:misc_good-vibes]
[vortaile]% nm vibepn-client
000000000000038c r __abi_tag
0000000000006020 B __bss_start
                 U close@GLIBC_2.2.5
0000000000006028 b completed.0
                 w __cxa_finalize@GLIBC_2.2.5
0000000000006000 D __data_start
0000000000006000 W data_start
00000000000031a0 t deregister_tm_clones
0000000000003210 t __do_global_dtors_aux
0000000000005c48 d __do_global_dtors_aux_fini_array_entry
0000000000006008 D __dso_handle
0000000000005c50 d _DYNAMIC
000000000000601c D _edata
0000000000006160 B _end
                 U ERR_error_string@OPENSSL_3.0.0
                 U ERR_get_error@OPENSSL_3.0.0
                 U __errno_location@GLIBC_2.2.5
                 U EVP_aes_256_gcm@OPENSSL_3.0.0
                 U EVP_CIPHER_CTX_ctrl@OPENSSL_3.0.0
                 U EVP_CIPHER_CTX_free@OPENSSL_3.0.0
                 U EVP_CIPHER_CTX_new@OPENSSL_3.0.0
                 U EVP_DecryptFinal_ex@OPENSSL_3.0.0
                 U EVP_DecryptInit_ex@OPENSSL_3.0.0
                 U EVP_DecryptUpdate@OPENSSL_3.0.0
                 U EVP_EncryptFinal_ex@OPENSSL_3.0.0
                 U EVP_EncryptInit_ex@OPENSSL_3.0.0
                 U EVP_EncryptUpdate@OPENSSL_3.0.0
                 U EVP_PKEY_CTX_free@OPENSSL_3.0.0
                 U EVP_PKEY_CTX_new_from_name@OPENSSL_3.0.0
                 U EVP_PKEY_CTX_set_params@OPENSSL_3.0.0
                 U EVP_PKEY_free@OPENSSL_3.0.0
                 U EVP_PKEY_generate@OPENSSL_3.0.0
                 U EVP_PKEY_get_octet_string_param@OPENSSL_3.0.0
                 U EVP_PKEY_keygen_init@OPENSSL_3.0.0
                 U __fdelt_chk@GLIBC_2.15
0000000000003d54 T _fini
                 U __fprintf_chk@GLIBC_2.3.4
0000000000003250 t frame_dummy
0000000000005c40 d __frame_dummy_init_array_entry
0000000000004a4c r __FRAME_END__
0000000000006060 b g_client_kp
0000000000005e50 d _GLOBAL_OFFSET_TABLE_
                 w __gmon_start__
0000000000004580 r __GNU_EH_FRAME_HDR
0000000000006018 d g_running
0000000000006040 b g_server_addr
00000000000060c0 b g_session
0000000000006010 d g_sock
0000000000006014 d g_tun
                 U inet_pton@GLIBC_2.2.5
0000000000002000 T _init
                 U ioctl@GLIBC_2.2.5
0000000000004000 R _IO_stdin_used
                 w _ITM_deregisterTMCloneTable
                 w _ITM_registerTMCloneTable
                 U __libc_start_main@GLIBC_2.34
0000000000002650 T main
0000000000002600 t main.cold
                 U __memcpy_chk@GLIBC_2.3.4
                 U open@GLIBC_2.2.5
                 U OPENSSL_cleanse@OPENSSL_3.0.0
                 U OSSL_PARAM_construct_end@OPENSSL_3.0.0
                 U OSSL_PARAM_construct_utf8_string@OPENSSL_3.0.0
                 U perror@GLIBC_2.2.5
                 U __printf_chk@GLIBC_2.3.4
                 U RAND_bytes@OPENSSL_3.0.0
                 U read@GLIBC_2.2.5
                 U recvfrom@GLIBC_2.2.5
00000000000031d0 t register_tm_clones
                 U select@GLIBC_2.2.5
0000000000003290 t send_packet.isra.0
                 U sendto@GLIBC_2.2.5
0000000000003260 t signal_handler
                 U __snprintf_chk@GLIBC_2.3.4
                 U socket@GLIBC_2.2.5
                 U __stack_chk_fail@GLIBC_2.4
0000000000003170 T _start
0000000000003400 t start_handshake
0000000000006020 B stderr@GLIBC_2.2.5
                 U strncpy@GLIBC_2.2.5
                 U strtol@GLIBC_2.2.5
                 U system@GLIBC_2.2.5
                 U __sysv_signal@GLIBC_2.2.5
                 U time@GLIBC_2.2.5
0000000000006020 D __TMC_END__
0000000000003ba0 T tun_close
0000000000003c00 T tun_configure
0000000000003a80 T tun_open
0000000000002622 t tun_open.cold
0000000000003bc0 T tun_read
0000000000003be0 T tun_write
00000000000038b0 T vpn_decrypt
00000000000036f0 T vpn_derive_session_key
0000000000003730 T vpn_encrypt
00000000000036c0 T vpn_free_keypair
0000000000003520 T vpn_generate_keypair
0000000000003a70 T vpn_generate_nonce
0000000000003a60 T vpn_random_bytes
                 U write@GLIBC_2.2.5
```

Among the symbols we find several interesting functions:

```text
vpn_generate_keypair
vpn_derive_session_key
vpn_encrypt
vpn_decrypt
vpn_generate_nonce
vpn_random_bytes
start_handshake
send_packet
tun_open
tun_read
tun_write
tun_close
```

From these names we can already infer a rough structure of the program. Several functions clearly belong to a custom VPN implementation:
- vpn_generate_keypair → generates a keypair for the client
- vpn_derive_session_key → derives the symmetric session key
- vpn_encrypt / vpn_decrypt → handles packet encryption and decryption
- vpn_generate_nonce → generates the nonce used for encryption
- vpn_random_bytes → helper function for randomness

Additionally, we see networking-related functions:
- start_handshake
- send_packet

and functions related to the TUN interface, which is commonly used by VPN software:
- tun_open
- tun_configure
- tun_read
- tun_write
- tun_close

The presence of these functions strongly suggests that the binary implements a minimal VPN client that:
1) establishes a handshake with a remote server
2) derives a session key
3) encrypts traffic
4) tunnels packets through a TUN interface

Another useful observation from the symbol list is the presence of OpenSSL functions such as:
- EVP_aes_256_gcm
- EVP_EncryptInit_ex
- EVP_EncryptUpdate
- EVP_DecryptInit_ex
- EVP_DecryptUpdate
- EVP_DecryptFinal_ex

These functions confirm that the program uses **AES-256-GCM** for encrypting VPN traffic. At this point, the most interesting function to investigate is: `vpn_derive_session_key`

because it is responsible for generating the symmetric key used for encryption. If there is any weakness in this function, it would allow us to recover the session key and decrypt the VPN traffic captured in the PCAP.

To better understand how the session key is generated, I inspected the function `vpn_derive_session_key` in the disassembly.

{% asset_img vpn_derive_disasm.webp vpn_derive_session_key disassembly %}

The relevant portion of the disassembly looks like this:

```asm
call    time
imul    eax, 19660Dh
add     eax, 3C6EF35Fh
mov     [rcx-1], al
cmp     rcx, rdx
jnz     loc_3710
```

From this snippet we can observe several important behaviors. First, the function calls `time`, which means the generator is seeded using the current UNIX timestamp. The resulting value is then repeatedly updated using a linear recurrence:

```
seed = seed * 0x19660d + 0x3c6ef35f
```

After each iteration, the lowest byte of the internal state (`seed & 0xff`) is written into the output buffer. This process repeats until **32 bytes of key material** have been produced.

The logic can therefore be summarized as the following pseudocode:

```c
seed = time(NULL);

for (int i = 0; i < 32; i++) {
    seed = seed * 0x19660d + 0x3c6ef35f;
    key[i] = seed & 0xff;
}
```

This pattern immediately resembles a **Linear Congruential Generator (LCG)**.

An LCG is a simple pseudo-random number generator defined by the recurrence:

```
X(n+1) = (a * X(n) + c) mod m
```

Although LCGs are commonly used for simulations and other non-security purposes due to their simplicity and speed, they are **not suitable for cryptographic key generation**. The critical issue here is that the generator is seeded with `time(NULL)`, which returns the current UNIX timestamp.

Because timestamps are predictable and observable from external data sources such as packet captures, the resulting key space becomes extremely small. Instead of brute-forcing a full cryptographic key space, an attacker only needs to consider timestamps around the moment when the VPN connection was established.

At this point the remaining unknown parameter is the timestamp used as the seed.

To approximate this value, I inspected the packet capture in **Wireshark** and located the packets corresponding to the VPN communication.

{% asset_img packet_timestamp.webp Packet timestamp observed in Wireshark %}

From the capture we can observe that the encrypted VPN traffic begins around this time window.

Rather than manually reconstructing the exact timestamp from the capture, I used an **LLM to analyze the PCAP timing information together with the key derivation logic**. Based on this analysis, the candidate UNIX timestamp was determined to be: `1772156047`

Since the binary seeds the generator using `time(NULL)`, which returns seconds since the Unix epoch, this value is a valid seed candidate for reproducing the session key.

#### Solution

Once the weakness in `vpn_derive_session_key` is understood, the rest of the challenge becomes straightforward.

The idea is to reproduce the key derivation algorithm, use the recovered timestamp as the seed, and then decrypt the encrypted VPN packet captured in the PCAP.

I used an LLM to help generate the initial solver script and then adjusted it to match the behavior observed in the binary.

The key derivation logic can be reproduced in Python as follows:

```python
from Crypto.Cipher import AES

def derive_key(ts: int) -> bytes:
    x = ts & 0xffffffff
    out = bytearray()

    for _ in range(32):
        x = (x * 0x19660d + 0x3c6ef35f) & 0xffffffff
        out.append(x & 0xff)

    return bytes(out)
```

Using the recovered timestamp:

```python
timestamp = 1772156047
key = derive_key(timestamp)
```

Next, we extract one of the encrypted VPN packets from the PCAP.

The encrypted payload can be copied directly from the packet bytes in Wireshark. The resulting hexadecimal blob represents the encrypted VPN payload.

The packet structure follows the typical **AES-GCM layout**:

```
nonce (12 bytes) | ciphertext | tag (16 bytes)
```

Using this structure we split the packet and attempt decryption:

```python
blob = bytes.fromhex(
"8b5d9fde0cd41180a698986ec6640ef23713c5adf2876484247a0efc24e3f613"
"11b7212733f85ed01e4c67f4b56b23b380f5cb8b33937943b4e4ae4a"
)

nonce = blob[:12]
ciphertext = blob[12:-16]
tag = blob[-16:]

cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
plaintext = cipher.decrypt_and_verify(ciphertext, tag)

print(plaintext)
```

Running the script successfully decrypts the packet and reveals the contents of the VPN tunnel.

Among the decrypted data we find the flag.

---

#### Flag
`dice{y0u_sh0uld_alw@ys_vib3_y0ur_vpns_82bc3}`

## Cryptography

### plane-or-exchange

#### Challenge Info
- **Category:** Crypto  
- **Points:** 108
- **Solves:** 304  
- **Author:** AdnanSlef  
- **File:** `crypto_plane-or-exchage.tar.gz`
    - `protocol.py`
    - `public.txt`

#### Description
> Alice and Bob had a brief exchange, and now they know something which I do not. Would you please help me to drop some Eves?

#### Analysis
The provided public data includes Alice's public key, Bob's public key, some public parameters, and a ciphertext.

```python
Alice's Pubkey: [[8, 15, 7, 26, 1, 4, 2, 12, 9, 18, 23, 25, 24, 14, 13, 16, 0, 3, 11, 10, 5, 20, 6, 21, 19, 17, 22], [5, 2, 23, 3, 25, 9, 26, 8, 24, 7, 14, 18, 12, 4, 20, 21, 6, 1, 19, 22, 10, 0, 16, 17, 15, 11, 13]]
Bob's Pubkey: [[26, 9, 21, 4, 28, 8, 20, 7, 27, 1, 13, 25, 22, 17, 6, 15, 24, 3, 12, 29, 11, 16, 10, 0, 18, 2, 14, 5, 19, 23], [5, 18, 28, 27, 25, 19, 23, 13, 21, 24, 16, 15, 8, 29, 14, 11, 26, 22, 9, 7, 10, 3, 2, 6, 0, 12, 17, 20, 1, 4]]
Public Info: [[11, 0, 2, 4, 8, 3, 1, 10, 7, 6, 9, 5], [1, 9, 8, 10, 11, 7, 4, 6, 5, 3, 2, 0]]
Ciphertext: 288cdf5ecf3eb860e2cb6790bff63baceaebb6ed511cd94dd0753bac59962ef0cd171231dc406ac3cdc2ff299d78390ff3
```

The code implementing the protocol is provided in `protocol.py`.

```python
import hashlib
from secrets import choice, randbelow
from sympy.combinatorics import Permutation
import sympy as sp

t = sp.Symbol('t', real=True, positive=True)

def compose(p1, p2):
    return [p1[p2[i]] for i in range(len(p1))]

def inverse(p):
    inverse = [0] * len(p)
    for i, j in enumerate(p):
        inverse[j] = i
    return inverse

def validate(point):
    x, o = point
    return len(x) == len(o) and \
           Permutation(compose(x, inverse(o))).cycles == 1 and \
           sum(x[i] == o[i] for i in range(len(x))) == 0

def calculate(point):
    mat = sp.Matrix([[t**-x for x in y] for y in mine(point)])
    return mat.det(method='bareiss')*(1-t)**(1-len(point[0]))

def sweep(ap):
    l = len(ap)
    current_row = [0] * l
    matrix = []
    for pair in ap:
        c1, c2 = sorted(pair)
        diff = pair[1] - pair[0]
        if diff > 0:
            s = 1
        elif diff < 0:
            s = -1
        else:
            s = 0
        for c in range(c1, c2):
            current_row[c] += s
        matrix.append(list(current_row))
    return matrix

def mine(point):
    x, o = point
    return sweep([*zip(x, o)])

def connect(g1, g2):
    x1, o1 = g1
    x2, o2 = g2
    l = len(x1)
    new_x = list(x1) + [v + l for v in x2]
    new_o = list(o1) + [v + l for v in o2]
    idx1 = l - 1
    idx2 = l
    new_x[idx1], new_x[idx2] = new_x[idx2], new_x[idx1]
    return (new_x, new_o)

def normalize(calculation):
    poly = sp.expand(sp.simplify(calculation))
    all_exponents = [term.as_coeff_exponent(t)[1] for term in poly.as_ordered_terms()]
    min_exp = min(all_exponents)
    poly *= t**(-min_exp)
    poly = sp.expand(sp.simplify(poly))
    if poly.coeff(t,0)<0:
        poly *= -1
    return poly

def slide1(data):
    def check(x1, o1, x2, o2):
        low1, high1 = min(x1, o1), max(x1, o1)
        low2, high2 = min(x2, o2), max(x2, o2)
        if high1 < low2 or high2 < low1:
            return True
        if (low1 > low2 and high1 < high2) or (low2 > low1 and high2 < high1):
            return True
        return False
    x, o = data
    idx = randbelow(len(x)-1)
    if check(x[idx], o[idx], x[idx+1], o[idx+1]):
        x[idx], x[idx+1] = x[idx+1], x[idx]
        o[idx], o[idx+1] = o[idx+1], o[idx]
    return (x, o)

def slide2(data):
    x_cols, o_cols = data
    n = len(x_cols)
    j = randbelow(n - 1)
    x_pos_j = x_cols.index(j)
    o_pos_j = o_cols.index(j)
    x_pos_j1 = x_cols.index(j + 1)
    o_pos_j1 = o_cols.index(j + 1)
    low_j, high_j = min(x_pos_j, o_pos_j), max(x_pos_j, o_pos_j)
    low_j1, high_j1 = min(x_pos_j1, o_pos_j1), max(x_pos_j1, o_pos_j1)
    valid = False
    if high_j < low_j1 or high_j1 < low_j:
        valid = True
    elif (low_j > low_j1 and high_j < high_j1) or (low_j1 > low_j and high_j1 < high_j):
        valid = True
    if valid:
        new_x = list(x_cols)
        new_o = list(o_cols)
        new_x[x_pos_j] = j + 1
        new_x[x_pos_j1] = j
        new_o[o_pos_j] = j + 1
        new_o[o_pos_j1] = j
        return (new_x, new_o)
    return data

def shuffle(data):
    x, o = data
    n = len(x)
    opt = randbelow(4)
    if opt==0:
        x = [(x+1)%n for x in x]
        o = [(o+1)%n for o in o]
    if opt==1:
        x = [(x+n-1)%n for x in x]
        o = [(o+n-1)%n for o in o]
    if opt==2:
        x = x[-1:] + x[:-1]
        o = o[-1:] + o[:-1]
    if opt==3:
        x = x[1:] + x[:1]
        o = o[1:] + o[:1]
    return (x, o)

def scramble(data, iter):
    new = [[*data[0]], [*data[1]]]
    for _ in range(iter):
        f = choice([
            slide1,
            slide2,
            shuffle
        ])
        new = f(new)
    return new

def derive_public_key(my_priv, public_info):
    return scramble(connect(public_info, my_priv), 1000)

def derive_shared_secret(my_priv, their_pub):
    return hashlib.sha256(str(normalize(calculate(connect(my_priv, their_pub)))).encode()).hexdigest()

def encrypt(flag, shared_secret):
    key = bytes.fromhex(shared_secret)
    while len(key) < len(flag):
        key += hashlib.sha256(key).digest()
    return bytes(a^b for a, b in zip(flag.encode(), key)).hex()

```
The challenge provides a custom cryptographic protocol implemented in Python.

When analyzing cryptography challenges, the typical process is:
1) Identify the **key exchange mechanism**
2) Identify how the **shared secret is derived**
3) Check whether **private information leaks through mathematical properties**
4) Reconstruct the protocol locally to compute the same secret

Looking at `protocol.py`, the important functions are:
- `connect()`
- `calculate()`
- `normalize()`
- `derive_shared_secret()`
- `encrypt()`

The shared secret is computed using:

```python
def derive_shared_secret(my_priv, their_pub):
    return hashlib.sha256(
        str(normalize(calculate(connect(my_priv, their_pub))))
        .encode()
    ).hexdigest()
```

So the final shared secret is:
`SHA256( normalize( calculate( connect(privA, pubB) ) ) )`

The encryption step then XORs the flag with a key derived from this hash.

The first thing worth doing is understanding what the protocol is actually manipulating.

The code models an object called a point as a pair of permutations:

```python
point = (x, o)
```

Here, both x and o are lists of integers. In the challenge code, they are treated as permutations: each value appears exactly once, and the ordering matters. The validate() function confirms that the structure is not arbitrary and enforces some constraints on these pairs.

At a high level, each index i defines a pair:

```python
(x[i], o[i])
```

These pairs are then fed into mine(), which calls sweep() to convert them into a matrix-like representation.

That is the first important observation: the protocol does not derive the shared secret directly from the raw permutations. Instead, it transforms them into an intermediate structure, builds a symbolic matrix from that structure, computes a determinant, normalizes the resulting polynomial, and only then hashes it. In other words, the real security of the scheme depends entirely on whether that final polynomial is hard to reproduce.

This means the main question is:
`Does the scrambling process actually change the final polynomial used for the shared secret?`
If the answer is no, the whole key exchange collapses

The next important function is connect():
```python
def connect(g1, g2):
    x1, o1 = g1
    x2, o2 = g2
    l = len(x1)
    new_x = list(x1) + [v + l for v in x2]
    new_o = list(o1) + [v + l for v in o2]
    idx1 = l - 1
    idx2 = l
    new_x[idx1], new_x[idx2] = new_x[idx2], new_x[idx1]
    return (new_x, new_o)
```

This function combines two points into one larger point. It does three things:
1) It appends the second structure after the first.
2) It shifts the indices of the second structure so they do not overlap with the first.
3) It swaps one boundary element in new_x, which acts like a special stitching step between the two halves. 

Conceptually, connect(g1, g2) is the operation that glues two structures together.

This matters because both public key generation and shared secret derivation are built around connect():
- Public key generation:
  `Public key generation:`
- Shared secret derivation:
  `Shared secret derivation:`

So connect() is the bridge between the raw private/public objects and the final symbolic expression that becomes the shared secret.

After two points are connected, the protocol turns them into a matrix through mine() and calculate():
```python
def mine(point):
    x, o = point
    return sweep([*zip(x, o)])
```

and

```python
def mine(point):
    x, o = point
    return sweep([*zip(x, o)])
```

Lets unpack that carefully.

**What does mine() do?**
mine() pairs each entry of x with the corresponding entry of o, then passes the list of pairs into sweep(). The sweep() function incrementally builds rows of integers based on the relative positions of each pair.

We do not need to understand every combinatorial detail of sweep() to solve the challenge. What matters is that it deterministically turns a point into a matrix-shaped integer structure.

**What does calculate() do?**
Once mine(point) produces its row data, calculate() converts every entry x into a symbolic term of the form:

```python
t**-x
```

where t is a SymPy symbol:

```python
t = sp.Symbol('t', real=True, positive=True)
```

So instead of doing plain arithmetic, the code works with symbolic polynomials. This is important because the protocol is not hiding a number; it is hiding a normalized polynomial expression.

The matrix determinant is then computed:

```python
mat.det(method='bareiss')
```

A determinant is a single value derived from a square matrix. In ordinary linear algebra it is a scalar, but here, because the matrix contains symbolic powers of t, the determinant becomes a symbolic expression in t. The code then multiplies by `(1-t)**(1-len(point[0]))`, which further transforms the result into the polynomial form the protocol wants.

At this stage, we can already see the cryptographic design:
1) Build a structure from permutations
2) Convert that structure into a symbolic matrix
3) Compute a determinant-based polynomial
4) Normalize it
5) Hash the normalized string

That polynomial is the true core of the shared secret.

The next function is:

```python
def normalize(calculation):
    poly = sp.expand(sp.simplify(calculation))
    all_exponents = [term.as_coeff_exponent(t)[1] for term in poly.as_ordered_terms()]
    min_exp = min(all_exponents)
    poly *= t**(-min_exp)
    poly = sp.expand(sp.simplify(poly))
    if poly.coeff(t,0)<0:
        poly *= -1
    return poly
```

This step is extremely important.

A symbolic polynomial can often be written in multiple equivalent ways. For example, two expressions may represent the exact same polynomial but have different formatting or different minimum exponents. If the protocol hashed the raw symbolic output directly, equivalent results might produce different strings.

normalize() avoids that by forcing a canonical form:
- it expands and simplifies the expression
- it shifts the polynomial so the smallest exponent becomes 0
- it flips the sign if the constant term is negative 

The result is that mathematically equivalent expressions become the same exact string.

That is why the shared secret derivation works reliably:
`hashlib.sha256(str(normalize(...)).encode()).hexdigest()`

The protocol is effectively saying:
`If two connected structures lead to the same normalized polynomial, they produce the same shared secret.`
That is exactly the property we end up abusing.

The vulnerability is in the mismatch between what the protocol tries to hide and what it actually uses as the secret.
Public keys are generated as follows:

```python
def derive_public_key(my_priv, public_info):
    return scramble(connect(public_info, my_priv), 1000)
```

The intention is clear: combine the public information with a private structure, then apply a large number of random transformations so the private structure is concealed.

Those transformations are chosen from:
- slide1()
- slide2()
- shuffle()

At first glance, this looks reasonable. If the public key is a heavily scrambled version of `connect(public_info, private_key)`, then perhaps reversing it should be hard.

The problem is that the protocol does not use the scrambled layout itself as the secret. It uses the output of:
```python
The problem is that the protocol does not use the scrambled layout itself as the secret. It uses the output of:
```

And that output behaves like a mathematical invariant under the allowed scrambling operations.

So what is invariant? An invariant is a property that stays the same even when the representation changes. A simple geometric analogy is that rotating a triangle changes its orientation, but not its area. The drawing looks different, but some deeper property remains unchanged.

That is exactly what happens here.

The functions `slide1()`, `slide2()`, and `shuffle()` rearrange the representation of the structure, but they do not change the determinant-based polynomial that calculate() ultimately produces. The object looks different, but the quantity used as the secret remains the same.

So although the protocol performs 1000 random scrambling steps, those steps do not protect the actual secret material.

The intended logic is:
- Alice keeps `privA`
- Bob keeps `privB`
- each side publishes a scrambled public key
- each side combines its private key with the other party's public key
- both derive the same shared secret

But because the determinant polynomial is invariant under scrambling, we do not need the original private keys. The public keys are already sufficient to recover the same normalized polynomial, and therefore the same SHA-256 hash.

That is the core break.

In practical terms, the vulnerability lives in the combination of these design choices:
1) `derive_public_key()` only scrambles the structure instead of changing the underlying invariant
2) `derive_shared_secret()` hashes a value that remains stable under that scrambling

So the protocol hides the wrong thing. It hides the representation, not the secret-dependent invariant.

#### Solution

Once the invariant issue is understood, the solve path becomes much cleaner.

The public data file gives us:
- Alice's public key
- Bob's public key
- the public information
- the ciphertext

Since the public keys already preserve the determinant polynomial needed for the exchange, we can skip any attempt to recover either private key.

The exploit is:
- parse Alice's public key, Bob's public key, the public info, and the ciphertext
- connect Alice's and Bob's public keys using the same `connect()` function
- compute the determinant polynomial with `calculate()`
- compute the determinant polynomial of `public_info`
- divide the combined polynomial by the `public_info` polynomial to remove the extra factor introduced by the protocol
- normalize the resulting polynomial with `normalize()`
- hash the resulting string with SHA-256
- expand that hash into a keystream
- XOR it with the ciphertext to recover the plaintext

The beauty of this attack is that it uses the challenge author's own code almost verbatim. We are not breaking SHA-256, brute-forcing permutations, or reversing the scramble process. We are simply noticing that the supposedly hidden value is already determined by public information.

**Solver**

```python
import ast
import hashlib
import os

import sympy as sp
from protocol import connect, calculate, normalize, t


def parse_public_file(path: str):
    values = {}

    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or ": " not in line:
                continue
            key, value = line.split(": ", 1)
            values[key] = value

    alice_pub = ast.literal_eval(values["Alice's Pubkey"])
    bob_pub = ast.literal_eval(values["Bob's Pubkey"])
    public_info = ast.literal_eval(values["Public Info"])
    ciphertext = bytes.fromhex(values["Ciphertext"])

    return alice_pub, bob_pub, public_info, ciphertext


def recover_shared_polynomial(alice_pub, bob_pub, public_info):
    # This gives normalize(calculate(connect(connect(public_info, privA), connect(public_info, privB))))
    combined_poly = normalize(calculate(connect(alice_pub, bob_pub)))

    # Remove the extra public_info factor once
    public_poly = normalize(calculate(public_info))

    q, r = sp.div(sp.Poly(combined_poly, t), sp.Poly(public_poly, t))
    if r.as_expr() != 0:
        raise ValueError(f"Division was not exact: remainder = {r.as_expr()}")

    return normalize(q.as_expr())


def expand_key(seed: bytes, length: int) -> bytes:
    key = bytearray(seed)
    while len(key) < length:
        key.extend(hashlib.sha256(bytes(key)).digest())
    return bytes(key[:length])


def main():
    base_dir = os.path.dirname(os.path.abspath(__file__))
    public_path = os.path.join(base_dir, "public.txt")

    alice_pub, bob_pub, public_info, ciphertext = parse_public_file(public_path)

    shared_poly = recover_shared_polynomial(alice_pub, bob_pub, public_info)
    shared_secret = hashlib.sha256(str(shared_poly).encode()).digest()

    keystream = expand_key(shared_secret, len(ciphertext))
    plaintext = bytes(c ^ k for c, k in zip(ciphertext, keystream))

    print(f"[+] shared polynomial: {shared_poly}")
    print(f"[+] shared secret: {shared_secret.hex()}")
    print(f"[+] plaintext: {plaintext.decode()}")

if __name__ == "__main__":
    main()
```

Instead of trying to reverse the scrambling operations or recover the private keys, the solver simply reproduces the protocol’s computation using the public data. This works because the determinant polynomial used in the protocol remains unchanged under the scrambling operations, so the public keys already preserve the information needed to reconstruct the shared secret.

The solver first combines Alice’s and Bob’s public keys using `connect(alice_pub, bob_pub)`. The resulting structure is then passed to calculate(...), which builds a symbolic matrix and computes its determinant, producing a polynomial in the variable t.

However, this polynomial still contains an extra factor introduced by the public information used in the protocol. To remove it, the solver also computes the determinant polynomial of public_info and divides the combined polynomial by this value. The result corresponds to the actual shared polynomial used in the key exchange.

This polynomial is then normalized using `normalize(...)` to obtain a canonical representation. The normalized polynomial is hashed with SHA-256, exactly as in the protocol, producing the shared secret.

Finally, the hash is expanded into a keystream and XORed with the ciphertext to recover the plaintext.

The key insight is that the determinant polynomial is invariant under scrambling, allowing the shared secret to be reconstructed entirely from public data.

#### Flag
`dice{plane_or_planar_my_w0rds_4r3_411_knotted_up}`

