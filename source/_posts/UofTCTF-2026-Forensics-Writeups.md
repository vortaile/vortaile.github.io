---
title: UofTCTF 2026 Forensics Writeups
categories:
  - Writeups
tags:
  - CTF
  - Digital Forensics
  - Cyber Security
toc: true
date: 2026-01-12 19:44:29
description: Write-ups for all Forensics challenges I solved during UofTCTF 2026.
top_img: forensics_uoftctf.webp
cover: uoftctf_logo_3000.webp
---

## TL;DR
Our team **Nusahack** participated in **UofTCTF 2026**, and I managed to solve **all Forensics challenges** during the competition (that was fun, ngl 🤓). This post contains my writeups covering both **basic network traffic analysis** and **printer/image forensics for TCG card**, focusing on practical investigative techniques.

---

## Baby Exfil

### Challenge Info
- **Category:** Digital Forensics  
- **Points:** 36  
- **Solves:** 463  
- **Author:** 0x157  
- **File:** `final.pcapng`

### Description
Team K&K has identified suspicious network activity on their machine. Fearing that a competing team may be attempting to steal confidential data through underhanded means, they need your help analyzing the network logs to uncover the truth.

### Analysis
The challenge gives us a **pcap file**.

From the description, there’s a clear keyword: **steal data (data exfiltration)**. Instead of manually inspecting packets one by one, it makes more sense to **export HTTP objects directly using wireshark** from the pcap to see what kind of data is being exfiltrated.

{% asset_img http_object_export.webp HTTP object export %}

Why HTTP? Because:
- HTTP has clear **methods** like `GET` and `POST`
- A lot of **stealer malware communicates over HTTP**
- This is a *baby* challenge, so it’s unlikely to be overly complex :v

After exporting HTTP objects in Wireshark, we can immediately spot the **malicious payload**. The payload itself was generated using **Python**, and alongside it, there are multiple files stolen from the victim’s desktop.

{% asset_img malicious_instance.webp malicious instance %}

By analyzing the extracted payload, we can see that it is a simple Python-based stealer script. The script recursively walks through the victim’s desktop directory, searching for files with common document and image extensions. Each file is read in binary form and encrypted using a repeating-key XOR scheme before being converted into a hex string. The encrypted data is then exfiltrated to a remote server via an HTTP POST request, blending the malicious traffic into normal-looking web uploads. This explains why multiple encrypted blobs appear in the HTTP objects and confirms that the challenge revolves around basic data exfiltration rather than advanced obfuscation techniques.

These stolen files are **XOR-encrypted**.

{% asset_img http_hex_raw.webp raw hex %}

Since XOR is reversible, we can recover the original files by:
- Extracting the **raw HTTP data**
- Decrypting the hex string using the XOR key found inside the payload

The XOR key used is:
`G0G0Squ1d3Ncrypt10n`

### Solution
```python [solver]
import glob, re, os

key = b"G0G0Squ1d3Ncrypt10n"

def xor(data, key):
    return bytes([data[i] ^ key[i % len(key)] for i in range(len(data))])

for fname in glob.glob("upload*"):
    with open(fname, "r", errors="ignore") as f:
        data = f.read()

    data = data.replace("\r\n", "\n")  # jaga-jaga newline windows

    # ambil filename asli dari header (kalo ada)
    m = re.search(r'filename="([^"]+)"', data)
    outname = m.group(1) if m else f"recovered_{fname}.bin"

    # ambil hex payload paling panjang (ini yang beneran file korban)
    cands = re.findall(r"[0-9a-fA-F]{200,}", data)
    if not cands:
        print(f"[-] {fname}: ga nemu hex payload")
        continue
    hex_data = max(cands, key=len)

    encrypted = bytes.fromhex(hex_data)
    decrypted = xor(encrypted, key)

    with open(outname, "wb") as f:
        f.write(decrypted)

    print(f"[+] {fname} -> {outname}")
```
The idea of the solver is simple:
1. Read each exported `upload*` file as text
2. Extract the **largest hex-encoded blob**, which corresponds to the actual encrypted file content
3. Convert the hex string back into raw bytes
4. Decrypt it using XOR with the known key
5. Recover the original stolen file

The script also tries to recover the **original filename** from the HTTP headers (if present). If a filename can’t be found, it falls back to a generic name.

Since XOR is reversible, applying the same operation again with the same key gives us back the original file contents.

After running the script, the stolen files are successfully recovered.  
Among the decrypted outputs, the flag can be found inside the file named: `HNderw.png`

{% asset_img solved.webp solved %}

### Flag
`uoftctf{b4by_w1r3sh4rk_an4lys1s}` 

---

## My Pokemon Card is Fake!

### Challenge Info
- **Category:** Digital Forensics  
- **Points:** 64  
- **Solves:** 101
- **Author:** levu12  
- **File:** `Zard.jpg`

### Description
Han Shangyan noticed that recently, Tong Nian has been getting into Pokemon cards. So, what could be a better present than a literal prototype for the original Charizard? Not only that, it has been authenticated and graded a PRISTINE GEM MINT 10 by CGC!!!

Han Shangyan was able to talk the seller down to a modest 6-7 figure sum (not kidding btw), but when he got home, he had an uneasy feeling for some reason. Can you help him uncover the secrets that lie behind these cards?

What you will need to find:

Date and time (relative to the printer, and 24-hour clock) that it was printed.

Printer's serial number.

The flag format will be `uoftctf{YYYY_MM_DD_HH:MM_SERIALNUM}`

Example: `uoftctf{9999_09_09_23:59_676767676}`

### Notes
1. You're free to dig more into the whole situation after you've solved the challenge, it's very interesting, though so much hasn't been or can't be said :(
2. Two days after I write this challenge, I'm going to meet the person whose name was used for all this again. Hopefully I'll be back to respond to tickets!!!

### Analysis
The challenge starts off in a very unusual way: instead of giving us logs, binaries, or packet captures, we are handed a single image file `Zard.jpg`. The image shows what is claimed to be a prototype Pokémon Charizard card from 1996, professionally graded and sealed by CGC.

{% asset_img Zard.webp Zard.jpg %}

At first glance, everything looks convincing. The artwork matches early Pokémon designs, the Japanese text seems authentic, and the slab gives the card an added sense of legitimacy. Nothing immediately screams “fake.”

However, the description hints that something feels off. This pushes us to think beyond surface-level inspection and approach the problem from a digital forensics perspective.

What made this challenge particularly exciting for me is that I had never worked with Pokémon cards or TCGs before. That unfamiliarity actually made the challenge more fun, it felt like learning something entirely new while still applying forensic techniques I was already familiar with. Instead of parsing binaries or reversing malware, I was suddenly dealing with physical-world artifacts translated into a digital image.

The key question becomes:

If this card truly dates back to 1996, is there any modern artifact that should not be present?

At this point, I stopped thinking about Pokemon cards and started thinking about printing technology. A card like this has to be printed at some stage, and modern printers are known to leave behind subtle forensic traces.

If this image was produced using a modern printer, it might accidentally carry artifacts that simply did not exist in the 1990s.

This realization naturally led me to printer forensics.

### Solution
At this point, I began searching online for prior research related to Pokemon cards and forensic printing artifacts. This led me to an article on Elite Fourum titled:
**“Yellow Dot Decoder – Fake Prototype Playtest Cards”**

{% asset_img elitefourum.webp elitefourum.com%}

The article explains how many fake Pokémon prototype cards were produced using modern color laser printers, which embed yellow tracking dots into printed materials. These dots are:
- Nearly invisible to the naked eye
- Arranged in a repeating grid
- Capable of encoding metadata such as:
  - Printing date and time
  - Printer serial number

Reading this article was a turning point. It confirmed that this was not just a theoretical idea, the exact same forensic technique had already been used to expose fake prototype cards in the real world.

Armed with this knowledge, I returned to the image with a clear plan: try to reveal and decode any embedded yellow tracking dots.

I opened the image in GIMP, which provides precise control over color channels.

Instead of adjusting brightness or contrast blindly, the goal was to isolate the color information most likely to expose yellow dots:
`Colors → Components → Extract Component`

{% asset_img extract_components.webp extract_components%}

Here, the RGB Blue channel was selected.

{% asset_img RGB_blue.webp RGB_blue%}

This choice is intentional. In the RGB color model, yellow is the opposite of blue, meaning yellow elements stand out most clearly when the blue channel is isolated. Immediately after extraction, faint but structured dot-like patterns began to appear.

However, the dots were still partially obscured by background texture from the card.

To make the dots readable, additional enhancement was required:
`Colors → Levels`

{% asset_img adjust_color.webp adjust colors%}

The following adjustments were made:
- Input Levels: The black point was shifted to the right to suppress background noise.
- Output Levels: Slight compression to increase contrast.

After fine-tuning these values, the background flattened into uniform gray, while a clear grid of yellow tracking dots emerged. At this point, there was no longer any ambiguity the image definitely contained printer tracking dots.

{% asset_img analysis_bnw_dots.webp bnw dots%}

{% asset_img analysis_yellow_dots.webp yellow dots%}

With the dot pattern clearly visible, the next step was decoding it.

{% asset_img yellow_dots.webp yellow dots decoder%}

Using the Yellow Dot Decoder tool referenced in the Elite Fourum article, the dot grid was manually transcribed and decoded. The decoder successfully extracted the embedded printer metadata:
- Date: 2024-08-06
- Time: 21:49
- Printer Serial Number: 704641508

This conclusively proves that the card was printed in 2024 using a modern printer, making it impossible for it to be a genuine 1996 prototype.

### Flag
`uoftctf{2024_08_06_21:49_704641508}`

### References
- [Yellow Dot Decoder - Fake Prototype Playtest Cards (Elite Fourum)](https://www.elitefourum.com/t/yellow-dot-decoder-fake-prototype-playtest-cards/52472)