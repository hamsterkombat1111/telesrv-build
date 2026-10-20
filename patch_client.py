#!/usr/bin/env python3
"""
Патч DrKLO Telegram под свой сервер:
  - все DC (IPv4 + IPv6) -> наш IP:2398
  - RSA-ключ сервера -> наш публичный ключ
  - fingerprint -> вычисленный от нашего ключа
  - app id / hash / version -> свои
"""
import re
import sys
import pathlib

OUR_IP = "144.31.167.136"
OUR_PORT = 2398

# base64 публичного ключа (RSAPublicKey DER) нашего server_rsa.pem
OUR_PUBKEY_B64 = (
    "MIIBCgKCAQEAz7F4hZSo7AK3UQbwXCWBasQJts1M2LU2s/OkCRSxde/MWIIJy77d"
    "tTYVYj/wm72SlSnY7d6rCNlslHu7i16Rd6G/0bb9eIjb2YIosSFEhXIMR5pKDuh8"
    "rle49WfvE4V9+AKquw+xIa+07HkyTePI4d78++aKM00CDeBD/NcYYkcyTG7y8gpV"
    "F+oxjJEaw5L03uhUepzhgKRrAt7GJsUQmYlkPEtDB2gp8TOC1CNNk1ecHtTY0wGb"
    "hItzMqcOEOdVq9WhvSO0LT1TJSOrGdOf27KGbJ5emJnE3ENiW/RLOrXXLuY6QoCf"
    "yt9lo9W6xu94BLnpx0pxGXti1J68ZsQfoQIDAQAB"
)
OUR_FP = 0xA228111F83E5BE80

root = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else ".")

def read(p):
    return p.read_text(encoding="utf-8", errors="surrogateescape")

def write(p, s):
    p.write_text(s, encoding="utf-8", errors="surrogateescape")

changed = []

# ---------- 1) ConnectionsManager.cpp: DC адреса ----------
cm = root / "TMessagesProj/jni/tgnet/ConnectionsManager.cpp"
src = read(cm)
orig = src

# все addAddressAndPort("IP", 443, ...) -> наш IP:2398 (и IPv4, и IPv6)
def repl_addr(m):
    return 'datacenter->addAddressAndPort("%s", %d, %s, %s);' % (
        OUR_IP, OUR_PORT, m.group(3), m.group(4))

src, n = re.subn(
    r'datacenter->addAddressAndPort\("([0-9a-fA-F:.]+)",\s*443,\s*([01]),\s*(""|[^)]*)\);',
    repl_addr, src)
print(f"DC addresses replaced: {n}")

# default port 443 -> 2398 в этом файле (осторожно: только для datacenter)
if src != orig:
    write(cm, src)
    changed.append(str(cm))

# ---------- 2) Handshake.cpp: RSA ключ + fingerprint ----------
hs = root / "TMessagesProj/jni/tgnet/Handshake.cpp"
src = read(hs)
orig = src

# заменить все PEM-блоки RSA PUBLIC KEY на наш
pem_lines = []
b64 = OUR_PUBKEY_B64
for i in range(0, len(b64), 64):
    pem_lines.append('                                                  "%s\\n"' % b64[i:i+64])
new_pem = ('serverPublicKeys.emplace_back("-----BEGIN RSA PUBLIC KEY-----\\n"\n'
           + "\n".join(pem_lines)
           + '\n                                                  "-----END RSA PUBLIC KEY-----");')

# находим блоки emplace_back с BEGIN RSA PUBLIC KEY ... END
pattern = re.compile(
    r'serverPublicKeys\.emplace_back\("-----BEGIN RSA PUBLIC KEY-----\\n".*?'
    r'"-----END RSA PUBLIC KEY-----"\);', re.S)
matches = pattern.findall(src)
print(f"RSA PEM blocks found: {len(matches)}")
if matches:
    src = pattern.sub(new_pem, src)

# fingerprint константы -> наш
src, nfp = re.subn(r'serverPublicKeysFingerprints\.push_back\(0x[0-9a-fA-F]+\);',
                   'serverPublicKeysFingerprints.push_back(0x%016x);' % OUR_FP, src)
print(f"Fingerprints replaced: {nfp}")

if src != orig:
    write(hs, src)
    changed.append(str(hs))

# ---------- 3) BuildVars.java: app id / hash ----------
bv = root / "TMessagesProj/src/main/java/org/telegram/messenger/BuildVars.java"
if bv.exists():
    src = read(bv)
    orig = src
    src = re.sub(r'APP_ID\s*=\s*\d+', 'APP_ID = 4', src)
    src = re.sub(r'APP_HASH\s*=\s*"[^"]*"', 'APP_HASH = "014b35b6184100b085b0d0572f9b5103"', src)
    if src != orig:
        write(bv, src)
        changed.append(str(bv))
        print("BuildVars APP_ID/APP_HASH patched")

print("CHANGED FILES:")
for c in changed:
    print("  ", c)
