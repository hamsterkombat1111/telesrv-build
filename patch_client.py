#!/usr/bin/env python3
"""Патч DrKLO Telegram под свой сервер: DC-адреса, RSA-ключ, fingerprint, APP_ID/HASH."""
import pathlib
import re
import sys

OUR_IP = "144.31.167.136"
OUR_PORT = 2398

# публичный ключ (RSAPublicKey DER) нашего server_rsa.pem
OUR_PUBKEY_B64 = (
    "MIIBCgKCAQEAz7F4hZSo7AK3UQbwXCWBasQJts1M2LU2s/OkCRSxde/MWIIJy77d"
    "tTYVYj/wm72SlSnY7d6rCNlslHu7i16Rd6G/0bb9eIjb2YIosSFEhXIMR5pKDuh8"
    "rle49WfvE4V9+AKquw+xIa+07HkyTePI4d78++aKM00CDeBD/NcYYkcyTG7y8gpV"
    "F+oxjJEaw5L03uhUepzhgKRrAt7GJsUQmYlkPEtDB2gp8TOC1CNNk1ecHtTY0wGb"
    "hItzMqcOEOdVq9WhvSO0LT1TJSOrGdOf27KGbJ5emJnE3ENiW/RLOrXXLuY6QoCf"
    "yt9lo9W6xu94BLnpx0pxGXti1J68ZsQfoQIDAQAB"
)
OUR_FP = 0xA228111F83E5BE80

RE_ADDR = re.compile(
    r'datacenter->addAddressAndPort\("([0-9a-fA-F:.]+)",\s*\d+,\s*([01]),\s*([^)]*)\);')
RE_PEM = re.compile(
    r'serverPublicKeys\.emplace_back\("-----BEGIN RSA PUBLIC KEY-----\\n".*?'
    r'"-----END RSA PUBLIC KEY-----"\);', re.S)
RE_FP = re.compile(r'serverPublicKeysFingerprints\.push_back\(0x[0-9a-fA-F]+\);')


def _read(p):
    return p.read_text(encoding="utf-8", errors="surrogateescape")


def _write(p, s):
    p.write_text(s, encoding="utf-8", errors="surrogateescape")


def _pem_block() -> str:
    lines = ['                                                  "%s\\n"' % OUR_PUBKEY_B64[i:i + 64]
             for i in range(0, len(OUR_PUBKEY_B64), 64)]
    return ('serverPublicKeys.emplace_back("-----BEGIN RSA PUBLIC KEY-----\\n"\n'
            + "\n".join(lines)
            + '\n                                                  "-----END RSA PUBLIC KEY-----");')


def patch(root: pathlib.Path) -> list[str]:
    changed = []

    # 1) DC-адреса -> наш IP:2398 (IPv4 и IPv6, сохраняя family и username)
    cm = root / "TMessagesProj/jni/tgnet/ConnectionsManager.cpp"
    src = orig = _read(cm)
    src, n = RE_ADDR.subn(
        lambda m: 'datacenter->addAddressAndPort("%s", %d, %s, %s);'
                  % (OUR_IP, OUR_PORT, m.group(2), m.group(3)), src)
    print(f"DC addresses replaced: {n}")
    if src != orig:
        _write(cm, src)
        changed.append(str(cm))

    # 2) RSA-ключ + fingerprint
    hs = root / "TMessagesProj/jni/tgnet/Handshake.cpp"
    src = orig = _read(hs)
    blocks = RE_PEM.findall(src)
    print(f"RSA PEM blocks found: {len(blocks)}")
    if blocks:
        src = RE_PEM.sub(lambda m: _pem_block(), src)
    src, nfp = RE_FP.subn(
        'serverPublicKeysFingerprints.push_back(0x%016x);' % OUR_FP, src)
    print(f"Fingerprints replaced: {nfp}")
    if src != orig:
        _write(hs, src)
        changed.append(str(hs))

    # 3) APP_ID / APP_HASH
    bv = root / "TMessagesProj/src/main/java/org/telegram/messenger/BuildVars.java"
    if bv.exists():
        src = orig = _read(bv)
        src = re.sub(r'APP_ID\s*=\s*\d+', 'APP_ID = 4', src)
        src = re.sub(r'APP_HASH\s*=\s*"[^"]*"',
                     'APP_HASH = "014b35b6184100b085b0d0572f9b5103"', src)
        if src != orig:
            _write(bv, src)
            changed.append(str(bv))
            print("BuildVars APP_ID/APP_HASH patched")

    # 4) Package name: com.zalypaebanaia.tg
    #
    # APP_PACKAGE drives applicationId for every variant (see
    # TMessagesProj_App/build.gradle: defaultConfig.applicationId = APP_PACKAGE).
    # The namespace stays org.telegram.messenger, so R/BuildConfig references in
    # the Java sources keep resolving -- only the installed identity changes.
    gp = root / "gradle.properties"
    if gp.exists():
        src = orig = _read(gp)
        src = re.sub(r'^APP_PACKAGE=.*$', 'APP_PACKAGE=com.zalypaebanaia.tg', src, flags=re.M)
        if src != orig:
            _write(gp, src)
            changed.append(str(gp))
            print("APP_PACKAGE patched -> com.zalypaebanaia.tg")

    # 5) wallet_available must default to true, not BuildVars.DEBUG_VERSION.
    #
    # Release builds set DEBUG_VERSION=false, so the wallet gate defaulted to
    # false and no client ever rendered the Send money entry point unless the
    # server config happened to arrive first. Forcing the default makes the
    # wallet reachable on a clean install; a server-sent value still overrides it.
    agc = root / "TMessagesProj/src/main/java/org/telegram/messenger/AppGlobalConfig.java"
    if agc.exists():
        src = orig = _read(agc)
        src = re.sub(
            r'ofBoolean\("wallet_available",\s*BuildVars\.DEBUG_VERSION\)',
            'ofBoolean("wallet_available", true)', src)
        if src != orig:
            _write(agc, src)
            changed.append(str(agc))
            print("wallet_available default -> true")

    return changed


def main() -> int:
    root = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else ".")
    changed = patch(root)
    print("CHANGED FILES:")
    for c in changed:
        print("  ", c)
    return 0


if __name__ == "__main__":
    sys.exit(main())
