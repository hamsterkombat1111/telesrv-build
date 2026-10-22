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

    # 5) google-services.json must know our applicationId.
    #
    # TMessagesProj_App applies the google-services plugin, which fails the build
    # with "No matching client found for package name" unless the package is
    # listed. The Firebase app id is copied from the existing release entry: this
    # build does not use FCM, it only has to satisfy the plugin.
    gs = root / "TMessagesProj_App/google-services.json"
    if gs.exists():
        import json
        data = json.loads(_read(gs))
        want = "com.zalypaebanaia.tg"
        clients = data.get("client", [])
        present = {c.get("client_info", {}).get("android_client_info", {}).get("package_name")
                   for c in clients}
        if want not in present and clients:
            template = next((c for c in clients
                             if c.get("client_info", {}).get("android_client_info", {})
                             .get("package_name") == "org.telegram.messenger"), clients[0])
            entry = json.loads(json.dumps(template))
            entry["client_info"]["android_client_info"]["package_name"] = want
            entry["client_info"]["mobilesdk_app_id"] = "1:760348033671:android:zalypaebanaia"
            clients.append(entry)
            data["client"] = clients
            _write(gs, json.dumps(data, indent=2))
            changed.append(str(gs))
            print("google-services.json: added", want)

    # 6) wallet_available must default to true, not BuildVars.DEBUG_VERSION.
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

    # 7) Point the wallet engine at our own TON network.
    #
    # The native engine talks to toncenter.com over HTTPS to deploy the wallet
    # contract and read balances. Both call sites are in the JNI bridge, which is
    # a normal C++ source file, so the host can be redirected without touching
    # the closed-source Rust library.
    #
    # Our network is served by tonbridge (toncenter-compatible HTTP API v2) in
    # front of the local lite-server; the domain is required because the engine
    # validates the TLS chain and a self-signed cert would be rejected.
    web = root / "TMessagesProj/jni/wallet/WalletEngineBridge.cpp"
    if web.exists():
        src = orig = _read(web)
        old = 'we::ProviderConfig{"https://toncenter.com", std::nullopt, 15000}'
        new = 'we::ProviderConfig{"https://zalypa.xyecoc.bond", std::nullopt, 15000}'
        count = src.count(old)
        src = src.replace(old, new)
        if src != orig:
            _write(web, src)
            changed.append(str(web))
            print(f"ton provider redirected ({count} sites)")

    # 8) Wallet creation must go through import, not through the server.
    #
    # The client's "Create a New Wallet" path sends wallet.replaceWallet with
    # inputWalletNew, asking the server to mint the wallet. Our server cannot:
    # the phrase format the client accepts is its own Rotation mnemonic,
    # validated by a closed-source native engine, so a server-generated phrase is
    # rejected with "Invalid Rotation recovery phrase".
    #
    # WalletImportFragment is the correct path: it generates the phrase with the
    # same engine that later verifies it, then binds the wallet through
    # inputWalletImported plus an ownership proof the server verifies.
    wkb = root / "TMessagesProj/src/main/java/org/telegram/ui/Wallet/WalletKeysBackupFragment.java"
    if wkb.exists():
        src = orig = _read(wkb)
        old = """                                wallet.createNewWallet(error -> {
                                    if (error != null) {
                                        BulletinFactory.of(WalletKeysBackupFragment.this).showForError(error);
                                        return;
                                    }
                                    finishFragment();
                                    if (previousFragment instanceof WalletActivity) {
                                        final BaseFragment walletFragment = previousFragment;
                                        AndroidUtilities.runOnUIThread(() -> {
                                            if (BulletinFactory.canShowBulletin(walletFragment)) {
                                                BulletinFactory.of(walletFragment)
                                                    .createSimpleBulletin(R.raw.contact_check, LocaleController.getString(R.string.WalletCreated), LocaleController.getString(R.string.WalletCreatedInfo))
                                                    .show();
                                            }
                                        }, 300);
                                    }
                                });"""
        new = """                                // Self-custody: the phrase is generated on the device by
                                // WalletImportFragment, because the server cannot mint a
                                // Rotation phrase and a server-side wallet could never be
                                // signed for.
                                presentFragment(new WalletImportFragment().setWipe(!saveLocally));"""
        src = src.replace(old, new, 1)
        if src != orig:
            _write(wkb, src)
            changed.append(str(wkb))
            print("wallet creation redirected to import")

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
