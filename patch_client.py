#!/usr/bin/env python3
"""Патч DrKLO Telegram под свой сервер: DC-адреса, RSA-ключ, fingerprint, APP_ID/HASH, кошелёк."""
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
    gp = root / "gradle.properties"
    if gp.exists():
        src = orig = _read(gp)
        src = re.sub(r'^APP_PACKAGE=.*$', 'APP_PACKAGE=com.zalypaebanaia.tg', src, flags=re.M)
        if src != orig:
            _write(gp, src)
            changed.append(str(gp))
            print("APP_PACKAGE patched -> com.zalypaebanaia.tg")

    # 5) google-services.json must know our applicationId.
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

    # 8) Safe storage.wipe in WalletKeysBackupFragment (prevent NPE when wallet.storage is null)
    wkb = root / "TMessagesProj/src/main/java/org/telegram/ui/Wallet/WalletKeysBackupFragment.java"
    if wkb.exists():
        src = orig = _read(wkb)
        old_wipe = """                                if (!saveLocally) {
                                    wallet.storage.wipe();
                                }"""
        new_wipe = """                                if (!saveLocally && wallet.storage != null) {
                                    wallet.storage.wipe();
                                }"""
        src = src.replace(old_wipe, new_wipe, 1)
        if src != orig:
            _write(wkb, src)
            changed.append(str(wkb))
            print("WalletKeysBackupFragment storage wipe NPE guarded")

    # 9) Auto-provision wallet on empty state & ensure challenge before createNewWallet
    gw = root / "TMessagesProj/src/main/java/org/telegram/ui/Wallet/GramWallet.java"
    if gw.exists():
        src = orig = _read(gw)

        # 9a) When server returns TL_walletStateEmpty, trigger auto-creation
        old_rs = """        requestingStateId = getConnectionsManager().sendRequestTyped(new TL_wallet.getState(), AndroidUtilities::runOnUIThread, (state, err) -> {
            requestingStateId = -1;
            if (state == null) {
                err("requesting gasless info: " + (err != null ? err.text : "NULL_ERROR"));
                return;
            }"""
        new_rs = """        requestingStateId = getConnectionsManager().sendRequestTyped(new TL_wallet.getState(), AndroidUtilities::runOnUIThread, (state, err) -> {
            requestingStateId = -1;
            if (state == null) {
                err("requesting gasless info: " + (err != null ? err.text : "NULL_ERROR"));
                return;
            }
            if (state instanceof TL_wallet.TL_walletStateEmpty) {
                this.state = state;
                onStateUpdate();
                notifyUpdate();
                createNewWallet(null);
                return;
            }"""
        src = src.replace(old_rs, new_rs, 1)

        # 9b) Request proof challenge before replaceWallet so server validates creation
        old_cnw = """    public void createNewWallet(Utilities.Callback<String> whenDone) {
        PasswordRequest.open(currentAccount, password -> {
            final TL_wallet.replaceWallet req = new TL_wallet.replaceWallet();
            req.wallet = new TL_wallet.inputWalletNew();
            req.password = password;
            return req;
        }, (state, error, password) -> {
            if (error != null) {
                whenDone.run(error.text == null ? "NULL_ERROR" : error.text);
                return;
            }
            updateState(state);
            onWalletChanged();
            whenDone.run(null);
        });
    }"""
        new_cnw = """    public void createNewWallet(Utilities.Callback<String> whenDone) {
        getConnectionsManager().sendRequestTyped(new TL_wallet.getProofChallenge(), AndroidUtilities::runOnUIThread, (challenge, chErr) -> {
            PasswordRequest.open(currentAccount, password -> {
                final TL_wallet.replaceWallet req = new TL_wallet.replaceWallet();
                req.wallet = new TL_wallet.inputWalletNew();
                req.password = password;
                return req;
            }, (state, error, password) -> {
                if (error != null) {
                    if (whenDone != null) whenDone.run(error.text == null ? "NULL_ERROR" : error.text);
                    return;
                }
                updateState(state);
                onWalletChanged();
                if (whenDone != null) whenDone.run(null);
            });
        });
    }"""
        src = src.replace(old_cnw, new_cnw, 1)

        if src != orig:
            _write(gw, src)
            changed.append(str(gw))
            print("GramWallet auto-provision & proof challenge wired")

    # 10) WalletActivity auto-trigger create if not ready & empty state
    wa = root / "TMessagesProj/src/main/java/org/telegram/ui/Wallet/WalletActivity.java"
    if wa.exists():
        src = orig = _read(wa)
        old_wa = """        if (!wallet.isReady()) {
            balanceView.setText(loading(0));"""
        new_wa = """        if (!wallet.isReady()) {
            if (wallet.getState() instanceof TL_wallet.TL_walletStateEmpty) {
                wallet.createNewWallet(null);
            }
            balanceView.setText(loading(0));"""
        src = src.replace(old_wa, new_wa, 1)
        if src != orig:
            _write(wa, src)
            changed.append(str(wa))
            print("WalletActivity auto-trigger create wired")

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
