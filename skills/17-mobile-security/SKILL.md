---
name: "mobile-security"
description: "Android and iOS application security testing, static and dynamic analysis, APK/IPA inspection, OWASP MASVS/MASTG verification, and mobile malware triage."
---

# Mobile Application Security

## When to Use
Testing Android (APK/AAB) or iOS (IPA) application security, decompiling, static/dynamic analysis, secure storage review, and mobile malware triage.

## Workflow
1. Static analysis: unpack/decode APK/IPA, review manifest/plist, flag exported components, permissions, and debug flags.
2. Secret hunting: scan decompiled sources and resources for API keys, tokens, private keys, backend URLs.
3. Review insecure data storage (SharedPreferences, Keychain, SQLite, logs, WebView cache, clipboard).
4. Verify TLS everywhere, certificate pinning, and no cleartext fallback.
5. Dynamic instrumentation with Frida/objection: disable SSL pinning, dump keystore/keychain, trace sensitive methods.
6. Platform interaction review: IPC, WebView, deep links, anti-tampering controls.
7. Mobile malware triage: permissions vs. stated function, accessibility-service abuse, C2 URLs, dynamic code loading.

## Scripts
- `scripts/apk_analyzer.py` — Static triage of an APK: manifest flags, permissions, exported components, secret scanning. Supports optional decompiled sources directory for deeper analysis.

## Output
- APK/IPA security assessment with MASVS coverage table.
- Findings mapped to MASTG tests with evidence and remediation.
- Secret scan results with file locations and match excerpts.

## Prerequisites
```bash
pip install requests pyaxmlparser
```

**Optional:** apktool, jadx, apkid, frida, objection, MobSF, adb

## References
- OWASP MASVS
- OWASP MASTG
- OWASP Mobile Top 10 (2024)
- Frida Documentation
- objection Documentation
- MobSF Documentation
