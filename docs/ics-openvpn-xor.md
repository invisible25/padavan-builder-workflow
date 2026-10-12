# OpenVPN XOR / scramble obfuscation build

This fork adds the OpenVPN **XOR scramble** obfuscation patch (the
Tunnelblick / clayface `--scramble` family) to the bundled OpenVPN 2.x
engine and builds installable APKs via GitHub Actions.

The patch lives at `patches/openvpn-xor-scramble.patch` and is applied to
the `main/src/main/cpp/openvpn` submodule at build time by
`.github/workflows/build-xor.yaml`.

## What it does

It XORs / permutes the on-wire byte stream so the traffic no longer looks
like OpenVPN to deep-packet-inspection (DPI) censorship systems. It is an
**anti-censorship / anti-DPI obfuscation layer, not encryption** — it does
not add or replace OpenVPN's own cryptography.

## Supported `--scramble` modes (add to your client `.ovpn` profile)

```
scramble xormask <password>   # XOR every byte with <password>, repeating
scramble xorptrpos            # XOR each byte with its position
scramble reverse              # reverse the packet payload
scramble obfuscate <password> # all of the above, combined
```

## Important requirements

- Works only with profiles that use the **OpenVPN 2.x** core (not the
  OpenVPN 3 core). Build/use the `UiOvpn2` flavour, or select the OpenVPN 2
  engine for the profile.
- The **server** must run a matching XOR-patched OpenVPN with the **same
  `scramble` setting and password**, or it will not connect.

## Getting the APK

Open the **Actions** tab → latest **Build XOR APK** run → download the
`ics-openvpn-xor-apk` artifact. It is debug-signed for sideloading.
