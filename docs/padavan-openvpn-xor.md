# Padavan firmware: newer OpenVPN + XOR scramble

`pre-build.sh` runs during the **Build firmware** workflow (after padavan-ng
sources are cloned, before the build) and:

1. Replaces the OpenVPN that padavan-ng bundles with **OpenVPN 2.6.23**
   (updating `user/openvpn/Makefile` `SRC_NAME` / `SRC_URL`).
2. Re-applies padavan's own `openvpn-orig.patch` (build-tree trim).
3. Applies the **XOR / scramble** obfuscation patch — the official
   Tunnelblick patch set matched to 2.6.23, vendored under
   `patches/openvpn-xor-2.6.23/`.

The resulting router firmware's OpenVPN understands the `scramble` option:

```
scramble xormask <password>
scramble xorptrpos
scramble reverse
scramble obfuscate <password>
```

This obfuscates the OpenVPN byte stream against DPI-based blocking. It is
**not** encryption. The **server** must run a matching XOR-patched OpenVPN
with the same `scramble` setting, or connections will fail.

## Changing the version

To use a different OpenVPN release (e.g. the 2.7 line), set `NEWVER` in
`pre-build.sh` and drop the matching Tunnelblick patch set into
`patches/openvpn-xor-<version>/`. Tunnelblick currently ships matched XOR
patches for 2.6.23 and 2.7.8.

## Building

Actions → **Build firmware** → Run workflow (the firmware target comes from
`build.config`). The firmware is uploaded as the run's artifact.
