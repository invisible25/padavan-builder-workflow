#!/bin/bash
# Custom pre-build hook (runs after padavan-ng sources are cloned, before build).
#
# Replaces the OpenVPN bundled in padavan-ng with a newer release and applies
# the XOR / scramble obfuscation patch (official Tunnelblick patch set, matched
# to the OpenVPN version). The scramble option lets OpenVPN traffic evade
# DPI-based blocking; it is obfuscation, not encryption, and the server must run
# a matching XOR-patched OpenVPN with the same `scramble` setting.
set -e

NEWVER="2.7.8"
REPO_ROOT="$(pwd)"
XOR_PATCHES="${REPO_ROOT}/patches/openvpn-xor-${NEWVER}"

cd padavan-ng/trunk/user/openvpn

# Drop whatever OpenVPN source padavan-ng bundles (any version but our target),
# so we build exactly the version we vendor below.
find . -maxdepth 1 \( -name 'openvpn-2.*' -o -name 'config_done' \) \
  ! -name "openvpn-${NEWVER}" ! -name "openvpn-${NEWVER}.tar.gz" -exec rm -rf {} +

# Point padavan's package Makefile at the new version.
sed -i "s|^SRC_NAME=.*|SRC_NAME=openvpn-${NEWVER}|" Makefile
sed -i "s|^SRC_URL=.*|SRC_URL=https://github.com/OpenVPN/openvpn/archive/refs/tags/v${NEWVER}.tar.gz|" Makefile

# Fetch the new OpenVPN source (kept as .tar.gz so the Makefile's download step
# is a no-op; the extracted dir below makes its extract step a no-op too).
if [ ! -f "openvpn-${NEWVER}.tar.gz" ]; then
  wget -t5 -T30 --no-check-certificate -O "openvpn-${NEWVER}.tar.gz" \
    "https://github.com/OpenVPN/openvpn/archive/refs/tags/v${NEWVER}.tar.gz"
fi
rm -rf "openvpn-${NEWVER}"
tar -xf "openvpn-${NEWVER}.tar.gz"
# archive extracts as openvpn-<ver> already; normalise just in case
[ -d "openvpn-${NEWVER}" ] || mv openvpn-* "openvpn-${NEWVER}"

# padavan's openvpn-orig.patch trims sample/doc/tests from the build (they break
# the cross-compile), but it is pinned to the 2.6 Makefile.am SUBDIRS layout.
# Do the same trim version-agnostically so it works across OpenVPN releases.
sed -i 's/ sample doc tests//' "openvpn-${NEWVER}/Makefile.am"
if grep -qE '^SUBDIRS =.*(sample|doc|tests)' "openvpn-${NEWVER}/Makefile.am"; then
  echo "ERROR: failed to trim sample/doc/tests from Makefile.am SUBDIRS"; exit 1
fi

# XOR / scramble obfuscation (Tunnelblick patch set matched to ${NEWVER}).
for p in \
  02-tunnelblick-openvpn_xorpatch-a.diff \
  03-tunnelblick-openvpn_xorpatch-b.diff \
  04-tunnelblick-openvpn_xorpatch-c.diff \
  05-tunnelblick-openvpn_xorpatch-d.diff \
  06-tunnelblick-openvpn_xorpatch-e.diff ; do
  patch -d "openvpn-${NEWVER}" -p1 -i "${XOR_PATCHES}/${p}"
done

# Fail loudly if the scramble option did not land.
grep -q 'streq (p\[0\], "scramble")' "openvpn-${NEWVER}/src/openvpn/options.c"
echo "OpenVPN replaced with ${NEWVER} and XOR-patched (scramble option present)."
