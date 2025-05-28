#!/bin/bash
set -e

cd padavan-ng/trunk/user/openvpn/openvpn-2.6.14

wget https://raw.githubusercontent.com/Tunnelblick/Tunnelblick/master/third_party/sources/openvpn/openvpn-2.6.14/patches/02-tunnelblick-openvpn_xorpatch-a.diff
wget https://raw.githubusercontent.com/Tunnelblick/Tunnelblick/master/third_party/sources/openvpn/openvpn-2.6.14/patches/03-tunnelblick-openvpn_xorpatch-b.diff
wget https://raw.githubusercontent.com/Tunnelblick/Tunnelblick/master/third_party/sources/openvpn/openvpn-2.6.14/patches/04-tunnelblick-openvpn_xorpatch-c.diff
wget https://raw.githubusercontent.com/Tunnelblick/Tunnelblick/master/third_party/sources/openvpn/openvpn-2.6.14/patches/05-tunnelblick-openvpn_xorpatch-d.diff
wget https://raw.githubusercontent.com/Tunnelblick/Tunnelblick/master/third_party/sources/openvpn/openvpn-2.6.14/patches/06-tunnelblick-openvpn_xorpatch-e.diff

patch -p1 < 02-tunnelblick-openvpn_xorpatch-a.diff
patch -p1 < 03-tunnelblick-openvpn_xorpatch-b.diff
patch -p1 < 04-tunnelblick-openvpn_xorpatch-c.diff
patch -p1 < 05-tunnelblick-openvpn_xorpatch-d.diff
patch -p1 < 06-tunnelblick-openvpn_xorpatch-e.diff
