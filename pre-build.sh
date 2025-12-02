#!/bin/bash
set -e

cd padavan-ng/trunk/user/openvpn/openvpn-2.6.17

wget https://github.com/samanajd2/OpenVPN-XOR-windows/blob/master/Xor-Patches/02-tunnelblick-openvpn_xorpatch-a.diff
wget https://github.com/samanajd2/OpenVPN-XOR-windows/blob/master/Xor-Patches/03-tunnelblick-openvpn_xorpatch-b.diff
wget https://github.com/samanajd2/OpenVPN-XOR-windows/blob/master/Xor-Patches/04-tunnelblick-openvpn_xorpatch-c.diff
wget https://github.com/samanajd2/OpenVPN-XOR-windows/blob/master/Xor-Patches/05-tunnelblick-openvpn_xorpatch-d.diff
wget https://github.com/samanajd2/OpenVPN-XOR-windows/blob/master/Xor-Patches/06-tunnelblick-openvpn_xorpatch-e.diff

patch -p1 < 02-tunnelblick-openvpn_xorpatch-a.diff
patch -p1 < 03-tunnelblick-openvpn_xorpatch-b.diff
patch -p1 < 04-tunnelblick-openvpn_xorpatch-c.diff
patch -p1 < 05-tunnelblick-openvpn_xorpatch-d.diff
patch -p1 < 06-tunnelblick-openvpn_xorpatch-e.diff
