#!/bin/bash
set -e

# Ждём появления исходников OpenVPN
echo "Ожидание появления директории openvpn-2.6.14..."
until [ -d trunk/user/openvpn/openvpn-2.6.14 ]; do
    sleep 2
done

cd trunk/user/openvpn/openvpn-2.6.14

# Массив имён патчей
patches=(
    "02-tunnelblick-openvpn_xorpatch-a.diff"
    "03-tunnelblick-openvpn_xorpatch-b.diff"
    "04-tunnelblick-openvpn_xorpatch-c.diff"
    "05-tunnelblick-openvpn_xorpatch-d.diff"
    "06-tunnelblick-openvpn_xorpatch-e.diff"
)

echo "Загрузка и применение XOR-патчей Tunnelblick..."
for patch in "${patches[@]}"; do
    echo "  -> Загрузка $patch"
    wget -q "https://raw.githubusercontent.com/Tunnelblick/Tunnelblick/master/third_party/sources/openvpn/openvpn-2.6.14/patches/$patch" -O "$patch"
    echo "  -> Применение $patch"
    patch -p1 < "$patch"
done

echo "✅ Все патчи успешно применены!"
