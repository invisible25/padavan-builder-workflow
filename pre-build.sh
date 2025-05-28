#!/bin/bash
set -e

OPENVPN_DIR="trunk/user/openvpn-2.6.14"
PATCH_URL_BASE="https://raw.githubusercontent.com/Tunnelblick/Tunnelblick/master/third_party/sources/openvpn/openvpn-2.6.14/patches"
PATCHES=(02-XOR.patch 03-XOR-define.patch 04-XOR-verify.patch 05-XOR-digest.patch 06-XOR-negotiation.patch)

echo "🔧 pre-build.sh: ожидание директории $OPENVPN_DIR (макс. 3 мин)..."

for i in {1..18}; do
  if [ -d "$OPENVPN_DIR" ]; then
    echo "✅ Найдена директория $OPENVPN_DIR"
    break
  fi
  sleep 10
done

if [ ! -d "$OPENVPN_DIR" ]; then
  echo "❌ Директория $OPENVPN_DIR не найдена. Завершение."
  exit 1
fi

cd "$OPENVPN_DIR"
echo "📥 Загрузка и применение XOR-патчей:"

for PATCH in "${PATCHES[@]}"; do
  echo "➕ Применение $PATCH..."
  curl -fsSL "$PATCH_URL_BASE/$PATCH" -o "$PATCH"
  patch -p1 < "$PATCH"
done

echo "✅ Патчи применены успешно."
