#!/bin/bash

# Устанавливаем 3x-ui панель и формируем самоподписанные сертификаты

set -euo pipefail

# --- Проверка и установка необходимых пакетов ---
install_pkg() {
  if ! command -v "$1" &>/dev/null; then
    apt update && apt install -y "$1"
  fi
}

install_pkg openssl
install_pkg qrencode

# --- Установка 3x-ui ---
if ! command -v x-ui &>/dev/null; then
    echo "[INFO] Устанавливаю 3x-ui..."
    bash <(curl -Ls https://raw.githubusercontent.com/MHSanaei/3x-ui/refs/tags/v2.6.0/install.sh)
else
    echo "[INFO] 3x-ui уже установлен."
fi

# --- Запуск службы ---
systemctl daemon-reload
if systemctl list-units --full --all | grep -Fq "x-ui.service"; then
    systemctl enable x-ui
    systemctl start x-ui
else
    x-ui
fi

# --- Генерация сертификата ---
CERT_DIR="/etc/ssl/self_signed_cert"
CERT_NAME="self_signed"
DAYS_VALID=3650

mkdir -p "$CERT_DIR"

CERT_PATH="$CERT_DIR/$CERT_NAME.crt"
KEY_PATH="$CERT_DIR/$CERT_NAME.key"

echo "[INFO] Генерирую самоподписанный сертификат на 10 лет..."

openssl req -x509 -nodes -days "$DAYS_VALID" -newkey rsa:2048 \
  -keyout "$KEY_PATH" \
  -out "$CERT_PATH" \
  -subj "/C=US/ST=None/L=None/O=None/OU=None/CN=localhost"

echo
echo "==========================================="
echo "      Установка 3x-ui завершена"
echo "==========================================="
echo "Пути к сертификатам:"
echo "  • Публичный сертификат: $CERT_PATH"
echo "  • Приватный ключ:       $KEY_PATH"
echo
echo "Для применения сертификата:"
echo "1) Откройте панель 3x-ui (порт и путь были показаны при установке)"
echo "2) Перейдите в «Настройки панели»"
echo "3) Укажите путь:"
echo "      - Публичный ключ: $CERT_PATH"
echo "      - Приватный ключ: $KEY_PATH"
echo "4) Сохраните и перезапустите панель."
echo
echo "Готово."