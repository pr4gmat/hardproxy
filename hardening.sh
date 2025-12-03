#!/bin/bash

# Жёсткий режим: выходим при ошибках и неиспользуемых переменных
set -euo pipefail

############################################
# ================ VIEW ====================
############################################

# === Цвета ===
VIEW_RESET="\e[0m"
VIEW_BOLD="\e[1m"

VIEW_RED="\e[31m"
VIEW_GREEN="\e[32m"
VIEW_YELLOW="\e[33m"
VIEW_BLUE="\e[34m"
VIEW_MAGENTA="\e[35m"
VIEW_CYAN="\e[36m"
VIEW_WHITE="\e[97m"

# === Логотип ===
view_logo() {
    echo -e "${VIEW_BOLD}${VIEW_CYAN}"
    cat <<'EOF'
 __   __  _______  ______    ______   _______  __    _  ___   __    _  _______        _______  __   __
|  | |  ||   _   ||    _ |  |      | |       ||  |  | ||   | |  |  | ||       |      |       ||  | |  |
|  |_|  ||  |_|  ||   | ||  |  _    ||    ___||   |_| ||   | |   |_| ||    ___|      |  _____||  |_|  |
|       ||       ||   |_||_ | | |   ||   |___ |       ||   | |       ||   | __       | |_____ |       |
|       ||       ||    __  || |_|   ||    ___||  _    ||   | |  _    ||   ||  | ___  |_____  ||       |
|   _   ||   _   ||   |  | ||       ||   |___ | | |   ||   | | | |   ||   |_| ||   |  _____| ||   _   |
|__| |__||__| |__||___|  |_||______| |_______||_|  |__||___| |_|  |__||_______||___| |_______||__| |__|

Version: v1.0
EOF
    echo -e "${RESET}"
}

# === Баннер секции ===
view_banner() {
    local title="$1"
    echo -e "${VIEW_BOLD}${VIEW_CYAN}====================[ ${title} ]====================${VIEW_RESET}"
}

# === Универсальный логгер ===
# типы: INFO / OK / WARN / ERROR
view_log() {
    local type="$1"
    local msg="$2"
    local color="$VIEW_WHITE"

    case "$type" in
        INFO)  color="$VIEW_CYAN" ;;
        OK)    color="$VIEW_GREEN" ;;
        WARN)  color="$VIEW_YELLOW" ;;
        ERROR) color="$VIEW_RED" ;;
        *)     color="$VIEW_WHITE" ;;
    esac

    echo -e "${VIEW_BOLD}${color}[${type}]${VIEW_RESET} ${msg}"
}

# Удобные короткие обёртки
log_info()  { view_log "INFO"  "$1"; }
log_ok()    { view_log "OK"    "$1"; }
log_warn()  { view_log "WARN"  "$1"; }
log_error() { view_log "ERROR" "$1"; }

############################################
# ============== LOGGING ===================
############################################

# Путь к лог-файлу
LOG_FILE="/var/log/vps_hardening.log"

setup_logging() {
    local log_dir
    log_dir="$(dirname "$LOG_FILE")"

    # Создаём директорию и сам лог-файл, если их нет
    mkdir -p "$log_dir"
    touch "$LOG_FILE"

    # Ограничиваем доступ: только root читает и пишет
    chmod 600 "$LOG_FILE"

    # Перенаправляем stdout и stderr в tee:
    # - всё, что скрипт выводит, видно на экране
    # - и одновременно пишется в лог
    exec > >(tee -a "$LOG_FILE") 2>&1

    # Стартовый красивый блок в логе
    echo
    view_banner "Запуск скрипта усиления безопасности"
    log_info "Дата и время запуска: $(date)"
    log_info "Лог-файл: ${LOG_FILE}"
    echo
}

############################################
# ============ ENV & CHECKS ===============
############################################

check_root() {
    if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
        log_error "Скрипт должен быть запущен от root."
        echo "Запустите: sudo bash $0"
        exit 1
    fi
    log_ok "Проверка root-привилегий пройдена"
}

check_ubuntu() {
    if [[ ! -f /etc/os-release ]]; then
        log_error "Не удалось определить операционную систему (нет /etc/os-release)."
        exit 1
    fi

    # shellcheck disable=SC1091
    . /etc/os-release

    if [[ "${ID}" != "ubuntu" ]]; then
        log_error "Этот скрипт предназначен только для Ubuntu. Обнаружено: ${ID}"
        exit 1
    fi

    local major minor
    major="${VERSION_ID%%.*}"
    minor="${VERSION_ID#*.}"

    if (( major < 20 )); then
        log_warn "Обнаружена Ubuntu ${VERSION_ID}. Рекомендуется 20.04 или новее."
    fi

    log_ok "ОС подтверждена: Ubuntu ${VERSION_ID}"
}

check_basic_tools() {
    view_banner "Проверка базовых утилит"

    local missing=()

    # Минимальный набор, без которого совсем плохо
    for bin in bash grep sed awk tee; do
        if ! command -v "$bin" >/dev/null 2>&1; then
            missing+=("$bin")
        fi
    done

    if (( ${#missing[@]} > 0 )); then
        log_error "Отсутствуют базовые утилиты: ${missing[*]}"
        echo "Установите их вручную и перезапустите скрипт."
        exit 1
    fi

    log_ok "Все базовые утилиты на месте"
}

############################################
# ============ BASE PACKAGES ==============
############################################

install_base_packages() {
    view_banner "Установка базовых пакетов"

    # Базовый набор, который почти наверняка пригодится
    local packages=(
        sudo
        curl
        wget
        git
        ca-certificates
        ufw
        fail2ban
        apparmor
        apparmor-utils
        auditd
        unattended-upgrades
    )

    local missing=()

    for pkg in "${packages[@]}"; do
        if ! dpkg -s "$pkg" >/dev/null 2>&1; then
            missing+=("$pkg")
        fi
    done

    if (( ${#missing[@]} == 0 )); then
        log_ok "Все базовые пакеты уже установлены"
        return 0
    fi

    log_info "Будут установлены следующие пакеты: ${missing[*]}"

    export DEBIAN_FRONTEND=noninteractive

    if ! apt-get install -y "${missing[@]}"; then
        log_error "Не удалось установить базовые пакеты: ${missing[*]}"
        exit 1
    fi

    log_ok "Базовые пакеты успешно установлены"
}

############################################
# ===== SYSTEM UPDATE & AUTO-UPDATES ======
############################################

update_system() {
    view_banner "Обновление системы"

    export DEBIAN_FRONTEND=noninteractive

    log_info "Обновляю списки пакетов (apt-get update)..."
    # Для apt-get update флаг -y не нужен и не используется
    if ! apt-get update; then
        log_error "Не удалось выполнить apt-get update."
        exit 1
    fi
    log_ok "Списки пакетов обновлены"

    log_info "Устанавливаю доступные обновления (apt-get full-upgrade)..."
    if ! apt-get full-upgrade -y; then
        log_error "Не удалось выполнить полное обновление системы (apt-get full-upgrade)."
        exit 1
    fi
    log_ok "Система успешно обновлена"
}

setup_auto_updates() {
    view_banner "Автоматические обновления (unattended-upgrades)"

    # Пакет мы уже тянули в install_base_packages, но на всякий случай проверим
    if ! dpkg -s unattended-upgrades >/dev/null 2>&1; then
        log_info "unattended-upgrades не установлен, устанавливаю..."
        export DEBIAN_FRONTEND=noninteractive
        if ! apt-get install -y unattended-upgrades; then
            log_error "Не удалось установить unattended-upgrades."
            exit 1
        fi
        log_ok "unattended-upgrades установлен"
    fi

    # Включаем периодические задачи APT
    cat >/etc/apt/apt.conf.d/20auto-upgrades <<EOF
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
EOF

    if [[ $? -ne 0 ]]; then
        log_error "Не удалось записать /etc/apt/apt.conf.d/20auto-upgrades."
        exit 1
    fi

    # Базовая конфигурация unattended-upgrades
    cat >/etc/apt/apt.conf.d/50unattended-upgrades <<'EOF'
Unattended-Upgrade::Allowed-Origins {
        "${distro_id}:${distro_codename}";
        "${distro_id}:${distro_codename}-security";
};

Unattended-Upgrade::Package-Blacklist {
};

Unattended-Upgrade::AutoFixInterruptedDpkg "true";
Unattended-Upgrade::MinimalSteps "true";
Unattended-Upgrade::InstallOnShutdown "false";

Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "false";
Unattended-Upgrade::Automatic-Reboot-Time "02:00";
EOF

    if [[ $? -ne 0 ]]; then
        log_error "Не удалось записать /etc/apt/apt.conf.d/50unattended-upgrades."
        exit 1
    fi

    # Лёгкая проверка — хотя бы запустить dry-run
    log_info "Проверка конфигурации unattended-upgrades (dry-run)..."
    if unattended-upgrade --dry-run --debug >/dev/null 2>&1; then
        log_ok "Конфигурация unattended-upgrades выглядит корректной"
    else
        log_warn "unattended-upgrade dry-run вернул ошибки. Проверьте настройки вручную при необходимости."
    fi
}

############################################
# ============== USER SETUP ===============
############################################

ENGINE_USER=""

create_engine_user() {
    view_banner "Создание пользователя"

    # --- 1. Ввод и проверка имени пользователя ---
    while true; do
        read -rp "Введите имя нового пользователя (8–32 символов, a-z0-9_): " NEWUSER

        # Пустой ввод
        if [[ -z "${NEWUSER}" ]]; then
            log_warn "Имя пользователя не может быть пустым."
            continue
        fi

        # Формат + длина 8–32
        if [[ ! "$NEWUSER" =~ ^[a-z0-9_]{8,32}$ ]]; then
            log_error "Неверный формат имени. Требования:"
            echo "  - длина: 8–32 символов"
            echo "  - разрешённые символы: a-z, 0-9, _"
            continue
        fi

        # Зарезервированные имена
        case "$NEWUSER" in
            root|admin|test|user|server|ubuntu|guest|operator)
                log_error "Имя '$NEWUSER' зарезервировано, выберите другое."
                continue
                ;;
        esac

        # Проверка существования
        if id "$NEWUSER" >/dev/null 2>&1; then
            log_error "Пользователь '$NEWUSER' уже существует."
            continue
        fi

        ENGINE_USER="$NEWUSER"
        log_ok "Имя пользователя принято: ${ENGINE_USER}"
        break
    done

    echo

    # --- 2. Ввод и проверка пароля ---
    local PASS1 PASS2

    while true; do
        echo "Введите пароль для пользователя ${ENGINE_USER}:"
        echo "  - минимум 12 символов"
        echo "  - хотя бы одна строчная буква"
        echo "  - хотя бы одна заглавная буква"
        echo "  - хотя бы одна цифра"
        echo "  - хотя бы один спецсимвол"
        read -rs -p "Пароль: " PASS1
        echo
        read -rs -p "Повторите пароль: " PASS2
        echo

        if [[ "$PASS1" != "$PASS2" ]]; then
            log_error "Пароли не совпадают. Попробуйте ещё раз."
            continue
        fi

        if [[ ${#PASS1} -lt 12 ]]; then
            log_error "Пароль слишком короткий (минимум 12 символов)."
            continue
        fi

        if [[ ! "$PASS1" =~ [a-z] ]]; then
            log_error "Пароль должен содержать хотя бы одну строчную букву."
            continue
        fi

        if [[ ! "$PASS1" =~ [A-Z] ]]; then
            log_error "Пароль должен содержать хотя бы одну заглавную букву."
            continue
        fi

        if [[ ! "$PASS1" =~ [0-9] ]]; then
            log_error "Пароль должен содержать хотя бы одну цифру."
            continue
        fi

        if [[ ! "$PASS1" =~ [^A-Za-z0-9] ]]; then
            log_error "Пароль должен содержать хотя бы один спецсимвол."
            continue
        fi

        break
    done

    # --- 3. Создание пользователя ---
    log_info "Создаю пользователя ${ENGINE_USER}..."
    if ! useradd -m -s /bin/bash "$ENGINE_USER"; then
        log_error "Не удалось создать пользователя ${ENGINE_USER}."
        exit 1
    fi
    log_ok "Пользователь ${ENGINE_USER} создан"

    # --- 4. Установка пароля ---
    echo "${ENGINE_USER}:${PASS1}" | chpasswd
    log_ok "Пароль для ${ENGINE_USER} установлен"

    # --- 5. Добавление в sudo ---
    if getent group sudo >/dev/null 2>&1; then
        usermod -aG sudo "$ENGINE_USER"
        log_ok "Пользователь ${ENGINE_USER} добавлен в группу sudo"
    else
        log_warn "Группа sudo не найдена. Возможно, используется другая модель прав."
    fi

    echo
    log_ok "Создание пользователя завершено."
}

############################################
# ============== SSH CONFIG ===============
############################################

ENGINE_SSH_PORT=""

ensure_ssh_server() {
    view_banner "Проверка OpenSSH"

    if dpkg -s openssh-server >/dev/null 2>&1; then
        log_ok "openssh-server уже установлен"
        return 0
    fi

    log_info "openssh-server не найден, устанавливаю..."
    export DEBIAN_FRONTEND=noninteractive
    if ! apt-get install -y openssh-server; then
        log_error "Не удалось установить openssh-server."
        exit 1
    fi

    log_ok "openssh-server установлен"
}

choose_ssh_port() {
    view_banner "Выбор SSH-порта"

    local port
    while true; do
        read -rp "Введите новый SSH-порт (1024–65535, по умолчанию 2222): " port
        # Если просто Enter — ставим 2222
        if [[ -z "$port" ]]; then
            port=2222
        fi

        # Число ли
        if [[ ! "$port" =~ ^[0-9]+$ ]]; then
            log_error "Порт должен быть числом."
            continue
        fi

        # Диапазон
        if (( port < 1024 || port > 65535 )); then
            log_error "Порт вне допустимого диапазона (1024–65535)."
            continue
        fi

        # Занят ли порт
        if ss -tuln 2>/dev/null | grep -q ":${port}\b"; then
            log_error "Порт ${port} уже используется другим сервисом."
            continue
        fi

        ENGINE_SSH_PORT="$port"
        log_ok "Выбран SSH-порт: ${ENGINE_SSH_PORT}"
        break
    done
}

harden_ssh_config() {
    view_banner "Настройка SSH-сервера"

    local sshd_conf="/etc/ssh/sshd_config"
    local backup_file="/etc/ssh/sshd_config.backup_$(date +%s)"

    if [[ -z "${ENGINE_SSH_PORT}" ]]; then
        log_error "ENGINE_SSH_PORT не задан. Сначала вызовите choose_ssh_port."
        exit 1
    fi

    if [[ ! -f "$sshd_conf" ]]; then
        log_error "Файл ${sshd_conf} не найден. Похоже, openssh-server установлен некорректно."
        exit 1
    fi

    # --- 1. Резервная копия ---
    log_info "Создаю резервную копию sshd_config: ${backup_file}"
    if ! cp "$sshd_conf" "$backup_file"; then
        log_error "Не удалось создать резервную копию sshd_config."
        exit 1
    fi
    log_ok "Резервная копия sshd_config создана"

    # --- 2. Удаляем старый наш блок, если он уже был ---
    sed -i '/^# ===== Настройки безопасности (добавлено скриптом VPS Hardening Engine) =====/,$d' "$sshd_conf"

    # --- 3. Чистим старые директивы, чтобы потом добавить свои ---
    sed -i \
        -e '/^[#[:space:]]*Port[[:space:]]\+/d' \
        -e '/^[#[:space:]]*PermitRootLogin[[:space:]]\+/d' \
        -e '/^[#[:space:]]*PasswordAuthentication[[:space:]]\+/d' \
        -e '/^[#[:space:]]*PermitEmptyPasswords[[:space:]]\+/d' \
        -e '/^[#[:space:]]*Protocol[[:space:]]\+/d' \
        -e '/^[#[:space:]]*ClientAliveInterval[[:space:]]\+/d' \
        -e '/^[#[:space:]]*ClientAliveCountMax[[:space:]]\+/d' \
        -e '/^[#[:space:]]*LoginGraceTime[[:space:]]\+/d' \
        -e '/^[#[:space:]]*MaxAuthTries[[:space:]]\+/d' \
        -e '/^[#[:space:]]*UseDNS[[:space:]]\+/d' \
        "$sshd_conf"

    # --- 4. Добавляем наши настройки в конец файла ---
    cat >>"$sshd_conf" <<EOF

# ===== Настройки безопасности (добавлено скриптом VPS Hardening Engine) =====
Port ${ENGINE_SSH_PORT}
Protocol 2
PermitRootLogin no
PasswordAuthentication yes
PermitEmptyPasswords no
MaxAuthTries 3
LoginGraceTime 20
ClientAliveInterval 120
ClientAliveCountMax 3
UseDNS no
EOF

    # Ограничиваем вход только для нашего пользователя, если он задан
    if [[ -n "$ENGINE_USER" ]]; then
        echo "AllowUsers ${ENGINE_USER}" >>"$sshd_conf"
    fi

    log_ok "Файл sshd_config обновлён"

    # --- 5. Проверка конфигурации ---
    log_info "Проверка конфигурации SSH (sshd -t)..."
    if ! sshd -t >/dev/null 2>&1; then
        log_error "Обнаружены ошибки в sshd_config. Откат к резервной копии."
        cp "$backup_file" "$sshd_conf"
        exit 1
    fi
    log_ok "Конфигурация sshd_config успешна проверена"

    # --- 6. Перезапуск SSH ---
    log_info "Перезапуск службы SSH..."

    if systemctl restart ssh 2>/dev/null; then
        log_ok "Служба ssh перезапущена"
    elif systemctl restart sshd 2>/dev/null; then
        log_ok "Служба sshd перезапущена"
    else
        log_error "Не удалось перезапустить SSH. Восстанавливаю резервную конфигурацию."
        cp "$backup_file" "$sshd_conf"
        systemctl restart ssh 2>/dev/null || systemctl restart sshd 2>/dev/null || true
        exit 1
    fi

    echo
    log_warn "ВНИМАНИЕ: SSH теперь слушает порт ${ENGINE_SSH_PORT}."
    echo "Убедитесь, что вы сможете подключиться по новому порту,"
    echo "и не закрывайте текущую сессию, пока не проверите новое подключение."
}

############################################
# ================ FIREWALL ===============
############################################

setup_ufw() {
    view_banner "Настройка брандмауэра (UFW)"

    if [[ -z "${ENGINE_SSH_PORT}" ]]; then
        log_error "ENGINE_SSH_PORT не задан. Сначала настройте SSH (choose_ssh_port/harden_ssh_config)."
        exit 1
    fi

    # Проверяем, установлен ли ufw (должен быть после install_base_packages, но на всякий случай)
    if ! command -v ufw >/dev/null 2>&1; then
        log_info "UFW не установлен. Устанавливаю..."
        export DEBIAN_FRONTEND=noninteractive
        if ! apt-get install -y ufw; then
            log_error "Не удалось установить ufw."
            exit 1
        fi
        log_ok "UFW установлен"
    fi

    # Отключаем UFW перед перенастройкой (если уже включён)
    if ufw status | grep -q "Status: active"; then
        log_info "UFW уже активен. Временно отключаю для перенастройки..."
        echo "y" | ufw disable >/dev/null 2>&1 || true
    fi

    # Правила по умолчанию
    log_info "Настраиваю правила по умолчанию: deny incoming, allow outgoing..."
    ufw default deny incoming
    ufw default allow outgoing
    log_ok "Правила по умолчанию настроены"

    # Разрешаем SSH-порт
    log_info "Разрешаю SSH-подключения на порт ${ENGINE_SSH_PORT}/tcp..."
    ufw allow "${ENGINE_SSH_PORT}"/tcp
    log_ok "SSH-порт ${ENGINE_SSH_PORT}/tcp разрешён"

    # Ограничиваем SSH (защита от brute-force)
    log_info "Включаю лимит попыток подключения к SSH (ufw limit)..."
    ufw limit "${ENGINE_SSH_PORT}"/tcp
    log_ok "Лимит попыток SSH включён"

    # Включаем UFW
    log_info "Включаю UFW..."
    echo "y" | ufw enable >/dev/null 2>&1
    log_ok "UFW включён"

    echo
    log_info "Текущий статус UFW:"
    ufw status verbose
}

############################################
# ================ FAIL2BAN ===============
############################################

setup_fail2ban() {
    view_banner "Настройка Fail2Ban"

    if [[ -z "${ENGINE_SSH_PORT}" ]]; then
        log_error "ENGINE_SSH_PORT не задан. Fail2Ban не может быть настроен."
        exit 1
    fi

    # Проверяем наличие пакета
    if ! command -v fail2ban-client >/dev/null 2>&1; then
        log_info "Fail2Ban не установлен. Устанавливаю..."
        export DEBIAN_FRONTEND=noninteractive
        if ! apt-get install -y fail2ban; then
            log_error "Не удалось установить Fail2Ban."
            exit 1
        fi
        log_ok "Fail2Ban установлен"
    else
        log_ok "Fail2Ban уже установлен"
    fi

    # Создаём наш локальный jail
    local jail_file="/etc/fail2ban/jail.d/hardening-ssh.local"

    log_info "Создаю jail-файл для SSH: ${jail_file}"

    cat > "$jail_file" <<EOF
[sshd]
enabled = true
port = ${ENGINE_SSH_PORT}
filter = sshd
logpath = /var/log/auth.log
backend = systemd

maxretry = 5          # 5 попыток
findtime = 10m        # в течение 10 минут
bantime = 1h          # бан на 1 час
EOF

    if [[ $? -ne 0 ]]; then
        log_error "Не удалось создать файл Fail2Ban: ${jail_file}"
        exit 1
    fi

    log_ok "Конфигурация Fail2Ban для SSH создана"

    # Включаем Fail2Ban в автозагрузку
    systemctl enable fail2ban >/dev/null 2>&1 || true

    # Перезапуск Fail2Ban
    log_info "Перезапуск Fail2Ban..."
    if ! systemctl restart fail2ban; then
        log_error "Не удалось перезапустить Fail2Ban."
        exit 1
    fi

    log_ok "Fail2Ban успешно перезапущен"

    # Показываем статус
    echo
    log_info "Статус fail2ban-client для sshd:"
    fail2ban-client status sshd || log_warn "Не удалось получить статус jail-а sshd"
}

############################################
# ========= PASSWORD POLICY (PAM) =========
############################################

setup_password_policy() {
    view_banner "Политика паролей и блокировка аккаунтов"

    local PWQUALITY_CONF="/etc/security/pwquality.conf"
    local LOGIN_DEFS="/etc/login.defs"
    local PAM_COMMON_PASSWORD="/etc/pam.d/common-password"
    local PAM_COMMON_AUTH="/etc/pam.d/common-auth"
    local PAM_COMMON_ACCOUNT="/etc/pam.d/common-account"

    # --- 1. Настройка /etc/security/pwquality.conf ---
    log_info "Настраиваю /etc/security/pwquality.conf..."

    cat > "$PWQUALITY_CONF" <<EOF
# Настройки политики сложности паролей
minlen = 12
dcredit = -1    # минимум одна цифра
ucredit = -1    # минимум одна заглавная буква
lcredit = -1    # минимум одна строчная буква
ocredit = -1    # минимум один спецсимвол
retry = 3
EOF

    if [[ $? -ne 0 ]]; then
        log_error "Не удалось записать ${PWQUALITY_CONF}"
        exit 1
    fi
    log_ok "Файл ${PWQUALITY_CONF} настроен"

    # --- 2. Настройка /etc/login.defs ---
    log_info "Настраиваю сроки действия паролей в ${LOGIN_DEFS}..."

    if [[ -f "$LOGIN_DEFS" ]]; then
        sed -i 's/^[#[:space:]]*PASS_MAX_DAYS.*/PASS_MAX_DAYS   60/' "$LOGIN_DEFS"
        sed -i 's/^[#[:space:]]*PASS_MIN_DAYS.*/PASS_MIN_DAYS   1/' "$LOGIN_DEFS"
        sed -i 's/^[#[:space:]]*PASS_WARN_AGE.*/PASS_WARN_AGE   7/' "$LOGIN_DEFS"
        log_ok "PASS_MAX_DAYS=60, PASS_MIN_DAYS=1, PASS_WARN_AGE=7 настроены"
    else
        log_warn "${LOGIN_DEFS} не найден, пропускаю настройку."
    fi

    # --- 3. Настройка common-password (pwquality + remember) ---
    if [[ -f "$PAM_COMMON_PASSWORD" ]]; then
        log_info "Настраиваю PAM-модуль сложности паролей и remember в ${PAM_COMMON_PASSWORD}..."

        # 3.1. Настраиваем строку с pam_pwquality.so (или добавляем, если её нет)
        if grep -q "pam_pwquality.so" "$PAM_COMMON_PASSWORD"; then
            # Заменяем существующую строку нашей жёсткой политикой
            sed -i 's#^password\s\+requisite\s\+pam_pwquality.so.*#password requisite pam_pwquality.so retry=3 minlen=12 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1#g' "$PAM_COMMON_PASSWORD"
        else
            # Вставляем строку перед pam_unix.so, если найдём
            if grep -q "pam_unix.so" "$PAM_COMMON_PASSWORD"; then
                sed -i 's#^\(password\s\+.*pam_unix.so.*\)#password requisite pam_pwquality.so retry=3 minlen=12 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1\n\1#' "$PAM_COMMON_PASSWORD"
            else
                # Если вообще всё странно — просто добавим в конец
                cat >>"$PAM_COMMON_PASSWORD" <<'EOF'
password requisite pam_pwquality.so retry=3 minlen=12 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1
EOF
            fi
        fi

        # 3.2. Добавляем remember=3 к pam_unix.so, если ещё нет
        if grep -q "pam_unix.so" "$PAM_COMMON_PASSWORD"; then
            if ! grep -q "pam_unix.so.*remember=" "$PAM_COMMON_PASSWORD"; then
                sed -i 's/\(pam_unix.so.*\)$/\1 remember=3/' "$PAM_COMMON_PASSWORD"
                log_ok "Добавлен remember=3 к pam_unix.so"
            else
                log_ok "remember= уже настроен для pam_unix.so, оставляю как есть"
            fi
        else
            log_warn "pam_unix.so не найден в ${PAM_COMMON_PASSWORD}, пропускаю remember=3."
        fi
    else
        log_warn "${PAM_COMMON_PASSWORD} не найден, пропускаю настройку политики паролей в PAM."
    fi

    # --- 4. Блокировка аккаунтов при неудачных попытках (pam_tally2) ---
    log_info "Настройка блокировки аккаунтов при неудачных попытках входа..."

    if [[ -f "$PAM_COMMON_AUTH" ]] && [[ -f "$PAM_COMMON_ACCOUNT" ]]; then
        if grep -q "pam_tally2.so" /etc/pam.d/* 2>/dev/null; then
            # Добавляем строку в common-auth, если ещё нет
            if ! grep -q "pam_tally2.so" "$PAM_COMMON_AUTH"; then
                cat <<'EOF' >>"$PAM_COMMON_AUTH"

# Блокировка аккаунта после 5 неудачных попыток на 15 минут
auth required pam_tally2.so onerr=fail deny=5 unlock_time=900
EOF
                log_ok "Добавлена строка pam_tally2.so в ${PAM_COMMON_AUTH}"
            else
                log_ok "pam_tally2 уже используется в ${PAM_COMMON_AUTH}, оставляю как есть"
            fi

            # В common-account должна быть строка account required pam_tally2.so
            if ! grep -q "pam_tally2.so" "$PAM_COMMON_ACCOUNT"; then
                cat <<'EOF' >>"$PAM_COMMON_ACCOUNT"

# Учёт попыток аутентификации
account required pam_tally2.so
EOF
                log_ok "Добавлена строка pam_tally2.so в ${PAM_COMMON_ACCOUNT}"
            else
                log_ok "pam_tally2 уже используется в ${PAM_COMMON_ACCOUNT}, оставляю как есть"
            fi
        else
            log_warn "Модуль pam_tally2.so не найден в системе. Блокировка по количеству попыток не настраивается."
        fi
    else
        log_warn "Файлы ${PAM_COMMON_AUTH} или ${PAM_COMMON_ACCOUNT} не найдены, блокировка аккаунтов по PAM не настраивается."
    fi

    log_ok "Политика паролей и базовая блокировка аккаунтов настроены"
}

############################################
# ================ APPARMOR ===============
############################################

setup_apparmor() {
    view_banner "Проверка и настройка AppArmor"

    # 1. Проверяем наличие пакетов
    if ! dpkg -s apparmor >/dev/null 2>&1 || ! dpkg -s apparmor-utils >/dev/null 2>&1; then
        log_info "AppArmor не полностью установлен. Устанавливаю пакеты apparmor и apparmor-utils..."
        export DEBIAN_FRONTEND=noninteractive
        if ! apt-get install -y apparmor apparmor-utils; then
            log_warn "Не удалось установить AppArmor-пакеты. Продолжаю без AppArmor."
            return
        fi
        log_ok "Пакеты AppArmor установлены"
    else
        log_ok "AppArmor и apparmor-utils уже установлены"
    fi

    # 2. Включаем службу AppArmor
    log_info "Включаю и запускаю службу AppArmor..."
    systemctl enable apparmor >/dev/null 2>&1 || true
    if ! systemctl start apparmor >/dev/null 2>&1; then
        log_warn "Не удалось запустить службу AppArmor. Возможно, ядро собрано без поддержки."
        return
    fi
    log_ok "Служба AppArmor запущена"

    # 3. Проверяем статус
    echo
    log_info "Текущий статус AppArmor:"
    if command -v aa-status >/dev/null 2>&1; then
        aa-status || log_warn "aa-status вернул ошибку, проверьте AppArmor вручную."
    else
        log_warn "Утилита aa-status не найдена, невозможно показать детальный статус профилей."
    fi

    echo
    log_info "Важно: в этом скрипте не создаются кастомные профили."
    log_info "Используются только стандартные профили AppArmor, поставляемые с системой."
}

############################################
# =============== HARDENING ===============
############################################

harden_sysctl_and_services() {
    view_banner "Системное ужесточение (sysctl и сервисы)"

    # --- 1. Настройки ядра (sysctl) ---
    local SYSCTL_CONF="/etc/sysctl.d/99-vps-hardening.conf"

    log_info "Записываю безопасные параметры ядра в ${SYSCTL_CONF}..."

    cat > "$SYSCTL_CONF" <<'EOF'
# ===== VPS Hardening: базовые сетевые настройки безопасности =====

# Отключение маршрутизации между интерфейсами
net.ipv4.ip_forward = 0

# Отключение приёма ICMP redirect-пакетов
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0

# Отключение source routing
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0

# Включение reverse path filtering (защита от spoofing)
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# Включение TCP SYN cookies (защита от SYN-flood)
net.ipv4.tcp_syncookies = 1

# Запрет приёма маршрутов через ICMP redirect для IPv6 (на будущее)
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
EOF

    if [[ $? -ne 0 ]]; then
        log_error "Не удалось записать ${SYSCTL_CONF}"
        exit 1
    fi

    log_ok "Файл ${SYSCTL_CONF} создан"

    log_info "Применяю настройки sysctl (sysctl --system)..."
    if sysctl --system >/dev/null 2>&1; then
        log_ok "Настройки sysctl успешно применены"
    else
        log_warn "sysctl --system вернул ошибку. Проверьте ${SYSCTL_CONF} вручную."
    fi

    # --- 2. Отключение лишних сервисов ---
    log_info "Проверяю и отключаю ненужные сервисы (если установлены)..."

    # Список сервисов-кандидатов на отключение
    local SERVICES_TO_DISABLE=(
        avahi-daemon   # автообнаружение в локальной сети
        cups           # печать
        bluetooth      # BT-демон
        rpcbind        # RPC-сервисы
        nfs-server     # NFS-сервер
        telnet         # устаревший небезопасный протокол
        vsftpd         # FTP-сервер
        ftp            # FTP-сервер (общее имя сервиса)
    )

    for svc in "${SERVICES_TO_DISABLE[@]}"; do
        if systemctl list-unit-files | grep -q "^${svc}.service"; then
            # Если сервис активен — останавливаем
            if systemctl is-active --quiet "$svc"; then
                log_info "Останавливаю сервис ${svc}..."
                systemctl stop "$svc" >/dev/null 2>&1 || log_warn "Не удалось остановить ${svc}"
            fi

            # Если включён в автозагрузке — отключаем
            if systemctl is-enabled --quiet "$svc"; then
                log_info "Отключаю автозапуск ${svc}..."
                systemctl disable "$svc" >/dev/null 2>&1 || log_warn "Не удалось отключить автозапуск ${svc}"
            fi

            log_ok "Сервис ${svc} (если был) отключён"
        fi
    done

    log_ok "Базовое системное ужесточение выполнено"
}

############################################
# ================= AUDITD =================
############################################

setup_auditd() {
    view_banner "Настройка системы аудита (auditd)"

    # --- Установка auditd ---
    if ! command -v auditctl >/dev/null 2>&1; then
        log_info "Устанавливаю auditd..."
        export DEBIAN_FRONTEND=noninteractive
        if ! apt-get install -y auditd audispd-plugins >/dev/null 2>&1; then
            log_error "Не удалось установить auditd"
            exit 1
        fi
        log_ok "auditd установлен"
    else
        log_ok "auditd уже установлен"
    fi

    # --- Включение в автозагрузку ---
    systemctl enable auditd >/dev/null 2>&1
    systemctl start auditd >/dev/null 2>&1

    # --- Настройка правил ---
    local AUDIT_RULES="/etc/audit/rules.d/hardening.rules"
    log_info "Создание правил аудита в ${AUDIT_RULES}"

    cat > "$AUDIT_RULES" <<'EOF'
# ===== Аудит критичных файлов =====
-w /etc/passwd -p wa -k passwd_changes
-w /etc/shadow -p wa -k shadow_changes

# ===== Аудит sudo =====
-w /usr/bin/sudo -p x -k sudo_usage
-w /etc/sudoers -p wa -k sudoers_changes
-w /etc/sudoers.d/ -p wa -k sudoers_changes

# ===== Аудит системных входов =====
-w /var/log/auth.log -p wa -k auth_log

# ===== Аудит запуска команд =====
-a always,exit -F arch=b64 -S execve -k exec_monitor
-a always,exit -F arch=b32 -S execve -k exec_monitor
EOF

    if [[ $? -ne 0 ]]; then
        log_error "Не удалось записать файл правил для auditd"
        exit 1
    fi

    # --- Перезапуск ---
    log_info "Перезапуск auditd..."
    systemctl restart auditd >/dev/null 2>&1

    # --- Проверка ---
    if auditctl -l >/dev/null 2>&1; then
        log_ok "auditd работает и правила активны"
    else
        log_warn "auditd запущен, но правила не активны — проверьте вручную"
    fi

    log_ok "Система аудита настроена"
}

############################################
# ============== FINAL REPORT =============
############################################

final_report() {
    view_banner "Установка завершена"

    echo -e "${VIEW_GREEN}${VIEW_BOLD}Все основные шаги безопасности выполнены успешно!${VIEW_RESET}"
    echo

    echo -e "${VIEW_CYAN}Итоговая конфигурация:${VIEW_RESET}"
    echo "----------------------------------------"

    if [[ -n "$ENGINE_USER" ]]; then
        echo -e "  • Создан пользователь: ${VIEW_GREEN}${ENGINE_USER}${VIEW_RESET}"
    else
        echo -e "  • Пользователь: ${VIEW_RED}не установлен${VIEW_RESET}"
    fi

    if [[ -n "$ENGINE_SSH_PORT" ]]; then
        echo -e "  • SSH-порт: ${VIEW_GREEN}${ENGINE_SSH_PORT}${VIEW_RESET}"
        echo "    Подключение: ssh -p ${ENGINE_SSH_PORT} ${ENGINE_USER}@<server_ip>"
    else
        echo -e "  • SSH-порт: ${VIEW_RED}не установлен${VIEW_RESET}"
    fi

    echo

    echo -e "${VIEW_CYAN}Состояние служб:${VIEW_RESET}"
    echo "----------------------------------------"

    # UFW status
    if command -v ufw >/dev/null 2>&1; then
        local ufw_state
        ufw_state=$(ufw status | head -n 1)
        echo -e "  • UFW: ${VIEW_GREEN}${ufw_state}${VIEW_RESET}"
    else
        echo -e "  • UFW: ${VIEW_RED}не установлен${VIEW_RESET}"
    fi

    # auditd status
    if systemctl is-active --quiet auditd; then
        echo -e "  • auditd: ${VIEW_GREEN}active${VIEW_RESET}"
    else
        echo -e "  • auditd: ${VIEW_RED}inactive${VIEW_RESET}"
    fi

    echo

    # Recommendations
    echo -e "${VIEW_CYAN}Рекомендации после установки:${VIEW_RESET}"
    echo "----------------------------------------"
    echo -e "  • Смените пароль нового пользователя"
    echo -e "  • Настройте SSH-ключи (рекомендуется)"
    echo -e "  • Сделайте снимок сервера/бэкап важного"
    echo -e "  • Перезагрузите систему для полной активации всех настроек"

    echo
    echo -e "${VIEW_YELLOW}Чтобы перезагрузить систему:${VIEW_RESET}"
    echo "  sudo reboot"
    echo

    echo -e "${VIEW_GREEN}${VIEW_BOLD}Сервер успешно подготовлен и защищён!${VIEW_RESET}"
    echo
}

############################################
# ================= MAIN ===================
############################################

main() {
    # 1. Сначала проверяем, что мы root
    check_root

    # 2. Логирование и красивый логотип
    setup_logging
    view_logo

    # 3. Проверки окружения
    check_ubuntu
    check_basic_tools

    # 4. Обновление системы и базовые пакеты
    update_system
    install_base_packages
    setup_auto_updates

    # 5. Пользователь
    create_engine_user

    # 6. SSH (сервер + порт + харднинг)
    ensure_ssh_server
    choose_ssh_port
    harden_ssh_config

    # 7. Firewall (UFW) для нового SSH-порта
    setup_ufw

    # 8. Fail2Ban
    setup_fail2ban

    # 9. Политика паролей (PAM)
    setup_password_policy

    # 10. AppArmor
    setup_apparmor

    # 11. Системное ужесточение (sysctl + сервисы)
    harden_sysctl_and_services

    # 12. Аудит (auditd)
    setup_auditd

    # 13. Финальный отчёт
    final_report
}

# Точка входа
main "$@"