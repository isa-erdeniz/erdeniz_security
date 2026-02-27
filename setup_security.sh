#!/bin/bash
# ErdenizTech — Tüm Projelere Güvenlik Kurulumu (tek katman: erdeniz_security)
set -e
ROOT="${ERDENIZTECH_ROOT:-/home/isa/erdeniztech}"
SECURITY="${ROOT}/erdeniz_security"

PROJECTS=(
    "looopone_dashboard"
    "worktrackere"
    "garment_core"
    "gyminfinitye_saas"
    "mehlr_1.0"
)

echo "═══════════════════════════════════════════"
echo "  ErdenizTech Security Setup — Tek Katman"
echo "  Root: $ROOT"
echo "  Not: GitHub yüklemek için Gitingiroe gerekir."
echo "═══════════════════════════════════════════"

pip install -e "$SECURITY" -q 2>/dev/null || true

for project in "${PROJECTS[@]}"; do
    dir="${ROOT}/${project}"
    if [ ! -f "$dir/manage.py" ]; then
        echo "▶ [$project] manage.py yok — atlanıyor"
        continue
    fi
    echo ""
    echo "▶ [$project] Kuruluyor..."
    (cd "$dir" && pip install -e "$SECURITY" -q 2>/dev/null || true)
    (cd "$dir" && pip install cryptography argon2-cffi django-encrypted-model-fields python-decouple -q 2>/dev/null || true)
    (cd "$dir" && python manage.py generate_key --type fernet 2>/dev/null | head -1) || true
    (cd "$dir" && python manage.py generate_key --type field 2>/dev/null | head -1) || true
    (cd "$dir" && python manage.py makemigrations erdeniz_security 2>/dev/null || true)
    (cd "$dir" && python manage.py migrate 2>/dev/null || true)
    (cd "$dir" && python manage.py security_check 2>/dev/null || true)
    echo "✓ [$project] Tamamlandı"
done

echo ""
echo "═══════════════════════════════════════════"
echo "  INSTALLED_APPS'a 'erdeniz_security' ve 'axes' ekleyin."
echo "  get_django_security_settings() ile ayarları yükleyin."
echo "═══════════════════════════════════════════"
