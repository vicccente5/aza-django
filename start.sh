#!/usr/bin/env bash
set -euo pipefail
: "${DATABASE_URL:?Configure DATABASE_URL con la cadena Session pooler de Supabase}"
python manage.py migrate --noinput
exec gunicorn aza_project.wsgi:application --bind "0.0.0.0:${PORT:-8000}" --workers 2
