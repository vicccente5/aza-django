import os
import sys
from pathlib import Path
from urllib.parse import urlsplit

from django.core.exceptions import ImproperlyConfigured
from django.db import DatabaseError
from django.db.backends.signals import connection_created
from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent.parent
# El comando de pruebas usa una base efímera, independientemente de la URL de ejecución.
en_pruebas = sys.argv[1:2] == ["test"]
if not en_pruebas:
    load_dotenv(BASE_DIR / ".env")

DEBUG = en_pruebas or os.environ.get("DEBUG", "1") == "1"
clave_secreta = os.environ.get("SECRET_KEY")
# Admite secretos aleatorios de 32 bytes codificados en Base64, como los de Render.
if not DEBUG and (
    not clave_secreta
    or len(clave_secreta) < 43
    or len(set(clave_secreta)) < 12
    or clave_secreta.startswith("django-insecure-")
    or any(caracter.isspace() for caracter in clave_secreta)
):
    raise ImproperlyConfigured("Configure SECRET_KEY con una clave aleatoria de al menos 43 caracteres y sin espacios.")
SECRET_KEY = clave_secreta if clave_secreta is not None else "aza-clave-local-cambiar-en-produccion"


def _origen_publico(valor, variable):
    try:
        url = urlsplit(valor)
        puerto = url.port
    except ValueError:
        raise ImproperlyConfigured(f"{variable} debe contener un origen válido.") from None
    esquemas = ("http", "https") if DEBUG else ("https",)
    if (
        url.scheme not in esquemas
        or not url.hostname
        or url.username is not None
        or url.path not in ("", "/")
        or url.query
        or url.fragment
    ):
        raise ImproperlyConfigured(f"{variable} debe contener un origen web sin ruta. En producción requiere HTTPS.")
    host = f"[{url.hostname}]" if ":" in url.hostname else url.hostname
    autoridad = f"{host}:{puerto}" if puerto is not None else host
    return f"{url.scheme}://{autoridad}", host


ALLOWED_HOSTS = [host.strip() for host in os.environ.get("ALLOWED_HOSTS", "").split(",") if host.strip()]
if DEBUG:
    ALLOWED_HOSTS.extend(("localhost", "127.0.0.1", "[::1]"))
CSRF_TRUSTED_ORIGINS = []
PUBLIC_BASE_URL = ""
for variable in ("RENDER_EXTERNAL_URL", "PUBLIC_BASE_URL"):
    valor = os.environ.get(variable, "").strip()
    if valor:
        PUBLIC_BASE_URL, host = _origen_publico(valor, variable)
        if host not in ALLOWED_HOSTS:
            ALLOWED_HOSTS.append(host)
        if PUBLIC_BASE_URL not in CSRF_TRUSTED_ORIGINS:
            CSRF_TRUSTED_ORIGINS.append(PUBLIC_BASE_URL)

# Solo en desarrollo local se muestra el OTP o enlace de recuperación en pantalla.
MOSTRAR_CODIGOS_EN_PANTALLA = DEBUG

INSTALLED_APPS = [
    "django.contrib.contenttypes",
    "django.contrib.auth",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "trefilado",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

ROOT_URLCONF = "aza_project.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

WSGI_APPLICATION = "aza_project.wsgi.application"

def _postgres_database(database_url, schema):
    from psycopg import ProgrammingError
    from psycopg.conninfo import conninfo_to_dict

    if schema != "aza":
        raise ImproperlyConfigured("La conexión de AZA requiere DB_SCHEMA=aza.")

    mensaje = "DATABASE_URL debe ser una URL PostgreSQL completa con usuario, contraseña, host y base de datos."
    if not database_url.startswith(("postgres://", "postgresql://")):
        raise ImproperlyConfigured(mensaje)
    try:
        params = conninfo_to_dict(database_url)
    except (ProgrammingError, ValueError):
        raise ImproperlyConfigured(mensaje) from None

    if not all(params.get(clave) for clave in ("host", "user", "password", "dbname")):
        raise ImproperlyConfigured(mensaje)
    if params["password"] == "[YOUR-PASSWORD]":
        raise ImproperlyConfigured("Reemplace [YOUR-PASSWORD] por la contraseña real en DATABASE_URL.")
    if params["host"].startswith("/") or "," in params["host"] or params.get("port", "5432") != "5432":
        raise ImproperlyConfigured("Use un único host PostgreSQL y el puerto 5432 del Session pooler.")

    return {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": params["dbname"],
        "USER": params["user"],
        "PASSWORD": params["password"],
        "HOST": params["host"],
        "PORT": 5432,
        "CONN_MAX_AGE": 60,
        "CONN_HEALTH_CHECKS": True,
        "OPTIONS": {"sslmode": "require", "connect_timeout": 10},
    }


def _aislar_esquema_postgresql(sender, connection, **kwargs):
    if connection.alias != "default" or connection.vendor != "postgresql":
        return

    # Session pooler conserva esta configuración durante la vida de la conexión.
    try:
        with connection.cursor() as cursor:
            cursor.execute("SET search_path TO aza")
            cursor.execute("SELECT pg_catalog.current_schema()")
            if cursor.fetchone() != ("aza",):
                raise ImproperlyConfigured("El esquema aza no existe o el usuario no tiene permiso USAGE.")
    except (DatabaseError, ImproperlyConfigured):
        connection.close()
        raise


database_url = os.environ.get("DATABASE_URL", "")
if en_pruebas or os.environ.get("AZA_SQLITE_LOCAL") == "1":
    if not en_pruebas and database_url:
        raise ImproperlyConfigured(
            "AZA_SQLITE_LOCAL=1 y DATABASE_URL no pueden configurarse a la vez. "
            "Quite AZA_SQLITE_LOCAL para usar PostgreSQL o deje DATABASE_URL vacía para usar SQLite."
        )
    if not DEBUG:
        raise ImproperlyConfigured("AZA_SQLITE_LOCAL solo se permite con DEBUG=1.")
    DATABASES = {
        "default": {
            "ENGINE": "django.db.backends.sqlite3",
            "NAME": ":memory:" if en_pruebas else BASE_DIR / "db.sqlite3",
        }
    }
else:
    if not database_url:
        raise ImproperlyConfigured(
            "Configure DATABASE_URL con el Session pooler de Supabase. "
            "Para desarrollo local aislado, use DEBUG=1 y AZA_SQLITE_LOCAL=1."
        )
    DATABASES = {"default": _postgres_database(database_url, os.environ.get("DB_SCHEMA", "aza"))}
    connection_created.connect(_aislar_esquema_postgresql, dispatch_uid="aza.search_path")

TEST_RUNNER = "aza_project.test_runner.SQLiteTestRunner"

AUTH_USER_MODEL = "trefilado.Usuario"
LOGIN_URL = "login"

LANGUAGE_CODE = "es-cl"
TIME_ZONE = "America/Santiago"
USE_I18N = True
USE_TZ = True

STATIC_URL = "static/"
STATIC_ROOT = BASE_DIR / "staticfiles"
try:  # archivos estáticos en la nube (se usa solo si whitenoise está instalado)
    import whitenoise  # noqa: F401
    MIDDLEWARE.insert(1, "whitenoise.middleware.WhiteNoiseMiddleware")
    STORAGES = {
        "default": {"BACKEND": "django.core.files.storage.FileSystemStorage"},
        "staticfiles": {"BACKEND": "whitenoise.storage.CompressedStaticFilesStorage"},
    }
except ImportError:
    pass
if not DEBUG:
    SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")
    SESSION_COOKIE_SECURE = True
    CSRF_COOKIE_SECURE = True
MEDIA_ROOT = BASE_DIR / "media"

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

if DEBUG:
    EMAIL_BACKEND = "django.core.mail.backends.console.EmailBackend"
else:
    EMAIL_BACKEND = "django.core.mail.backends.smtp.EmailBackend"
    EMAIL_HOST = os.environ.get("EMAIL_HOST", "")
    EMAIL_HOST_USER = os.environ.get("EMAIL_HOST_USER", "")
    EMAIL_HOST_PASSWORD = os.environ.get("EMAIL_HOST_PASSWORD", "")
    DEFAULT_FROM_EMAIL = os.environ.get("DEFAULT_FROM_EMAIL", "")
    if not all(valor.strip() for valor in (EMAIL_HOST, EMAIL_HOST_USER, EMAIL_HOST_PASSWORD, DEFAULT_FROM_EMAIL)):
        raise ImproperlyConfigured("Configure EMAIL_HOST, EMAIL_HOST_USER, EMAIL_HOST_PASSWORD y DEFAULT_FROM_EMAIL.")
    try:
        EMAIL_PORT = int(os.environ.get("EMAIL_PORT", "587"))
    except ValueError:
        raise ImproperlyConfigured("EMAIL_PORT debe ser un puerto SMTP válido.") from None
    if not 1 <= EMAIL_PORT <= 65535:
        raise ImproperlyConfigured("EMAIL_PORT debe ser un puerto SMTP válido.")
    EMAIL_USE_TLS = True
    EMAIL_TIMEOUT = 10

# Sin token configurado, la API de captura queda deshabilitada.
API_TOKEN_CAPTURA = os.environ.get("API_TOKEN_CAPTURA", "")
