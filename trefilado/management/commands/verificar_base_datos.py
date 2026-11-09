import re

from django.core.exceptions import ImproperlyConfigured
from django.core.management.base import BaseCommand, CommandError
from django.db import DatabaseError, connection
from django.db.models import Count

from trefilado.models import MetricaCaptura, Usuario


def _identificar_proyecto(config):
    host = (config.get("HOST") or "").lower()
    rol, _, referencia = (config.get("USER") or "").rpartition(".")
    if host.endswith(".pooler.supabase.com") and rol and re.fullmatch(r"[a-z0-9]{20}", referencia):
        return referencia
    return "no identificable"


class Command(BaseCommand):
    help = "Comprueba la conexión PostgreSQL al esquema aza y muestra sus totales sin credenciales."

    def handle(self, *args, **options):
        self.stdout.write(f"Motor: {connection.vendor}")
        if connection.vendor != "postgresql":
            self.stdout.write("Esquema: no aplica")
            raise CommandError("AZA requiere PostgreSQL y el esquema aza para compartir datos.")

        try:
            with connection.cursor() as cursor:
                cursor.execute("SELECT pg_catalog.current_schema(), pg_catalog.current_schemas(false)::text[]")
                esquema, ruta = cursor.fetchone()
        except (DatabaseError, ImproperlyConfigured):
            raise CommandError("No se pudo verificar la conexión PostgreSQL al esquema aza.") from None

        self.stdout.write(f"Esquema: {esquema or 'no disponible'}")
        if esquema != "aza" or ruta != ["aza"]:
            raise CommandError("La sesión PostgreSQL debe usar únicamente el esquema aza.")
        self.stdout.write(f"Proyecto Supabase: {_identificar_proyecto(connection.settings_dict)}")

        try:
            metricas = MetricaCaptura.objects.aggregate(total=Count("pk"), con_angulo=Count("exit_angle_deg"))
            usuarios = Usuario.objects.count()
        except DatabaseError:
            raise CommandError("No se pudieron consultar los totales del esquema aza. Verifique las migraciones y los permisos.") from None

        self.stdout.write(f"Capturas: {metricas['total']} ({metricas['con_angulo']} con ángulo)")
        self.stdout.write(f"Usuarios: {usuarios}")
