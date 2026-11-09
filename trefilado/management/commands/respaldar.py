"""Ejecuta un respaldo de la base de datos (para programar con cron / Programador de tareas)."""
from django.conf import settings
from django.core.management.base import BaseCommand, CommandError

from trefilado.services import ejecutar_respaldo, registrar_auditoria


class Command(BaseCommand):
    help = "Genera un respaldo de la base de datos y lo registra en el historial."

    def handle(self, *args, **opciones):
        if settings.DATABASES["default"]["ENGINE"] != "django.db.backends.sqlite3":
            raise CommandError("Este comando respalda SQLite; administre los respaldos PostgreSQL desde Supabase.")
        r = ejecutar_respaldo()
        registrar_auditoria(None, "RESPALDO_AUTOMATICO", f"Resultado: {r.get_resultado_display()}")
        self.stdout.write(f"Respaldo {r.get_resultado_display().lower()}: {r.archivo or r.detalle}")
