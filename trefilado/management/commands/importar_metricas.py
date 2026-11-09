"""Importa las capturas originales de METRICAS_CONSOLIDADAS."""

import json
import math
import re
from datetime import datetime
from pathlib import Path
from zipfile import BadZipFile, ZipFile

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError
from django.db import transaction
from django.utils import timezone

from trefilado.models import MetricaCaptura


NOMBRE_ARCHIVO = re.compile(
    r"(?P<fecha>\d{4}-\d{2}-\d{2})_Trigger_(?P<trigger>\d+)_(?P<momento>\d{8}_\d{6})_metricas\.json"
)
TAMANO_LOTE = 500


def _archivos(origen):
    if origen.is_dir():
        for archivo in sorted(origen.glob("*.json")):
            yield archivo.name, archivo.read_bytes()
    elif origen.is_file() and origen.suffix.lower() == ".zip":
        with ZipFile(origen) as paquete:
            for entrada in sorted(paquete.namelist()):
                if entrada.lower().endswith(".json"):
                    yield Path(entrada).name, paquete.read(entrada)
    else:
        raise CommandError(f"No existe una carpeta JSON o archivo ZIP válido: {origen}")


def _entero(datos, clave, nullable=False):
    valor = datos.get(clave)
    if valor is None and nullable:
        return None
    if isinstance(valor, bool) or not isinstance(valor, int) or valor < 0:
        raise ValueError(f"{clave} debe ser un entero no negativo")
    return valor


def _numero(datos, clave, nullable=False):
    valor = datos.get(clave)
    if valor is None and nullable:
        return None
    if isinstance(valor, bool) or not isinstance(valor, (int, float)) or not math.isfinite(valor):
        raise ValueError(f"{clave} debe ser un número finito")
    return float(valor)


def _texto(datos, clave, maximo=None, nullable=False):
    valor = datos.get(clave)
    if valor is None and nullable:
        return ""
    if not isinstance(valor, str) or (maximo and len(valor) > maximo):
        raise ValueError(f"{clave} debe ser texto válido")
    return valor


def _normalizar(nombre, contenido):
    coincidencia = NOMBRE_ARCHIVO.fullmatch(nombre)
    if not coincidencia:
        raise ValueError("nombre de archivo inesperado")
    datos = json.loads(contenido.decode("utf-8"))
    if not isinstance(datos, dict):
        raise ValueError("el JSON debe contener un objeto")
    momento = datetime.strptime(coincidencia["momento"], "%Y%m%d_%H%M%S")
    if momento.date().isoformat() != coincidencia["fecha"]:
        raise ValueError("la fecha del archivo no coincide con su marca de tiempo")
    return {
        "archivo_origen": nombre,
        "trigger": coincidencia["trigger"],
        "fecha_hora": timezone.make_aware(momento),
        "total_frames": _entero(datos, "total_frames"),
        "scene": _texto(datos, "scene", 30),
        "mean_background": _numero(datos, "mean_background"),
        "first_exit_frame": _entero(datos, "first_exit_frame", nullable=True),
        "exit_confidence": _texto(datos, "exit_confidence", 40),
        "circle_cx": _numero(datos, "circle_cx", nullable=True),
        "circle_cy": _numero(datos, "circle_cy", nullable=True),
        "circle_radius": _numero(datos, "circle_radius", nullable=True),
        "circle_method": _texto(datos, "circle_method", 60, nullable=True),
        "circle_support_frames": _entero(datos, "circle_support_frames"),
        "angle_frame": _entero(datos, "angle_frame", nullable=True),
        "exit_angle_deg": _numero(datos, "exit_angle_deg", nullable=True),
        "angle_confidence": _texto(datos, "angle_confidence", 40),
        "diagnostic_path": _texto(datos, "diagnostic_path"),
    }


class Command(BaseCommand):
    help = (
        "Importa los JSON reales desde METRICAS_CONSOLIDADAS o su ZIP, sin duplicar capturas. "
        "Los conteos de nuevas y actualizadas son aproximados si se ejecutan importaciones concurrentes."
    )

    def add_arguments(self, parser):
        parser.add_argument("--source", type=Path, help="Carpeta con JSON o archivo ZIP de origen.")

    def handle(self, *args, **options):
        carpeta = Path(settings.BASE_DIR) / "METRICAS_CONSOLIDADAS" / "METRICAS_CONSOLIDADAS"
        origen = options["source"] or (carpeta if carpeta.is_dir() else Path(settings.BASE_DIR) / "METRICAS_CONSOLIDADAS.zip")
        filas = []
        nombres = set()
        try:
            for nombre, contenido in _archivos(origen):
                if nombre in nombres:
                    raise ValueError(f"archivo duplicado: {nombre}")
                nombres.add(nombre)
                try:
                    filas.append(_normalizar(nombre, contenido))
                except (ValueError, TypeError, KeyError, UnicodeDecodeError, json.JSONDecodeError) as exc:
                    raise ValueError(f"{nombre}: {exc}") from exc
        except (OSError, BadZipFile, ValueError) as exc:
            raise CommandError(str(exc)) from exc
        if not filas:
            raise CommandError(f"No se encontraron JSON en {origen}")

        filas.sort(key=lambda fila: fila["archivo_origen"])
        campos_actualizables = [campo for campo in filas[0] if campo != "archivo_origen"]
        actualizadas = 0
        with transaction.atomic():
            for inicio in range(0, len(filas), TAMANO_LOTE):
                lote = filas[inicio:inicio + TAMANO_LOTE]
                archivos = [fila["archivo_origen"] for fila in lote]
                actualizadas += MetricaCaptura.objects.filter(archivo_origen__in=archivos).count()
                MetricaCaptura.objects.bulk_create(
                    [MetricaCaptura(**fila) for fila in lote],
                    update_conflicts=True,
                    unique_fields=["archivo_origen"],
                    update_fields=campos_actualizables,
                )
        creadas = len(filas) - actualizadas
        self.stdout.write(self.style.SUCCESS(
            f"Capturas importadas: {len(filas)} ({creadas} nuevas, {actualizadas} actualizadas)."
        ))
