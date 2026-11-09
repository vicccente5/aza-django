"""Modelos del dominio (diagrama de clases)."""
import secrets
import uuid
from datetime import timedelta

from django.contrib.auth.models import AbstractUser
from django.db import models
from django.utils import timezone
from django.utils.crypto import salted_hmac


def firma_recuperacion(usuario):
    contexto = f"{usuario.password}\0{usuario.email.casefold()}\0{usuario.is_active}\0{usuario.version_seguridad}"
    return salted_hmac("trefilado.recuperacion", contexto, algorithm="sha256").hexdigest()


class Usuario(AbstractUser):
    """Usuario con un único rol. 'is_active' representa el estado activo/desactivado."""

    class Rol(models.TextChoices):
        OPERADOR = "OPERADOR", "Operador"
        SUPERVISOR = "SUPERVISOR", "Supervisor"
        ADMINISTRADOR = "ADMINISTRADOR", "Administrador"

    rol = models.CharField(max_length=20, choices=Rol.choices, default=Rol.OPERADOR)
    fecha_cambio_clave = models.DateTimeField(default=timezone.now)
    version_seguridad = models.UUIDField(default=uuid.uuid4, editable=False)

    def nombre_completo(self):
        return self.get_full_name() or self.username

    def __str__(self):
        return f"{self.nombre_completo()} ({self.get_rol_display()})"


class TokenRecuperacion(models.Model):
    usuario = models.ForeignKey(Usuario, on_delete=models.CASCADE, related_name="tokens")
    token = models.CharField(max_length=100, unique=True)
    firma_clave = models.CharField(max_length=64, default="")
    expiracion = models.DateTimeField()
    usado = models.BooleanField(default=False)

    @property
    def valido(self):
        return (
            self.usuario.is_active
            and not self.usado
            and self.expiracion > timezone.now()
            and secrets.compare_digest(self.firma_clave, firma_recuperacion(self.usuario))
        )


class Receta(models.Model):
    nombre = models.CharField(max_length=80, unique=True)
    espesor = models.FloatField("Espesor (mm)")
    materialidad = models.CharField(max_length=60)
    limite_min = models.FloatField("Límite mínimo del ángulo (°)")
    limite_max = models.FloatField("Límite máximo del ángulo (°)")
    vigente = models.BooleanField(default=True)

    class Meta:
        ordering = ["nombre"]

    def __str__(self):
        return self.nombre


class Lote(models.Model):
    class Turno(models.TextChoices):
        MANANA = "MANANA", "Mañana"
        TARDE = "TARDE", "Tarde"
        NOCHE = "NOCHE", "Noche"

    class Estado(models.TextChoices):
        ABIERTO = "ABIERTO", "Abierto"
        CERRADO = "CERRADO", "Cerrado"

    identificador = models.CharField(max_length=40)
    receta = models.ForeignKey(Receta, on_delete=models.PROTECT, related_name="lotes")
    fecha = models.DateField(default=timezone.localdate)
    turno = models.CharField(max_length=10, choices=Turno.choices)
    estado = models.CharField(max_length=10, choices=Estado.choices, default=Estado.ABIERTO)

    class Meta:
        ordering = ["-fecha", "identificador"]

    def __str__(self):
        return self.identificador


class Inspeccion(models.Model):
    class Estado(models.TextChoices):
        APROBADO = "APROBADO", "Aprobado"
        RECHAZADO = "RECHAZADO", "Rechazado"
        SIN_RECETA = "SIN_RECETA", "Sin receta"

    lote = models.ForeignKey(Lote, on_delete=models.PROTECT, related_name="inspecciones")
    receta = models.ForeignKey(Receta, on_delete=models.PROTECT, null=True, blank=True, related_name="inspecciones")
    angulo = models.FloatField("Ángulo medido (°)")
    estado = models.CharField(max_length=12, choices=Estado.choices)
    # Copia de los límites con que se evaluó (no cambian si luego se edita la receta).
    limite_min = models.FloatField(null=True, blank=True)
    limite_max = models.FloatField(null=True, blank=True)
    fecha_hora_dato = models.DateTimeField()
    fecha_hora_recepcion = models.DateTimeField(default=timezone.now)
    imagen = models.FileField(upload_to="evidencias/", blank=True)
    imagen_referencia = models.CharField(max_length=255, blank=True)

    class Meta:
        ordering = ["-fecha_hora_dato", "-id"]

    @property
    def tiene_evidencia(self):
        return bool(self.imagen) or bool(self.imagen_referencia)

    def __str__(self):
        return f"Inspección {self.pk} - {self.get_estado_display()}"


class MetricaCaptura(models.Model):
    """Mediciones originales de los JSON consolidados, sin clasificación inventada."""

    archivo_origen = models.CharField(max_length=160, unique=True)
    trigger = models.CharField(max_length=12)
    fecha_hora = models.DateTimeField(db_index=True)
    total_frames = models.PositiveIntegerField()
    scene = models.CharField(max_length=30)
    mean_background = models.FloatField()
    first_exit_frame = models.PositiveIntegerField(null=True, blank=True)
    exit_confidence = models.CharField(max_length=40)
    circle_cx = models.FloatField(null=True, blank=True)
    circle_cy = models.FloatField(null=True, blank=True)
    circle_radius = models.FloatField(null=True, blank=True)
    circle_method = models.CharField(max_length=60, blank=True)
    circle_support_frames = models.PositiveIntegerField()
    angle_frame = models.PositiveIntegerField(null=True, blank=True)
    exit_angle_deg = models.FloatField(null=True, blank=True)
    angle_confidence = models.CharField(max_length=40)
    diagnostic_path = models.TextField(blank=True)

    class Meta:
        ordering = ["-fecha_hora", "-id"]

    def __str__(self):
        return f"Trigger {self.trigger} · {self.fecha_hora:%Y-%m-%d %H:%M:%S}"


class Alerta(models.Model):
    inspeccion = models.ForeignKey(Inspeccion, on_delete=models.CASCADE, related_name="alertas")
    fecha = models.DateTimeField(default=timezone.now)
    revisada = models.BooleanField(default=False)
    observacion = models.CharField(max_length=300, blank=True)
    fecha_revision = models.DateTimeField(null=True, blank=True)
    revisada_por = models.ForeignKey(Usuario, on_delete=models.SET_NULL, null=True, blank=True, related_name="alertas_revisadas")

    class Meta:
        ordering = ["fecha"]


class EnvioAPI(models.Model):
    inspeccion = models.OneToOneField(Inspeccion, on_delete=models.SET_NULL, null=True, blank=True, related_name="envio")
    fecha_hora = models.DateTimeField(default=timezone.now)
    ip_origen = models.GenericIPAddressField(null=True, blank=True)
    aceptado = models.BooleanField(default=False)
    motivo_rechazo = models.CharField(max_length=60, blank=True)

    class Meta:
        ordering = ["-fecha_hora", "-id"]


class BloqueoIP(models.Model):
    ip = models.GenericIPAddressField()
    fecha_inicio = models.DateTimeField(default=timezone.now)
    duracion_min = models.PositiveIntegerField(default=30)
    levantado = models.BooleanField(default=False)

    @property
    def fin(self):
        return self.fecha_inicio + timedelta(minutes=self.duracion_min)

    @property
    def activo(self):
        return (not self.levantado) and self.fin > timezone.now()

    class Meta:
        ordering = ["-fecha_inicio"]


class IpPermitida(models.Model):
    direccion = models.CharField("IP o subred", max_length=64, unique=True)
    descripcion = models.CharField("Descripción", max_length=120, blank=True)

    class Meta:
        ordering = ["direccion"]


class IntentoLogin(models.Model):
    username = models.CharField(max_length=150)
    ip = models.GenericIPAddressField(null=True, blank=True)
    fecha_hora = models.DateTimeField(default=timezone.now)
    exitoso = models.BooleanField(default=False)
    # ok, credenciales, desactivado, ip_no_autorizada, otp, bloqueado, bloqueo_activado
    motivo = models.CharField(max_length=30, blank=True)

    class Meta:
        ordering = ["-fecha_hora", "-id"]


class Auditoria(models.Model):
    """Registro inmutable de cambios (CU10)."""

    usuario = models.ForeignKey(Usuario, on_delete=models.SET_NULL, null=True, blank=True, related_name="auditorias")
    fecha_hora = models.DateTimeField(default=timezone.now)
    accion = models.CharField(max_length=60)
    detalle = models.CharField(max_length=300, blank=True)
    valor_anterior = models.TextField(blank=True)
    valor_nuevo = models.TextField(blank=True)

    class Meta:
        ordering = ["-fecha_hora", "-id"]

    def save(self, *args, **kwargs):
        if not self._state.adding:
            raise PermissionError("Las entradas de auditoría no se pueden modificar.")
        super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise PermissionError("Las entradas de auditoría no se pueden eliminar.")


class Parametro(models.Model):
    nombre = models.CharField(max_length=60, unique=True)
    valor = models.CharField(max_length=100)
    descripcion = models.CharField(max_length=200, blank=True)

    class Meta:
        ordering = ["nombre"]


class Respaldo(models.Model):
    class Resultado(models.TextChoices):
        EXITOSO = "EXITOSO", "Exitoso"
        FALLIDO = "FALLIDO", "Fallido"

    fecha_hora = models.DateTimeField(default=timezone.now)
    resultado = models.CharField(max_length=10, choices=Resultado.choices)
    archivo = models.CharField(max_length=200, blank=True)
    detalle = models.CharField(max_length=200, blank=True)

    class Meta:
        ordering = ["-fecha_hora", "-id"]
