"""Lógica de negocio reutilizable."""
import ipaddress
import sqlite3
import uuid
from datetime import timedelta
from pathlib import Path

from django.conf import settings
from django.core.mail import send_mail
from django.utils import timezone

from .models import Auditoria, IntentoLogin, IpPermitida, Inspeccion, Parametro, Respaldo

# nombre: (valor por defecto, descripción)
PARAM_DEFAULTS = {
    "login_max_intentos": ("5", "Intentos fallidos consecutivos de inicio de sesión antes de bloquear"),
    "login_bloqueo_min": ("15", "Minutos de bloqueo de acceso tras superar los intentos fallidos"),
    "clave_vigencia_dias": ("90", "Días de vigencia de la contraseña"),
    "api_max_intentos": ("10", "Intentos fallidos consecutivos en la API antes de bloquear la IP"),
    "api_bloqueo_min": ("30", "Minutos de bloqueo de una IP en la API"),
    "alerta_umbral_seg": ("2", "Segundos entre actualizaciones del panel del Operador (alertas)"),
    "api_desconexion_min": ("5", "Minutos sin datos para considerar desconectada la API de captura"),
    "retencion_historicos_dias": ("365", "Política de retención de históricos (días)"),
    "respaldo_frecuencia": ("DIARIA", "Frecuencia de respaldos automáticos"),
}

FRECUENCIAS_RESPALDO = [("DIARIA", "Diaria"), ("SEMANAL", "Semanal"), ("MENSUAL", "Mensual")]


def asegurar_parametros():
    """Crea los parámetros que falten con su valor por defecto."""
    for nombre, (valor, desc) in PARAM_DEFAULTS.items():
        Parametro.objects.get_or_create(nombre=nombre, defaults={"valor": valor, "descripcion": desc})


def get_param(nombre):
    """Devuelve el valor del parámetro (entero si corresponde); si no existe, usa el defecto."""
    p = Parametro.objects.filter(nombre=nombre).first()
    valor = p.valor if p else PARAM_DEFAULTS[nombre][0]
    try:
        return int(valor)
    except (TypeError, ValueError):
        return valor


def registrar_auditoria(usuario, accion, detalle="", anterior="", nuevo=""):
    if not getattr(usuario, "is_authenticated", False):
        usuario = None
    return Auditoria.objects.create(
        usuario=usuario, accion=accion, detalle=detalle[:300], valor_anterior=anterior, valor_nuevo=nuevo
    )


def obtener_ip(request):
    return request.META.get("REMOTE_ADDR") or None


def validar_politica_clave(clave):
    """Mínimo 8 caracteres, una mayúscula y un número. Devuelve lista de errores."""
    errores = []
    if len(clave) < 8:
        errores.append("Debe tener al menos 8 caracteres.")
    if not any(c.isupper() for c in clave):
        errores.append("Debe incluir al menos una letra mayúscula.")
    if not any(c.isdigit() for c in clave):
        errores.append("Debe incluir al menos un número.")
    return errores


def cambiar_clave(usuario, nueva):
    version_anterior = usuario.version_seguridad
    usuario.set_password(nueva)
    fecha = timezone.now()
    version_nueva = uuid.uuid4()
    actualizados = type(usuario).objects.filter(
        pk=usuario.pk, version_seguridad=version_anterior, is_active=True
    ).update(
        password=usuario.password,
        fecha_cambio_clave=fecha,
        version_seguridad=version_nueva,
    )
    if not actualizados:
        return False
    usuario.fecha_cambio_clave = fecha
    usuario.version_seguridad = version_nueva
    return True


def enviar_correo(destino, asunto, mensaje):
    if not destino:
        return False
    return send_mail(asunto, mensaje, None, [destino], fail_silently=False)


# ---------------------------------------------------------------- lista blanca de IPs
def ip_en_lista_blanca(ip):
    try:
        direccion = ipaddress.ip_address(ip)
    except (ValueError, TypeError):
        return False
    for entrada in IpPermitida.objects.all():
        try:
            if direccion in ipaddress.ip_network(entrada.direccion, strict=False):
                return True
        except ValueError:
            continue
    return False


# ---------------------------------------------------------------- bloqueo de login
def login_bloqueado(username):
    minutos = get_param("login_bloqueo_min")
    ultimo = IntentoLogin.objects.filter(username=username, motivo="bloqueo_activado").order_by("-fecha_hora").first()
    return bool(ultimo and ultimo.fecha_hora + timedelta(minutes=minutos) > timezone.now())


def registrar_fallo_login(username, ip, motivo):
    """Registra un intento fallido y, al alcanzar el máximo consecutivo, activa el bloqueo."""
    IntentoLogin.objects.create(username=username, ip=ip, exitoso=False, motivo=motivo)
    maximo = get_param("login_max_intentos")
    corte = None
    for e in IntentoLogin.objects.filter(username=username).filter(
        motivo__in=["ok", "bloqueo_activado"]
    ).order_by("-fecha_hora")[:1]:
        corte = e.fecha_hora
    qs = IntentoLogin.objects.filter(username=username, motivo__in=["credenciales", "otp"])
    if corte:
        qs = qs.filter(fecha_hora__gt=corte)
    if qs.count() >= maximo:
        IntentoLogin.objects.create(username=username, ip=ip, exitoso=False, motivo="bloqueo_activado")


# ---------------------------------------------------------------- clasificación (CU18)
def clasificar(angulo, receta):
    """Devuelve el estado de la inspección según la receta activa."""
    if receta is None or not receta.vigente:
        return Inspeccion.Estado.SIN_RECETA
    if receta.limite_min <= angulo <= receta.limite_max:
        return Inspeccion.Estado.APROBADO
    return Inspeccion.Estado.RECHAZADO


# ---------------------------------------------------------------- respaldos (CU14)
def ejecutar_respaldo():
    if settings.DATABASES["default"]["ENGINE"] != "django.db.backends.sqlite3":
        raise RuntimeError("El respaldo de archivos solo es compatible con SQLite; use los respaldos de Supabase.")
    carpeta = Path(settings.BASE_DIR) / "respaldos"
    carpeta.mkdir(exist_ok=True)
    nombre = f"aza_{timezone.localtime().strftime('%Y%m%d_%H%M%S')}.sqlite3"
    try:
        origen = sqlite3.connect(str(settings.DATABASES["default"]["NAME"]))
        destino = sqlite3.connect(str(carpeta / nombre))
        origen.backup(destino)
        destino.close()
        origen.close()
        return Respaldo.objects.create(resultado=Respaldo.Resultado.EXITOSO, archivo=nombre)
    except Exception as exc:  # noqa: BLE001 - se registra como respaldo fallido
        return Respaldo.objects.create(resultado=Respaldo.Resultado.FALLIDO, detalle=str(exc)[:200])
