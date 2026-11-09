import csv
import json
import secrets
import uuid
from datetime import datetime, timedelta

from django.conf import settings
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout, update_session_auth_hash
from django.contrib.sessions.models import Session
from django.core.paginator import Paginator
from django.utils.crypto import salted_hmac
from django.db import transaction
from django.db.models import Count, Max, Min, Q
from django.db.models.functions import TruncDate
from django.http import FileResponse, Http404, HttpResponse, JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.utils import timezone
from django.utils.dateparse import parse_datetime
from django.utils.html import format_html
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST

from .decorators import rol_requerido
from .forms import (
    AuditoriaFiltroForm, ConfigRespaldoForm, EvidenciaForm, IpForm, LoginForm, LoteForm,
    MetricasFiltroForm, NuevaClaveForm, OTPForm, RecetaForm, RecuperarForm, UsuarioForm,
)
from .models import (
    Alerta, Auditoria, BloqueoIP, EnvioAPI, IntentoLogin, Inspeccion, IpPermitida, Lote,
    MetricaCaptura, Parametro, Receta, Respaldo, TokenRecuperacion, Usuario, firma_recuperacion,
)
from .services import (
    PARAM_DEFAULTS, asegurar_parametros, cambiar_clave, clasificar, ejecutar_respaldo, enviar_correo,
    get_param, ip_en_lista_blanca, login_bloqueado, obtener_ip, registrar_auditoria, registrar_fallo_login,
)

OP = Usuario.Rol.OPERADOR
SUP = Usuario.Rol.SUPERVISOR
ADM = Usuario.Rol.ADMINISTRADOR


# =====================================================================================
# CU01 / CU02 - Autenticación
# =====================================================================================
def home(request):
    if not request.user.is_authenticated:
        return redirect("login")
    destinos = {OP: "panel", SUP: "dashboard", ADM: "control"}
    return redirect(destinos.get(request.user.rol, "login"))


def _finalizar_login(request, usuario, ip, otp_verificado=False):
    login(request, usuario)
    request.session["otp_verificado"] = bool(otp_verificado and usuario.rol == ADM)
    request.session["auth_version"] = str(usuario.version_seguridad)
    IntentoLogin.objects.create(username=usuario.username, ip=ip, exitoso=True, motivo="ok")
    vigencia = get_param("clave_vigencia_dias")
    if timezone.now() - usuario.fecha_cambio_clave > timedelta(days=vigencia):
        request.session["clave_vencida"] = True
        messages.warning(request, f"Su contraseña tiene más de {vigencia} días. Debe cambiarla para continuar.")
        return redirect("cambiar_clave")
    destino = request.GET.get("next", "")
    if destino.startswith("/") and not destino.startswith("//"):
        return redirect(destino)
    return redirect("home")


def _firma_otp(usuario):
    contexto = f"{usuario.password}\0{usuario.email.casefold()}\0{usuario.is_active}\0{usuario.version_seguridad}"
    return salted_hmac("trefilado.otp", contexto, algorithm="sha256").hexdigest()


def _emitir_otp(request, usuario, reenvio=False):
    previo = request.session.get("pre_auth") if reenvio else None
    if reenvio and (not previo or previo.get("user_id") != usuario.pk or previo.get("reenviados", 0) >= 2):
        return False
    codigo = f"{secrets.randbelow(10**6):06d}"
    nuevo = {
        "user_id": usuario.pk,
        "codigo": codigo,
        "expira": (timezone.now() + timedelta(minutes=5)).isoformat(),
        "reenviados": previo.get("reenviados", 0) + 1 if previo else 0,
        "clave": _firma_otp(usuario),
    }
    try:
        enviado = enviar_correo(usuario.email, "Código de verificación AZA", f"Su código OTP es: {codigo} (vence en 5 minutos).")
    except Exception:
        enviado = False
    if not enviado:
        request.session.pop("pre_auth", None)
        return False
    request.session["pre_auth"] = nuevo
    if getattr(settings, "MOSTRAR_CODIGOS_EN_PANTALLA", settings.DEBUG):
        messages.info(request, f"Código de verificación enviado a su correo: {codigo}")
    return True


def login_view(request):
    if request.user.is_authenticated:
        return redirect("home")
    form = LoginForm(request.POST or None)
    if request.method == "POST" and form.is_valid():
        username = form.cleaned_data["username"].strip()
        password = form.cleaned_data["password"]
        ip = obtener_ip(request)

        if login_bloqueado(username):
            IntentoLogin.objects.create(username=username, ip=ip, exitoso=False, motivo="bloqueado")
            messages.error(
                request,
                f"Acceso bloqueado temporalmente por intentos fallidos. Intente de nuevo en {get_param('login_bloqueo_min')} minutos.",
            )
            return render(request, "trefilado/login.html", {"form": form})

        candidato = Usuario.objects.filter(username=username).first()
        if candidato and not candidato.is_active and candidato.check_password(password):
            IntentoLogin.objects.create(username=username, ip=ip, exitoso=False, motivo="desactivado")
            messages.error(request, "Su usuario está desactivado. Contacte al Administrador.")
            return render(request, "trefilado/login.html", {"form": form})

        usuario = authenticate(request, username=username, password=password)
        if usuario is None:
            registrar_fallo_login(username, ip, "credenciales")
            messages.error(request, "Usuario o contraseña incorrectos.")
            return render(request, "trefilado/login.html", {"form": form})

        if usuario.rol == OP and not ip_en_lista_blanca(ip):
            IntentoLogin.objects.create(username=username, ip=ip, exitoso=False, motivo="ip_no_autorizada")
            messages.error(request, "Acceso no permitido desde esta dirección IP. Los Operadores solo pueden ingresar desde la red de la planta.")
            return render(request, "trefilado/login.html", {"form": form})

        if usuario.rol == ADM:
            if _emitir_otp(request, usuario):
                return redirect("login_otp")
            messages.error(request, "No se pudo enviar el código de verificación. Intente más tarde.")
            return render(request, "trefilado/login.html", {"form": form})

        return _finalizar_login(request, usuario, ip)
    return render(request, "trefilado/login.html", {"form": form})


def login_otp(request):
    pre = request.session.get("pre_auth")
    if not pre:
        return redirect("login")
    usuario = Usuario.objects.filter(pk=pre["user_id"]).first()
    if usuario is None or not usuario.is_active or usuario.rol != ADM or not secrets.compare_digest(
        _firma_otp(usuario), pre.get("clave", "")
    ):
        request.session.pop("pre_auth", None)
        return redirect("login")
    form = OTPForm(request.POST or None)
    if request.method == "POST":
        ip = obtener_ip(request)
        if login_bloqueado(usuario.username):
            request.session.pop("pre_auth", None)
            messages.error(request, "Acceso bloqueado temporalmente por intentos fallidos.")
            return redirect("login")
        if "reenviar" in request.POST:
            if _emitir_otp(request, usuario, reenvio=True):
                messages.success(request, "Se envió un nuevo código.")
                return redirect("login_otp")
            request.session.pop("pre_auth", None)
            messages.error(request, "No se pudo reenviar el código. Inicie sesión nuevamente.")
            return redirect("login")
        if form.is_valid():
            expirado = datetime.fromisoformat(pre["expira"]) < timezone.now()
            if expirado or form.cleaned_data["codigo"] != pre["codigo"]:
                registrar_fallo_login(usuario.username, ip, "otp")
                messages.error(request, "Código OTP incorrecto o expirado. Puede reintentar o solicitar un nuevo código.")
            else:
                request.session.pop("pre_auth", None)
                return _finalizar_login(request, usuario, ip, otp_verificado=True)
    return render(request, "trefilado/login_otp.html", {"form": form, "usuario": usuario})


@require_POST
def logout_view(request):
    logout(request)
    messages.success(request, "Sesión cerrada correctamente.")
    return redirect("login")


@rol_requerido()
def cambiar_clave_view(request):
    form = NuevaClaveForm(request.POST or None)
    if request.method == "POST" and form.is_valid():
        if not cambiar_clave(request.user, form.cleaned_data["password1"]):
            logout(request)
            messages.error(request, "La cuenta cambió durante la operación. Inicie sesión nuevamente.")
            return redirect("login")
        update_session_auth_hash(request, request.user)
        request.session["auth_version"] = str(request.user.version_seguridad)
        request.session.pop("clave_vencida", None)
        registrar_auditoria(request.user, "CAMBIO_CLAVE", "El usuario cambió su contraseña")
        messages.success(request, "Contraseña actualizada correctamente.")
        return redirect("home")
    return render(request, "trefilado/form_pagina.html", {"titulo": "Cambiar contraseña", "form": form, "boton": "Guardar contraseña"})


def recuperar(request):
    form = RecuperarForm(request.POST or None)
    if request.method == "POST" and form.is_valid():
        ident = form.cleaned_data["identificador"].strip()
        usuario = Usuario.objects.filter(Q(username=ident) | Q(email__iexact=ident)).first()
        if usuario and usuario.is_active and usuario.email:
            tok = TokenRecuperacion.objects.create(
                usuario=usuario,
                token=secrets.token_urlsafe(32),
                firma_clave=firma_recuperacion(usuario),
                expiracion=timezone.now() + timedelta(minutes=30),
            )
            ruta = reverse("recuperar_confirmar", args=[tok.token])
            enlace = f"{settings.PUBLIC_BASE_URL}{ruta}" if settings.PUBLIC_BASE_URL else request.build_absolute_uri(ruta)
            try:
                enviado = enviar_correo(usuario.email, "Recuperación de contraseña AZA", f"Use este enlace (vence en 30 minutos): {enlace}")
            except Exception:
                enviado = False
            if enviado:
                registrar_auditoria(usuario, "RECUPERACION_SOLICITADA", "Se generó un enlace temporal")
                if getattr(settings, "MOSTRAR_CODIGOS_EN_PANTALLA", settings.DEBUG):
                    messages.info(request, format_html('Enlace enviado a su correo: <a href="{0}">{0}</a>', enlace))
            else:
                tok.delete()
        else:
            registrar_auditoria(None, "RECUPERACION_SOLICITADA", f"Solicitud para cuenta inexistente o desactivada: {ident}")
        messages.success(request, "Si la cuenta existe, recibirás un correo con las instrucciones.")
        return redirect("recuperar")
    return render(request, "trefilado/recuperar.html", {"form": form})


def recuperar_confirmar(request, token):
    tok = TokenRecuperacion.objects.filter(token=token).select_related("usuario").first()
    if tok is None or not tok.valido:
        messages.error(request, "El enlace no es válido, expiró o ya fue utilizado. Solicite uno nuevo.")
        return redirect("recuperar")
    form = NuevaClaveForm(request.POST or None)
    if request.method == "POST" and form.is_valid():
        with transaction.atomic():
            tok = TokenRecuperacion.objects.select_for_update().select_related("usuario").get(pk=tok.pk)
            if not tok.valido:
                messages.error(request, "El enlace no es válido, expiró o ya fue utilizado. Solicite uno nuevo.")
                return redirect("recuperar")
            if not cambiar_clave(tok.usuario, form.cleaned_data["password1"]):
                messages.error(request, "La cuenta cambió durante la operación. Solicite un enlace nuevo.")
                return redirect("recuperar")
            tok.usado = True
            tok.save(update_fields=["usado"])
            registrar_auditoria(tok.usuario, "CLAVE_RESTABLECIDA", "Contraseña restablecida mediante enlace temporal")
        _cerrar_sesiones_usuario(tok.usuario_id)
        messages.success(request, "Contraseña restablecida. Ya puede iniciar sesión.")
        return redirect("login")
    return render(request, "trefilado/form_pagina.html", {"titulo": "Restablecer contraseña", "form": form, "boton": "Restablecer", "publico": True})


# =====================================================================================
# CU03 / CU04 / CU05 / CU06 - Operador
# =====================================================================================
def _batch_actual(request):
    batch = request.session.get("batch")
    if not batch:
        return None, None
    lote = Lote.objects.select_related("receta").filter(pk=batch["lote"], estado=Lote.Estado.ABIERTO).first()
    receta = Receta.objects.filter(pk=batch["receta"]).first()
    if lote is None or receta is None:
        request.session.pop("batch", None)
        return None, None
    return receta, lote


@rol_requerido(OP)
def seleccion(request):
    recetas = Receta.objects.filter(vigente=True)
    lotes = Lote.objects.filter(estado=Lote.Estado.ABIERTO).select_related("receta").order_by("identificador")
    if not recetas.exists() or not lotes.exists():
        messages.warning(request, "No hay recetas vigentes o lotes abiertos. Contacte al Supervisor o Administrador.")
    if request.method == "POST":
        rid, lid = request.POST.get("receta", ""), request.POST.get("lote", "")
        if not rid or not lid:
            messages.error(request, "Debe seleccionar una receta y un lote para poder registrar resultados.")
        else:
            receta = recetas.filter(pk=rid).first() if rid.isdigit() else None
            lote = lotes.filter(pk=lid).first() if lid.isdigit() else None
            if receta is None or lote is None:
                messages.error(request, "La receta o el lote seleccionado ya no está disponible.")
            elif lote.receta_id != receta.id:
                messages.error(request, "El lote seleccionado no corresponde a la receta elegida.")
            else:
                cambio = "batch" in request.session
                request.session["batch"] = {"receta": receta.id, "lote": lote.id, "hora": timezone.now().isoformat()}
                registrar_auditoria(
                    request.user, "CAMBIO_BATCH" if cambio else "SELECCION_BATCH",
                    f"Receta {receta.nombre} / Lote {lote.identificador}",
                )
                messages.success(request, "Receta y lote asociados al batch en curso.")
                return redirect("panel")
    receta, lote = _batch_actual(request)
    return render(request, "trefilado/seleccion.html", {"recetas": recetas, "lotes": lotes, "receta_sel": receta, "lote_sel": lote})


@rol_requerido(OP)
def panel(request):
    ctx = {
        "ultima": MetricaCaptura.objects.first(),
        "recientes": MetricaCaptura.objects.all()[:8],
        "intervalo": 10,
    }
    if request.GET.get("parcial"):
        return render(request, "trefilado/_panel_contenido.html", ctx)
    return render(request, "trefilado/panel.html", ctx)


@rol_requerido(OP)
@require_POST
def alerta_revisar(request, pk):
    alerta = get_object_or_404(Alerta, pk=pk)
    if not alerta.revisada:
        alerta.revisada = True
        alerta.observacion = request.POST.get("observacion", "").strip()[:300]
        alerta.fecha_revision = timezone.now()
        alerta.revisada_por = request.user
        alerta.save()
        messages.success(request, "Alerta marcada como revisada.")
    return redirect("panel")


@rol_requerido()
def inspeccion_detalle(request, pk):
    insp = get_object_or_404(Inspeccion.objects.select_related("lote", "receta"), pk=pk)
    form = EvidenciaForm()
    if request.method == "POST":
        if request.user.rol != OP:
            messages.error(request, "Solo el Operador puede asociar evidencia visual.")
            return redirect("inspeccion_detalle", pk=pk)
        form = EvidenciaForm(request.POST, request.FILES)
        if form.is_valid():
            archivo = form.cleaned_data.get("archivo")
            ref = form.cleaned_data.get("referencia", "").strip()
            if not archivo and not ref:
                messages.warning(request, "No se adjuntó imagen; el registro de la inspección se conserva sin evidencia.")
            else:
                if archivo:
                    insp.imagen = archivo
                if ref:
                    insp.imagen_referencia = ref
                insp.save()
                registrar_auditoria(request.user, "EVIDENCIA_ASOCIADA", f"Inspección {insp.pk}")
                messages.success(request, "Evidencia visual asociada a la inspección.")
            return redirect("inspeccion_detalle", pk=pk)
    return render(request, "trefilado/inspeccion_detalle.html", {"insp": insp, "form": form, "alertas": insp.alertas.all()})


@rol_requerido()
def evidencia(request, pk):
    insp = get_object_or_404(Inspeccion, pk=pk)
    if not insp.imagen:
        raise Http404("Sin imagen asociada")
    return FileResponse(insp.imagen.open("rb"))


# =====================================================================================
# CU07 / CU08 / CU09 - Supervisor
# =====================================================================================
def _aplicar_fechas(qs, form, campo):
    if form.cleaned_data.get("desde"):
        qs = qs.filter(**{f"{campo}__date__gte": form.cleaned_data["desde"]})
    if form.cleaned_data.get("hasta"):
        qs = qs.filter(**{f"{campo}__date__lte": form.cleaned_data["hasta"]})
    return qs


@rol_requerido(SUP, ADM)
def historial(request):
    form = MetricasFiltroForm(request.GET or None)
    qs = MetricaCaptura.objects.all()
    if form.is_bound:
        if form.is_valid():
            d = form.cleaned_data
            qs = _aplicar_fechas(qs, form, "fecha_hora")
            if d.get("escena"):
                qs = qs.filter(scene__iexact=d["escena"].strip())
            if d.get("angulo") == "con":
                qs = qs.filter(exit_angle_deg__isnull=False)
            elif d.get("angulo") == "sin":
                qs = qs.filter(exit_angle_deg__isnull=True)
        else:
            qs = qs.none()

    if request.GET.get("export") == "csv":
        if not qs.exists():
            messages.warning(request, "No hay datos para exportar con los filtros actuales.")
        else:
            resp = HttpResponse(content_type="text/csv; charset=utf-8")
            resp["Content-Disposition"] = 'attachment; filename="metricas_captura.csv"'
            resp.write("\ufeff")
            w = csv.writer(resp, delimiter=";")
            w.writerow([
                "Archivo origen", "Fecha/hora", "Trigger", "Escena", "Frames", "Fondo medio",
                "Primer frame de salida", "Confianza salida", "Centro X", "Centro Y", "Radio",
                "Método círculo", "Frames soporte", "Frame ángulo", "Ángulo salida (°)",
                "Confianza ángulo", "Ruta diagnóstico original",
            ])
            for i in qs.iterator():
                w.writerow([
                    i.archivo_origen, timezone.localtime(i.fecha_hora).strftime("%d-%m-%Y %H:%M:%S"),
                    i.trigger, i.scene, i.total_frames, i.mean_background,
                    i.first_exit_frame, i.exit_confidence, i.circle_cx, i.circle_cy,
                    i.circle_radius, i.circle_method, i.circle_support_frames,
                    i.angle_frame, i.exit_angle_deg, i.angle_confidence, i.diagnostic_path,
                ])
            return resp

    pagina = Paginator(qs, 20).get_page(request.GET.get("page"))
    q = request.GET.copy()
    q.pop("page", None)
    q.pop("export", None)
    return render(request, "trefilado/historial.html", {"form": form, "pagina": pagina, "querystring": q.urlencode()})


@rol_requerido(OP, SUP, ADM)
def metrica_detalle(request, pk):
    metrica = get_object_or_404(MetricaCaptura, pk=pk)
    return render(request, "trefilado/metrica_detalle.html", {"metrica": metrica})


def _svg_tendencia(valores, lim_min=None, lim_max=None):
    """Genera los datos de un gráfico de líneas SVG simple (todo como texto)."""
    if not valores:
        return None
    ancho, alto, margen = 640, 220, 30
    candidatos = list(valores)
    if lim_min is not None and lim_max is not None:
        candidatos += [lim_min, lim_max]
    vmin, vmax = min(candidatos), max(candidatos)
    if vmax == vmin:
        vmin, vmax = vmin - 1, vmax + 1
    pad = (vmax - vmin) * 0.1
    vmin, vmax = vmin - pad, vmax + pad

    def py(v):
        return alto - margen - (v - vmin) / (vmax - vmin) * (alto - 2 * margen)

    n = len(valores)

    def px(i):
        return margen + (i * (ancho - 2 * margen) / (n - 1 if n > 1 else 1))

    return {
        "ancho": str(ancho), "alto": str(alto),
        "puntos": " ".join(f"{px(i):.1f},{py(v):.1f}" for i, v in enumerate(valores)),
        "circulos": [(f"{px(i):.1f}", f"{py(v):.1f}") for i, v in enumerate(valores)] if n <= 40 else [],
        "y_min": f"{py(lim_min):.1f}" if lim_min is not None else None,
        "y_max": f"{py(lim_max):.1f}" if lim_max is not None else None,
        "x0": str(margen), "x1": str(ancho - margen),
        "txt_min": f"{lim_min:.2f}" if lim_min is not None else "", "txt_max": f"{lim_max:.2f}" if lim_max is not None else "",
        "eje_sup": f"{vmax:.2f}", "eje_inf": f"{vmin:.2f}", "y_inf": str(alto - margen), "y_sup": str(margen),
    }


@rol_requerido(SUP, ADM)
def dashboard(request):
    form = MetricasFiltroForm(request.GET or None)
    qs = MetricaCaptura.objects.all()
    if form.is_bound:
        if form.is_valid():
            qs = _aplicar_fechas(qs, form, "fecha_hora")
            escena = form.cleaned_data.get("escena", "").strip()
            if escena:
                qs = qs.filter(scene__iexact=escena)
            if form.cleaned_data.get("angulo") == "con":
                qs = qs.filter(exit_angle_deg__isnull=False)
            elif form.cleaned_data.get("angulo") == "sin":
                qs = qs.filter(exit_angle_deg__isnull=True)
        else:
            qs = qs.none()
    total = qs.count()
    con_angulo = qs.filter(exit_angle_deg__isnull=False).count()
    angulos = qs.filter(exit_angle_deg__isnull=False).aggregate(
        minimo=Min("exit_angle_deg"), maximo=Max("exit_angle_deg")
    )
    valores = list(qs.filter(exit_angle_deg__isnull=False).order_by("-fecha_hora").values_list("exit_angle_deg", flat=True)[:60])[::-1]
    dias = list(qs.annotate(dia=TruncDate("fecha_hora")).values("dia").annotate(
        total=Count("id"), con_angulo=Count("id", filter=Q(exit_angle_deg__isnull=False))
    ).order_by("dia"))
    mayor_dia = max((d["total"] for d in dias), default=0)
    for dia in dias:
        dia["pct"] = round(dia["total"] * 100 / mayor_dia) if mayor_dia else 0
    ctx = {
        "form": form, "total": total, "con_angulo": con_angulo,
        "sin_angulo": total - con_angulo,
        "porcentaje_angulo": round(con_angulo * 100 / total, 1) if total else 0,
        "angulos": angulos, "svg": _svg_tendencia(valores), "dias": dias,
        "escenas": qs.values("scene").annotate(n=Count("id")).order_by("-n", "scene"),
        "confianzas": qs.values("angle_confidence").annotate(n=Count("id")).order_by("-n", "angle_confidence"),
        "ahora": timezone.localtime(),
    }
    if request.GET.get("parcial"):
        return render(request, "trefilado/_dashboard_contenido.html", ctx)
    return render(request, "trefilado/dashboard.html", ctx)


@rol_requerido(SUP)
def lotes(request):
    return render(request, "trefilado/lotes.html", {"lotes": Lote.objects.select_related("receta")[:100]})


@rol_requerido(SUP)
def lote_nuevo(request):
    form = LoteForm(request.POST or None)
    if request.method == "POST" and form.is_valid():
        lote = form.save()
        registrar_auditoria(request.user, "LOTE_CREADO", f"Lote {lote.identificador}", nuevo=f"receta={lote.receta}, fecha={lote.fecha}, turno={lote.get_turno_display()}")
        messages.success(request, "Lote creado correctamente.")
        return redirect("lotes")
    return render(request, "trefilado/form_pagina.html", {"titulo": "Nuevo lote", "form": form, "volver": "lotes"})


@rol_requerido(SUP)
def lote_editar(request, pk):
    lote = get_object_or_404(Lote, pk=pk)
    if lote.estado == Lote.Estado.CERRADO:
        messages.error(request, "El lote está cerrado y no puede editarse.")
        return redirect("lotes")
    anterior = f"identificador={lote.identificador}, receta={lote.receta}, fecha={lote.fecha}, turno={lote.get_turno_display()}"
    form = LoteForm(request.POST or None, instance=lote)
    if request.method == "POST" and form.is_valid():
        lote = form.save()
        nuevo = f"identificador={lote.identificador}, receta={lote.receta}, fecha={lote.fecha}, turno={lote.get_turno_display()}"
        registrar_auditoria(request.user, "LOTE_EDITADO", f"Lote {lote.identificador}", anterior, nuevo)
        messages.success(request, "Lote actualizado.")
        return redirect("lotes")
    return render(request, "trefilado/form_pagina.html", {"titulo": f"Editar lote {lote.identificador}", "form": form, "volver": "lotes"})


@rol_requerido(SUP)
@require_POST
def lote_cerrar(request, pk):
    lote = get_object_or_404(Lote, pk=pk)
    if lote.estado == Lote.Estado.ABIERTO:
        lote.estado = Lote.Estado.CERRADO
        lote.save()
        registrar_auditoria(request.user, "LOTE_CERRADO", f"Lote {lote.identificador}", "ABIERTO", "CERRADO")
        messages.success(request, "Lote cerrado: ya no se ofrece para selección en planta.")
    return redirect("lotes")


# =====================================================================================
# CU10 - Auditoría
# =====================================================================================
@rol_requerido(SUP, ADM)
def auditoria(request):
    form = AuditoriaFiltroForm(request.GET or None)
    qs = Auditoria.objects.select_related("usuario")
    if form.is_bound:
        if form.is_valid():
            d = form.cleaned_data
            qs = _aplicar_fechas(qs, form, "fecha_hora")
            if d.get("usuario"):
                qs = qs.filter(usuario=d["usuario"])
            if d.get("accion"):
                qs = qs.filter(accion__icontains=d["accion"].strip())
        else:
            qs = qs.none()
    pagina = Paginator(qs, 25).get_page(request.GET.get("page"))
    q = request.GET.copy()
    q.pop("page", None)
    return render(request, "trefilado/auditoria.html", {"form": form, "pagina": pagina, "querystring": q.urlencode()})


# =====================================================================================
# CU11 - Usuarios y roles
# =====================================================================================
@rol_requerido(ADM)
def usuarios(request):
    return render(request, "trefilado/usuarios.html", {"usuarios": Usuario.objects.order_by("rol", "username")})


def _cerrar_sesiones_usuario(usuario_id):
    for sesion in Session.objects.filter(expire_date__gt=timezone.now()):
        datos = sesion.get_decoded()
        if datos.get("_auth_user_id") == str(usuario_id) or datos.get("pre_auth", {}).get("user_id") == usuario_id:
            sesion.delete()


@rol_requerido(ADM)
def usuario_nuevo(request):
    form = UsuarioForm(request.POST or None)
    if request.method == "POST" and form.is_valid():
        u = form.save()
        registrar_auditoria(request.user, "USUARIO_CREADO", f"Usuario {u.username}", nuevo=f"rol={u.get_rol_display()}, correo={u.email}")
        messages.success(request, "Usuario creado con los permisos de su rol.")
        return redirect("usuarios")
    return render(request, "trefilado/form_pagina.html", {"titulo": "Nuevo usuario", "form": form, "volver": "usuarios"})


@rol_requerido(ADM)
def usuario_editar(request, pk):
    u = get_object_or_404(Usuario, pk=pk)
    rol_anterior, clave_anterior, correo_anterior = u.rol, u.password, u.email
    username_anterior, version_anterior = u.username, u.version_seguridad
    anterior = f"nombre={u.nombre_completo()}, rol={u.get_rol_display()}, correo={u.email}"
    form = UsuarioForm(request.POST or None, instance=u)
    if request.method == "POST" and form.is_valid():
        u = form.save(commit=False)
        cambio_sensible = any((
            u.rol != rol_anterior,
            u.password != clave_anterior,
            u.email != correo_anterior,
            u.username != username_anterior,
        ))
        if cambio_sensible:
            u.version_seguridad = uuid.uuid4()
        actualizados = Usuario.objects.filter(pk=u.pk, version_seguridad=version_anterior).update(
            username=u.username,
            first_name=u.first_name,
            last_name=u.last_name,
            email=u.email,
            rol=u.rol,
            password=u.password,
            fecha_cambio_clave=u.fecha_cambio_clave,
            version_seguridad=u.version_seguridad,
        )
        if not actualizados:
            messages.error(request, "La cuenta cambió durante la edición. Revise sus datos e intente nuevamente.")
            return redirect("usuarios")
        if cambio_sensible:
            _cerrar_sesiones_usuario(u.pk)
        if u.password != clave_anterior or u.email != correo_anterior or u.username != username_anterior:
            TokenRecuperacion.objects.filter(usuario=u, usado=False).update(usado=True)
        nuevo = f"nombre={u.nombre_completo()}, rol={u.get_rol_display()}, correo={u.email}"
        registrar_auditoria(request.user, "USUARIO_EDITADO", f"Usuario {u.username}", anterior, nuevo)
        messages.success(request, "Usuario actualizado.")
        return redirect("usuarios")
    return render(request, "trefilado/form_pagina.html", {"titulo": f"Editar usuario {u.username}", "form": form, "volver": "usuarios"})


@rol_requerido(ADM)
@require_POST
def usuario_estado(request, pk):
    u = get_object_or_404(Usuario, pk=pk)
    if u.pk == request.user.pk:
        messages.error(request, "No puede desactivar su propio usuario.")
        return redirect("usuarios")
    anterior = "activo" if u.is_active else "desactivado"
    nuevo_estado = not u.is_active
    version_nueva = uuid.uuid4()
    actualizados = Usuario.objects.filter(pk=u.pk, version_seguridad=u.version_seguridad).update(
        is_active=nuevo_estado, version_seguridad=version_nueva
    )
    if not actualizados:
        messages.error(request, "La cuenta cambió durante la operación. Intente nuevamente.")
        return redirect("usuarios")
    u.is_active = nuevo_estado
    u.version_seguridad = version_nueva
    _cerrar_sesiones_usuario(u.pk)
    TokenRecuperacion.objects.filter(usuario=u, usado=False).update(usado=True)
    nuevo = "activo" if u.is_active else "desactivado"
    registrar_auditoria(request.user, "USUARIO_ACTIVADO" if u.is_active else "USUARIO_DESACTIVADO", f"Usuario {u.username}", anterior, nuevo)
    messages.success(request, f"Usuario {nuevo}. Su historial de acciones se conserva.")
    return redirect("usuarios")


# =====================================================================================
# CU12 - Recetas
# =====================================================================================
@rol_requerido(ADM)
def recetas(request):
    return render(request, "trefilado/recetas.html", {"recetas": Receta.objects.all()})


def _txt_receta(r):
    return f"espesor={r.espesor}, material={r.materialidad}, min={r.limite_min}, max={r.limite_max}, vigente={r.vigente}"


@rol_requerido(ADM)
def receta_nueva(request):
    form = RecetaForm(request.POST or None)
    if request.method == "POST" and form.is_valid():
        r = form.save()
        registrar_auditoria(request.user, "RECETA_CREADA", f"Receta {r.nombre}", nuevo=_txt_receta(r))
        messages.success(request, "Receta creada.")
        return redirect("recetas")
    return render(request, "trefilado/form_pagina.html", {"titulo": "Nueva receta", "form": form, "volver": "recetas"})


@rol_requerido(ADM)
def receta_editar(request, pk):
    r = get_object_or_404(Receta, pk=pk)
    anterior = _txt_receta(r)
    form = RecetaForm(request.POST or None, instance=r)
    if request.method == "POST" and form.is_valid():
        r = form.save()
        registrar_auditoria(request.user, "RECETA_EDITADA", f"Receta {r.nombre}", anterior, _txt_receta(r))
        messages.success(request, "Receta actualizada. Las inspecciones ya registradas conservan los valores con que fueron evaluadas.")
        return redirect("recetas")
    return render(request, "trefilado/form_pagina.html", {"titulo": f"Editar receta {r.nombre}", "form": form, "volver": "recetas"})


# =====================================================================================
# CU13 - Parámetros generales
# =====================================================================================
@rol_requerido(ADM)
def parametros(request):
    asegurar_parametros()
    params = list(Parametro.objects.exclude(nombre__startswith="respaldo_"))
    errores = {}
    if request.method == "POST":
        nuevos = {}
        for p in params:
            valor = request.POST.get(p.nombre, "").strip()
            if not valor.isdigit() or int(valor) < 1:
                errores[p.nombre] = "Debe ser un número entero mayor o igual a 1."
            nuevos[p.nombre] = valor
        if not errores:
            for p in params:
                if nuevos[p.nombre] != p.valor:
                    registrar_auditoria(request.user, "PARAMETRO_MODIFICADO", p.nombre, p.valor, nuevos[p.nombre])
                    p.valor = nuevos[p.nombre]
                    p.save()
            messages.success(request, "Parámetros guardados y aplicados de inmediato.")
            return redirect("parametros")
        messages.error(request, "Hay valores inválidos; no se guardó ningún cambio.")
        for p in params:
            p.valor_form = nuevos[p.nombre]
    for p in params:
        p.error = errores.get(p.nombre)
        if not hasattr(p, "valor_form"):
            p.valor_form = p.valor
    return render(request, "trefilado/parametros.html", {"params": params})


# =====================================================================================
# CU14 - Respaldos
# =====================================================================================
@rol_requerido(ADM)
def respaldos(request):
    usa_sqlite = settings.DATABASES["default"]["ENGINE"] == "django.db.backends.sqlite3"
    if not usa_sqlite:
        return render(request, "trefilado/respaldos.html", {"usa_sqlite": False, "historial": Respaldo.objects.all()[:30]})
    asegurar_parametros()
    actual = Parametro.objects.get(nombre="respaldo_frecuencia")
    form = ConfigRespaldoForm(request.POST or None, initial={"frecuencia": actual.valor})
    if request.method == "POST" and form.is_valid():
        if form.cleaned_data["frecuencia"] != actual.valor:
            registrar_auditoria(request.user, "RESPALDO_FRECUENCIA", "Frecuencia de respaldo", actual.valor, form.cleaned_data["frecuencia"])
            actual.valor = form.cleaned_data["frecuencia"]
            actual.save()
        messages.success(request, "Frecuencia de respaldo guardada.")
        return redirect("respaldos")
    return render(request, "trefilado/respaldos.html", {"form": form, "historial": Respaldo.objects.all()[:30], "usa_sqlite": True})


@rol_requerido(ADM)
@require_POST
def respaldo_ejecutar(request):
    if settings.DATABASES["default"]["ENGINE"] != "django.db.backends.sqlite3":
        messages.error(request, "Los respaldos de PostgreSQL se administran desde Supabase.")
        return redirect("respaldos")
    r = ejecutar_respaldo()
    registrar_auditoria(request.user, "RESPALDO_EJECUTADO", f"Resultado: {r.get_resultado_display()}")
    if r.resultado == Respaldo.Resultado.EXITOSO:
        messages.success(request, f"Respaldo generado: {r.archivo}")
    else:
        messages.error(request, "El respaldo falló y quedó registrado como fallido en el historial.")
    return redirect("respaldos")


# =====================================================================================
# CU15 - Lista blanca de IPs
# =====================================================================================
@rol_requerido(ADM)
def ips(request):
    return render(request, "trefilado/ips.html", {"ips": IpPermitida.objects.all()})


@rol_requerido(ADM)
def ip_nueva(request):
    form = IpForm(request.POST or None)
    if request.method == "POST" and form.is_valid():
        ip = form.save()
        registrar_auditoria(request.user, "IP_AGREGADA", ip.direccion, nuevo=ip.direccion)
        messages.success(request, "IP o subred agregada. Se aplica a los próximos inicios de sesión de Operadores.")
        return redirect("ips")
    return render(request, "trefilado/form_pagina.html", {"titulo": "Agregar IP o subred", "form": form, "volver": "ips"})


@rol_requerido(ADM)
def ip_editar(request, pk):
    ip = get_object_or_404(IpPermitida, pk=pk)
    anterior = ip.direccion
    form = IpForm(request.POST or None, instance=ip)
    if request.method == "POST" and form.is_valid():
        ip = form.save()
        registrar_auditoria(request.user, "IP_EDITADA", ip.direccion, anterior, ip.direccion)
        messages.success(request, "Lista blanca actualizada.")
        return redirect("ips")
    return render(request, "trefilado/form_pagina.html", {"titulo": "Editar IP o subred", "form": form, "volver": "ips"})


@rol_requerido(ADM)
@require_POST
def ip_eliminar(request, pk):
    ip = get_object_or_404(IpPermitida, pk=pk)
    registrar_auditoria(request.user, "IP_ELIMINADA", ip.direccion, anterior=ip.direccion)
    ip.delete()
    messages.success(request, "IP o subred eliminada de la lista blanca.")
    return redirect("ips")


# =====================================================================================
# CU16 - Dashboard de control centralizado
# =====================================================================================
@rol_requerido(ADM)
def control(request):
    ahora = timezone.now()
    ids = set()
    for s in Session.objects.filter(expire_date__gte=ahora):
        uid = s.get_decoded().get("_auth_user_id")
        if uid:
            ids.add(uid)
    ultimo = MetricaCaptura.objects.first()
    total_capturas = MetricaCaptura.objects.count()
    capturas_con_angulo = MetricaCaptura.objects.filter(exit_angle_deg__isnull=False).count()

    alertas = []
    for b in BloqueoIP.objects.all()[:8]:
        alertas.append({"fecha": b.fecha_inicio, "tipo": "Bloqueo de IP en la API", "detalle": f"{b.ip} bloqueada por {b.duracion_min} min", "bloqueo": b if b.activo else None})
    etiquetas = {"bloqueo_activado": "Cuenta bloqueada por intentos fallidos", "ip_no_autorizada": "Ingreso desde IP no autorizada"}
    for i in IntentoLogin.objects.filter(motivo__in=list(etiquetas.keys()))[:8]:
        alertas.append({"fecha": i.fecha_hora, "tipo": etiquetas[i.motivo], "detalle": f"Usuario {i.username} desde {i.ip or '-'}", "bloqueo": None})
    alertas.sort(key=lambda a: a["fecha"], reverse=True)

    ctx = {
        "conectados": len(ids),
        "total_capturas": total_capturas,
        "capturas_con_angulo": capturas_con_angulo,
        "capturas_sin_angulo": total_capturas - capturas_con_angulo,
        "ultima_captura": ultimo,
        "alertas": alertas[:10],
    }
    if request.GET.get("parcial"):
        return render(request, "trefilado/_control_contenido.html", ctx)
    return render(request, "trefilado/control.html", ctx)


@rol_requerido(ADM)
@require_POST
def bloqueo_levantar(request, pk):
    """Extra de la maqueta: permite levantar un bloqueo para seguir probando."""
    b = get_object_or_404(BloqueoIP, pk=pk)
    b.levantado = True
    b.save()
    registrar_auditoria(request.user, "BLOQUEO_IP_LEVANTADO", b.ip)
    messages.success(request, f"Bloqueo de {b.ip} levantado.")
    return redirect("control")


# =====================================================================================
# CU17 / CU18 / CU19 - API de captura
# =====================================================================================
def _rechazar(ip, motivo, mensaje, status):
    EnvioAPI.objects.create(ip_origen=ip, aceptado=False, motivo_rechazo=motivo)
    return JsonResponse({"estado": "rechazado", "motivo": mensaje}, status=status)


def _evaluar_bloqueo_api(ip):
    """CU19: bloquea la IP al superar el máximo de intentos fallidos consecutivos."""
    maximo = get_param("api_max_intentos")
    ultimo_bloqueo = BloqueoIP.objects.filter(ip=ip).order_by("-fecha_inicio").first()
    qs = EnvioAPI.objects.filter(ip_origen=ip).order_by("-fecha_hora", "-id")
    if ultimo_bloqueo:
        qs = qs.filter(fecha_hora__gt=ultimo_bloqueo.fecha_inicio)
    consecutivos = 0
    for e in qs[: maximo + 5]:
        if (not e.aceptado) and e.motivo_rechazo == "token_invalido":
            consecutivos += 1
        else:
            break
    if consecutivos > maximo:
        BloqueoIP.objects.create(ip=ip, duracion_min=get_param("api_bloqueo_min"))


@csrf_exempt
def api_inspecciones(request):
    if request.method != "POST":
        return JsonResponse({"error": "Método no permitido. Use POST."}, status=405)
    if not settings.API_TOKEN_CAPTURA:
        return JsonResponse({"error": "API de captura no configurada."}, status=503)
    ip = obtener_ip(request)

    # CU19 A3: IP bloqueada -> se rechaza sin evaluar credenciales
    if any(b.activo for b in BloqueoIP.objects.filter(ip=ip)):
        return _rechazar(ip, "ip_bloqueada", "IP bloqueada temporalmente", 403)

    # CU17 paso 2: validar token
    cabecera = request.headers.get("Authorization", "")
    token = cabecera[7:].strip() if cabecera.startswith("Bearer ") else ""
    if not token or not secrets.compare_digest(token.encode(), settings.API_TOKEN_CAPTURA.encode()):
        EnvioAPI.objects.create(ip_origen=ip, aceptado=False, motivo_rechazo="token_invalido")
        _evaluar_bloqueo_api(ip)
        return JsonResponse({"estado": "rechazado", "motivo": "Token ausente o inválido"}, status=401)

    # CU17 A3: datos malformados
    try:
        datos = json.loads(request.body.decode("utf-8"))
        angulo = float(datos["angulo"])
        ident_lote = str(datos["lote"]).strip()
        if not ident_lote:
            raise ValueError
        fecha_dato = timezone.now()
        if datos.get("fecha_hora"):
            fecha_dato = parse_datetime(str(datos["fecha_hora"]))
            if fecha_dato is None:
                raise ValueError
            if timezone.is_naive(fecha_dato):
                fecha_dato = timezone.make_aware(fecha_dato)
    except (ValueError, KeyError, TypeError, UnicodeDecodeError):
        return _rechazar(ip, "datos_malformados", "Datos malformados", 400)

    # CU17 A2: receta o lote inexistente
    lote = Lote.objects.filter(identificador=ident_lote, estado=Lote.Estado.ABIERTO).first()
    if lote is None:
        return _rechazar(ip, "lote_inexistente", "Lote inexistente o cerrado", 422)
    receta = None
    rid = datos.get("receta")
    if rid not in (None, ""):
        try:
            receta = Receta.objects.filter(pk=int(rid)).first()
        except (ValueError, TypeError):
            receta = None
        if receta is None:
            return _rechazar(ip, "receta_inexistente", "Receta inexistente", 422)

    # CU18: clasificar y persistir
    with transaction.atomic():
        estado = clasificar(angulo, receta)
        activa = receta is not None and receta.vigente
        insp = Inspeccion.objects.create(
            lote=lote, receta=receta, angulo=angulo, estado=estado,
            limite_min=receta.limite_min if activa else None,
            limite_max=receta.limite_max if activa else None,
            fecha_hora_dato=fecha_dato, fecha_hora_recepcion=timezone.now(),
        )
        if estado == Inspeccion.Estado.RECHAZADO:
            Alerta.objects.create(inspeccion=insp)
        EnvioAPI.objects.create(inspeccion=insp, ip_origen=ip, aceptado=True)
    return JsonResponse(
        {"estado": "aceptado", "id_inspeccion": insp.pk, "clasificacion": estado, "recibido": insp.fecha_hora_recepcion.isoformat()},
        status=201,
    )
