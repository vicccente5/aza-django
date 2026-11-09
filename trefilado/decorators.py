from functools import wraps

from django.contrib import messages
from django.contrib.auth import logout
from django.shortcuts import redirect


def rol_requerido(*roles):
    """Exige sesión iniciada y, si se indican roles, que el usuario tenga uno de ellos."""

    def decorador(vista):
        @wraps(vista)
        def envoltura(request, *args, **kwargs):
            if not request.user.is_authenticated:
                return redirect(f"/login/?next={request.path}")
            if request.session.get("auth_version") != str(request.user.version_seguridad):
                logout(request)
                messages.error(request, "Su sesión cambió. Inicie sesión nuevamente.")
                return redirect("login")
            if request.user.rol == "ADMINISTRADOR" and not request.session.get("otp_verificado"):
                logout(request)
                messages.error(request, "Debe iniciar sesión de nuevo y verificar su código para acceder como Administrador.")
                return redirect("login")
            if request.session.get("clave_vencida") and request.resolver_match.url_name != "cambiar_clave":
                return redirect("cambiar_clave")
            if roles and request.user.rol not in roles:
                messages.error(request, "Acceso denegado: su rol no tiene permisos para esta sección.")
                return redirect("home")
            return vista(request, *args, **kwargs)

        return envoltura

    return decorador
