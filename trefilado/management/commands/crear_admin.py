"""Crea el primer administrador con datos reales y contraseña introducida en privado."""

import getpass
import sys
import warnings

from django.core.exceptions import ValidationError
from django.core.management.base import BaseCommand, CommandError
from django.core.validators import validate_email

from trefilado.models import Usuario
from trefilado.services import validar_politica_clave


class Command(BaseCommand):
    help = "Crea un administrador de AZA mediante preguntas interactivas."

    def handle(self, *args, **options):
        if not sys.stdin.isatty():
            raise CommandError("Ejecute crear_admin en una terminal interactiva para ocultar la contraseña.")

        username = Usuario.normalize_username(input("Nombre de usuario: ").strip())
        nombre = input("Nombre real: ").strip()
        apellido = input("Apellido real: ").strip()
        email = input("Correo real para recibir el OTP: ").strip()
        if not all((username, nombre, apellido, email)):
            raise CommandError("Todos los campos son obligatorios.")
        try:
            validate_email(email)
        except ValidationError as exc:
            raise CommandError("El correo no es válido.") from exc
        if Usuario.objects.filter(username__iexact=username).exists():
            raise CommandError("Ese nombre de usuario ya existe.")

        try:
            with warnings.catch_warnings():
                warnings.simplefilter("error", getpass.GetPassWarning)
                password = getpass.getpass("Contraseña: ")
                confirmacion = getpass.getpass("Repita la contraseña: ")
        except getpass.GetPassWarning:
            raise CommandError("No fue posible ocultar la contraseña en esta terminal.") from None
        if password != confirmacion:
            raise CommandError("Las contraseñas no coinciden.")
        errores = validar_politica_clave(password)
        if errores:
            raise CommandError(" ".join(errores))

        usuario = Usuario(
            username=username,
            first_name=nombre,
            last_name=apellido,
            email=email,
            rol=Usuario.Rol.ADMINISTRADOR,
        )
        usuario.set_password(password)
        try:
            usuario.full_clean()
        except ValidationError as exc:
            raise CommandError(str(exc)) from exc
        usuario.save()
        self.stdout.write(self.style.SUCCESS(f"Administrador {username} creado."))
