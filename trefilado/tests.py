import getpass
import json
import os
import runpy
import warnings
from base64 import b64encode
from datetime import datetime, timedelta
from io import StringIO
from pathlib import Path
from smtplib import SMTPException
from tempfile import TemporaryDirectory
from unittest.mock import MagicMock, call, patch

from django.contrib.auth import SESSION_KEY
from django.contrib.sessions.models import Session
from django.core import mail
from django.core.exceptions import ImproperlyConfigured
from django.core.management import call_command
from django.core.management.base import CommandError
from django.db import IntegrityError, OperationalError, connection
from django.test import Client, SimpleTestCase, TestCase, override_settings
from django.test.utils import CaptureQueriesContext
from django.urls import reverse

from aza_project import settings as proyecto_settings
from aza_project.test_runner import SQLiteTestRunner
from . import views
from .models import MetricaCaptura, TokenRecuperacion, Usuario
from .services import cambiar_clave


def captura(angulo):
    return {
        "total_frames": 104,
        "scene": "oscura",
        "mean_background": 4.51,
        "first_exit_frame": 88,
        "exit_confidence": "ALTA",
        "circle_cx": 385.8,
        "circle_cy": 193.8,
        "circle_radius": 145.0,
        "circle_method": "promedio_temporal",
        "circle_support_frames": 3,
        "angle_frame": 88 if angulo is not None else None,
        "exit_angle_deg": angulo,
        "angle_confidence": "ALTA" if angulo is not None else "SIN_SENAL",
        "diagnostic_path": "/equipo-origen/resultado_analisis.png",
    }


class ImportacionMetricasTests(TestCase):
    def _guardar(self, carpeta, numero, datos):
        momento = datetime(2026, 7, 14, 13, 44) + timedelta(seconds=numero)
        nombre = f"{momento:%Y-%m-%d}_Trigger_{numero:04d}_{momento:%Y%m%d_%H%M%S}_metricas.json"
        (Path(carpeta) / nombre).write_text(json.dumps(datos), encoding="utf-8")
        return nombre

    def test_importacion_repetible_y_dashboard_sin_clasificacion_inventada(self):
        with TemporaryDirectory() as carpeta:
            nombre = self._guardar(carpeta, 1, captura(313.7))
            self._guardar(carpeta, 2, captura(None))
            call_command("importar_metricas", source=Path(carpeta), stdout=StringIO())
            self.assertEqual(MetricaCaptura.objects.count(), 2)

            actualizado = captura(320.0)
            self._guardar(carpeta, 1, actualizado)
            call_command("importar_metricas", source=Path(carpeta), stdout=StringIO())
            self.assertEqual(MetricaCaptura.objects.count(), 2)
            self.assertEqual(MetricaCaptura.objects.get(archivo_origen=nombre).exit_angle_deg, 320.0)

        supervisor = Usuario.objects.create_user(username="supervisor", password="Clave1234", rol=Usuario.Rol.SUPERVISOR)
        respuesta = self.client.post(reverse("login"), {"username": supervisor.username, "password": "Clave1234"})
        self.assertRedirects(respuesta, reverse("home"), fetch_redirect_response=False)
        respuesta = self.client.get("/supervisor/dashboard/")
        self.assertEqual(respuesta.status_code, 200)
        self.assertEqual((respuesta.context["total"], respuesta.context["con_angulo"], respuesta.context["sin_angulo"]), (2, 1, 1))
        respuesta = self.client.get("/supervisor/historial/?angulo=sin")
        self.assertEqual(respuesta.context["pagina"].paginator.count, 1)

    def test_json_invalido_no_importa_ninguna_captura(self):
        with TemporaryDirectory() as carpeta:
            self._guardar(carpeta, 1, captura(313.7))
            invalido = captura(None)
            del invalido["total_frames"]
            self._guardar(carpeta, 2, invalido)
            with self.assertRaises(CommandError):
                call_command("importar_metricas", source=Path(carpeta), stdout=StringIO())
        self.assertEqual(MetricaCaptura.objects.count(), 0)

    def test_importacion_mixta_conserva_identidad_y_agrupa_escrituras(self):
        with TemporaryDirectory() as carpeta:
            nombre = self._guardar(carpeta, 1, captura(313.7))
            call_command("importar_metricas", source=Path(carpeta), stdout=StringIO())
            original = MetricaCaptura.objects.get(archivo_origen=nombre)

            self._guardar(carpeta, 1, captura(None))
            for numero in range(2, 121):
                self._guardar(carpeta, numero, captura(320.0))
            salida = StringIO()
            with CaptureQueriesContext(connection) as consultas:
                call_command("importar_metricas", source=Path(carpeta), stdout=salida)

        self.assertIn("120 (119 nuevas, 1 actualizadas)", salida.getvalue())
        self.assertEqual(MetricaCaptura.objects.count(), 120)
        original.refresh_from_db()
        self.assertIsNone(original.exit_angle_deg)
        escrituras = sum(consulta["sql"].startswith("INSERT INTO") for consulta in consultas)
        self.assertLessEqual(escrituras, 4)

    @patch("trefilado.management.commands.importar_metricas.TAMANO_LOTE", 2)
    def test_fallo_en_segundo_lote_revierte_las_escrituras_del_primero(self):
        with TemporaryDirectory() as carpeta:
            nombre = self._guardar(carpeta, 1, captura(313.7))
            call_command("importar_metricas", source=Path(carpeta), stdout=StringIO())
            self._guardar(carpeta, 1, captura(320.0))
            self._guardar(carpeta, 2, captura(None))
            ultimo = self._guardar(carpeta, 3, captura(318.0))
            guardar_lote = MetricaCaptura.objects.bulk_create

            def fallar_ultimo_lote(registros, **opciones):
                if registros[0].archivo_origen == ultimo:
                    raise IntegrityError("fallo simulado en el segundo lote")
                return guardar_lote(registros, **opciones)

            with patch.object(MetricaCaptura.objects, "bulk_create", side_effect=fallar_ultimo_lote):
                with self.assertRaises(IntegrityError):
                    call_command("importar_metricas", source=Path(carpeta), stdout=StringIO())

        self.assertEqual(MetricaCaptura.objects.count(), 1)
        self.assertEqual(MetricaCaptura.objects.get(archivo_origen=nombre).exit_angle_deg, 313.7)


class AdministradorInicialTests(TestCase):
    @patch("trefilado.management.commands.crear_admin.sys.stdin")
    @patch("trefilado.management.commands.crear_admin.getpass.getpass", side_effect=["ClaveSegura9", "ClaveSegura9"])
    @patch("builtins.input", side_effect=["azadmin", "Ana", "Díaz", "ana@example.org"])
    def test_crear_admin_pide_datos_y_no_guarda_clave_en_texto_plano(self, _input, _getpass, stdin):
        stdin.isatty.return_value = True
        call_command("crear_admin", stdout=StringIO())
        usuario = Usuario.objects.get(username="azadmin")
        self.assertEqual(usuario.rol, Usuario.Rol.ADMINISTRADOR)
        self.assertEqual((usuario.first_name, usuario.last_name, usuario.email), ("Ana", "Díaz", "ana@example.org"))
        self.assertTrue(usuario.check_password("ClaveSegura9"))
        self.assertNotEqual(usuario.password, "ClaveSegura9")

    @patch("trefilado.management.commands.crear_admin.sys.stdin")
    @patch("builtins.input", side_effect=["azadmin", "Ana", "Díaz", "ana@example.org"])
    def test_crear_admin_se_detiene_si_la_terminal_no_puede_ocultar_clave(self, _input, stdin):
        stdin.isatty.return_value = True

        def entrada_sin_ocultar(_mensaje):
            warnings.warn("La terminal no puede ocultar la entrada.", getpass.GetPassWarning)
            self.fail("El comando permitió la lectura de contraseña sin ocultar la entrada.")

        with patch("getpass.getpass", side_effect=entrada_sin_ocultar):
            with self.assertRaisesMessage(CommandError, "No fue posible ocultar la contraseña"):
                call_command("crear_admin", stdout=StringIO())
        self.assertFalse(Usuario.objects.exists())


@override_settings(EMAIL_BACKEND="django.core.mail.backends.locmem.EmailBackend", MOSTRAR_CODIGOS_EN_PANTALLA=False)
class AccesoAdministradorTests(TestCase):
    def _crear_usuario(self, rol):
        return Usuario.objects.create_user(
            username="usuario_aza", password="ClaveSegura9", email="usuario@example.org", rol=rol,
        )

    def _login(self):
        return self.client.post(reverse("login"), {"username": "usuario_aza", "password": "ClaveSegura9"})

    @patch("trefilado.views.secrets.randbelow", return_value=51024)
    def test_administrador_accede_al_control_despues_del_codigo_enviado(self, _aleatorio):
        usuario = self._crear_usuario(Usuario.Rol.ADMINISTRADOR)
        self.assertRedirects(self._login(), reverse("login_otp"))
        self.assertNotIn(SESSION_KEY, self.client.session)
        self.assertEqual(len(mail.outbox), 1)
        self.assertEqual(mail.outbox[0].to, [usuario.email])
        self.assertIn("051024", mail.outbox[0].body)

        respuesta = self.client.post(reverse("login_otp"), {"codigo": "051024"})
        self.assertRedirects(respuesta, reverse("home"), fetch_redirect_response=False)
        self.assertEqual(self.client.session[SESSION_KEY], str(usuario.pk))
        self.assertNotIn("pre_auth", self.client.session)
        self.assertEqual(self.client.get(reverse("control")).status_code, 200)

    def test_supervisor_promovido_debe_iniciar_sesion_con_otp(self):
        usuario = self._crear_usuario(Usuario.Rol.SUPERVISOR)
        self.assertRedirects(self._login(), reverse("home"), fetch_redirect_response=False)
        self.assertEqual(self.client.session[SESSION_KEY], str(usuario.pk))

        Usuario.objects.filter(pk=usuario.pk).update(rol=Usuario.Rol.ADMINISTRADOR)
        self.assertRedirects(self.client.get(reverse("control")), reverse("login"))
        self.assertNotIn(SESSION_KEY, self.client.session)

    @patch("trefilado.views.enviar_correo", side_effect=SMTPException("falló el proveedor"))
    def test_fallo_del_correo_no_autentica_ni_abre_desafio(self, _correo):
        self._crear_usuario(Usuario.Rol.ADMINISTRADOR)
        self.assertContains(self._login(), "No se pudo enviar el código de verificación")
        self.assertNotIn("pre_auth", self.client.session)
        self.assertNotIn(SESSION_KEY, self.client.session)

    def test_fallo_del_reenvio_descarta_codigo_previo(self):
        self._crear_usuario(Usuario.Rol.ADMINISTRADOR)
        self.assertRedirects(self._login(), reverse("login_otp"))
        self.assertIn("pre_auth", self.client.session)

        with patch("trefilado.views.enviar_correo", side_effect=SMTPException("falló el proveedor")):
            self.assertRedirects(self.client.post(reverse("login_otp"), {"reenviar": "1"}), reverse("login"))
        self.assertNotIn("pre_auth", self.client.session)
        self.assertNotIn(SESSION_KEY, self.client.session)


@override_settings(
    EMAIL_BACKEND="django.core.mail.backends.locmem.EmailBackend",
    MOSTRAR_CODIGOS_EN_PANTALLA=False,
    PUBLIC_BASE_URL="https://portal.example.org",
)
class RecuperacionClaveTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.usuario = Usuario.objects.create_user(
            username="usuario_aza", password="ClaveOriginal9", email="usuario@example.org",
        )

    def _solicitar_recuperacion(self):
        respuesta = self.client.post(reverse("recuperar"), {"identificador": self.usuario.email})
        self.assertRedirects(respuesta, reverse("recuperar"))

    def _obtener_enlace(self):
        self._solicitar_recuperacion()
        token = TokenRecuperacion.objects.get(usuario=self.usuario)
        ruta = reverse("recuperar_confirmar", args=[token.token])
        self.assertEqual(len(mail.outbox), 1)
        self.assertEqual(mail.outbox[0].to, [self.usuario.email])
        self.assertIn(f"https://portal.example.org{ruta}", mail.outbox[0].body)
        return token, ruta

    def _restablecer(self, ruta, clave):
        return self.client.post(ruta, {"password1": clave, "password2": clave})

    def test_cambiar_clave_invalida_enlace_pendiente(self):
        token, ruta = self._obtener_enlace()
        self.usuario.set_password("ClaveCambiada8")
        self.usuario.save(update_fields=["password"])

        self.assertRedirects(self._restablecer(ruta, "ClaveRestablecida7"), reverse("recuperar"))
        self.usuario.refresh_from_db()
        token.refresh_from_db()
        self.assertTrue(self.usuario.check_password("ClaveCambiada8"))
        self.assertFalse(token.usado)

    def test_enlace_solo_permite_restablecer_la_clave_una_vez(self):
        token, ruta = self._obtener_enlace()
        self.assertRedirects(self._restablecer(ruta, "ClaveRestablecida7"), reverse("login"))
        token.refresh_from_db()
        self.assertTrue(token.usado)

        self.assertRedirects(self._restablecer(ruta, "ClaveRepetida6"), reverse("recuperar"))
        self.usuario.refresh_from_db()
        self.assertTrue(self.usuario.check_password("ClaveRestablecida7"))

    @patch("trefilado.services.send_mail", side_effect=SMTPException("falló el proveedor"))
    def test_fallo_del_correo_elimina_el_token(self, correo):
        self._solicitar_recuperacion()
        correo.assert_called_once()
        self.assertFalse(TokenRecuperacion.objects.filter(usuario=self.usuario).exists())


@override_settings(EMAIL_BACKEND="django.core.mail.backends.locmem.EmailBackend", MOSTRAR_CODIGOS_EN_PANTALLA=False)
class InvalidacionCredencialesTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.usuario = Usuario.objects.create_user(
            username="admin_objetivo", password="ClaveOriginal9", email="objetivo@example.org", rol=Usuario.Rol.ADMINISTRADOR,
        )
        cls.administrador = Usuario.objects.create_user(
            username="admin_gestion", password="ClaveGestion8", email="gestion@example.org", rol=Usuario.Rol.ADMINISTRADOR,
        )

    def setUp(self):
        self.gestion = Client()
        with patch("trefilado.views.secrets.randbelow", return_value=31294):
            respuesta = self.gestion.post(reverse("login"), {
                "username": self.administrador.username, "password": "ClaveGestion8",
            })
        self.assertRedirects(respuesta, reverse("login_otp"))
        respuesta = self.gestion.post(reverse("login_otp"), {"codigo": "031294"})
        self.assertRedirects(respuesta, reverse("home"), fetch_redirect_response=False)

    def _iniciar_desafio_otp(self):
        with patch("trefilado.views.secrets.randbelow", return_value=51024):
            respuesta = self.client.post(reverse("login"), {
                "username": self.usuario.username, "password": "ClaveOriginal9",
            })
        self.assertRedirects(respuesta, reverse("login_otp"))
        self.assertIn("pre_auth", self.client.session)
        return self.client.session.session_key

    def _crear_credenciales_pendientes(self):
        sesion_otp = self._iniciar_desafio_otp()
        respuesta = self.client.post(reverse("recuperar"), {"identificador": self.usuario.email})
        self.assertRedirects(respuesta, reverse("recuperar"))
        token = TokenRecuperacion.objects.get(usuario=self.usuario)
        ruta = reverse("recuperar_confirmar", args=[token.token])
        self.assertEqual(self.client.get(ruta).status_code, 200)
        return sesion_otp, token, ruta

    def _comprobar_invalidacion(self, sesion_otp, token, ruta, clave_vigente="ClaveOriginal9"):
        self.assertFalse(Session.objects.filter(session_key=sesion_otp).exists())
        token.refresh_from_db()
        self.assertTrue(token.usado)
        respuesta = self.client.post(reverse("login_otp"), {"codigo": "051024"})
        self.assertRedirects(respuesta, reverse("login"))
        self.assertNotIn(SESSION_KEY, self.client.session)
        respuesta = self.client.post(ruta, {"password1": "ClaveRestablecida7", "password2": "ClaveRestablecida7"})
        self.assertRedirects(respuesta, reverse("recuperar"))
        self.usuario.refresh_from_db()
        self.assertTrue(self.usuario.check_password(clave_vigente))

    def _editar_usuario(self, **cambios):
        datos = {"username": self.usuario.username, "email": self.usuario.email, "rol": self.usuario.rol}
        datos.update(cambios)
        respuesta = self.gestion.post(reverse("usuario_editar", args=[self.usuario.pk]), datos)
        self.assertRedirects(respuesta, reverse("usuarios"), fetch_redirect_response=False)
        self.usuario.refresh_from_db()

    def _editar_correo(self):
        self._editar_usuario(email="nuevo@example.org")
        self.assertEqual(self.usuario.email, "nuevo@example.org")

    def test_editar_correo_invalida_otp_y_enlace_de_recuperacion(self):
        sesion_otp, token, ruta = self._crear_credenciales_pendientes()
        self._editar_correo()
        self._comprobar_invalidacion(sesion_otp, token, ruta)

    def test_editar_solo_clave_renueva_version_de_seguridad(self):
        sesion_otp, token, ruta = self._crear_credenciales_pendientes()
        version_anterior = self.usuario.version_seguridad
        self._editar_usuario(password="ClaveEditada8")
        self.assertNotEqual(self.usuario.version_seguridad, version_anterior)
        self._comprobar_invalidacion(sesion_otp, token, ruta, clave_vigente="ClaveEditada8")

    def test_instancia_obsoleta_no_cambia_clave_de_cuenta_activa(self):
        obsoleta = Usuario.objects.get(pk=self.usuario.pk)
        self._editar_correo()
        version_vigente = self.usuario.version_seguridad
        self.assertTrue(self.usuario.is_active)

        self.assertFalse(cambiar_clave(obsoleta, "ClaveObsoleta7"))
        self.usuario.refresh_from_db()
        self.assertEqual(self.usuario.version_seguridad, version_vigente)
        self.assertEqual(self.usuario.email, "nuevo@example.org")
        self.assertTrue(self.usuario.check_password("ClaveOriginal9"))

    def test_edicion_obsoleta_no_restaura_rol_correo_ni_estado(self):
        obsoleta = Usuario.objects.get(pk=self.usuario.pk)
        self._editar_usuario(rol=Usuario.Rol.SUPERVISOR, email="nuevo@example.org")
        estado = reverse("usuario_estado", args=[self.usuario.pk])
        self.assertRedirects(self.gestion.post(estado), reverse("usuarios"))
        self.usuario.refresh_from_db()
        version_vigente = self.usuario.version_seguridad

        datos_obsoletos = {"rol": obsoleta.rol, "email": obsoleta.email, "password": "ClaveObsoleta7"}
        with patch.object(views, "get_object_or_404", return_value=obsoleta):
            self._editar_usuario(**datos_obsoletos)

        self.assertContains(self.gestion.get(reverse("usuarios")), "La cuenta cambió durante la edición")
        self.assertEqual(self.usuario.version_seguridad, version_vigente)
        self.assertEqual(self.usuario.rol, Usuario.Rol.SUPERVISOR)
        self.assertEqual(self.usuario.email, "nuevo@example.org")
        self.assertFalse(self.usuario.is_active)
        self.assertTrue(self.usuario.check_password("ClaveOriginal9"))

    def test_rechaza_sesion_otp_finalizada_con_version_anterior_al_cambio_de_correo(self):
        self._iniciar_desafio_otp()
        version_anterior = self.usuario.version_seguridad
        finalizar_login = views._finalizar_login

        def cambiar_correo_antes_de_guardar_sesion(request, usuario, ip, otp_verificado=False):
            self._editar_correo()
            return finalizar_login(request, usuario, ip, otp_verificado=otp_verificado)

        with patch.object(views, "_finalizar_login", side_effect=cambiar_correo_antes_de_guardar_sesion):
            respuesta = self.client.post(reverse("login_otp"), {"codigo": "051024"})
        self.assertRedirects(respuesta, reverse("home"), fetch_redirect_response=False)
        self.assertNotEqual(self.usuario.version_seguridad, version_anterior)
        self.assertEqual(self.client.session["auth_version"], str(version_anterior))
        self.assertEqual(self.client.session[SESSION_KEY], str(self.usuario.pk))
        self.assertTrue(self.client.session["otp_verificado"])

        self.assertRedirects(self.client.get(reverse("control")), reverse("login"))
        self.assertNotIn(SESSION_KEY, self.client.session)

    def test_desactivar_y_reactivar_no_rehabilita_otp_ni_enlace_previo(self):
        sesion_otp, token, ruta = self._crear_credenciales_pendientes()
        estado = reverse("usuario_estado", args=[self.usuario.pk])
        self.assertRedirects(self.gestion.post(estado), reverse("usuarios"))
        self.usuario.refresh_from_db()
        self.assertFalse(self.usuario.is_active)
        self.assertFalse(Session.objects.filter(session_key=sesion_otp).exists())
        token.refresh_from_db()
        self.assertTrue(token.usado)

        self.assertRedirects(self.gestion.post(estado), reverse("usuarios"))
        self.usuario.refresh_from_db()
        self.assertTrue(self.usuario.is_active)
        self._comprobar_invalidacion(sesion_otp, token, ruta)


class ConfiguracionProduccionTests(SimpleTestCase):
    url_postgresql = "postgresql://usuario:prueba@pooler.example.invalid:5432/postgres"
    clave_produccion = b64encode(bytes(range(32))).decode("ascii")

    def _cargar_settings(self, entorno, comando="runserver"):
        with (
            patch.dict(os.environ, entorno, clear=True),
            patch("sys.argv", ["manage.py", comando]),
            patch("dotenv.load_dotenv"),
            patch("django.db.backends.signals.connection_created.connect"),
        ):
            return runpy.run_path(proyecto_settings.__file__)

    def test_arranque_sin_url_postgresql_falla(self):
        with self.assertRaisesMessage(ImproperlyConfigured, "Configure DATABASE_URL"):
            self._cargar_settings({})

    def test_sqlite_local_explicito_sin_url(self):
        config = self._cargar_settings({"DEBUG": "1", "AZA_SQLITE_LOCAL": "1"})
        self.assertEqual(config["DATABASES"]["default"]["ENGINE"], "django.db.backends.sqlite3")
        self.assertEqual(config["DATABASES"]["default"]["NAME"], proyecto_settings.BASE_DIR / "db.sqlite3")
        self.assertTrue(config["SECRET_KEY"])

    def test_sqlite_local_y_url_postgresql_son_incompatibles(self):
        with self.assertRaisesMessage(ImproperlyConfigured, "AZA_SQLITE_LOCAL=1 y DATABASE_URL no pueden configurarse a la vez"):
            self._cargar_settings({"DEBUG": "1", "AZA_SQLITE_LOCAL": "1", "DATABASE_URL": self.url_postgresql})

    def test_produccion_rechaza_sqlite_local(self):
        with self.assertRaisesMessage(ImproperlyConfigured, "AZA_SQLITE_LOCAL solo se permite con DEBUG=1"):
            self._cargar_settings({"DEBUG": "0", "SECRET_KEY": self.clave_produccion, "AZA_SQLITE_LOCAL": "1"})

    def test_comando_test_ignora_url_y_usa_sqlite_en_memoria(self):
        entorno = {"DEBUG": "0", "AZA_SQLITE_LOCAL": "1", "DATABASE_URL": self.url_postgresql}
        config = self._cargar_settings(entorno, comando="test")
        self.assertEqual(config["DATABASES"]["default"], {"ENGINE": "django.db.backends.sqlite3", "NAME": ":memory:"})

    def test_url_postgresql_decodifica_clave_y_exige_ssl(self):
        db = proyecto_settings._postgres_database(
            "postgresql://usuario:Clave%40%23%25@pooler.example.invalid:5432/aza%2Ddatos?sslmode=disable",
            "aza",
        )
        self.assertEqual(db["ENGINE"], "django.db.backends.postgresql")
        self.assertEqual(db["NAME"], "aza-datos")
        self.assertEqual(db["PASSWORD"], "Clave@#%")
        self.assertEqual(db["PORT"], 5432)
        self.assertEqual(db["OPTIONS"]["sslmode"], "require")

    def test_rechaza_esquema_public_y_pooler_de_transacciones(self):
        url = "postgresql://usuario:prueba@pooler.example.invalid:{puerto}/postgres"
        with self.assertRaisesMessage(ImproperlyConfigured, "DB_SCHEMA=aza"):
            proyecto_settings._postgres_database(url.format(puerto=5432), "public")
        with self.assertRaisesMessage(ImproperlyConfigured, "Session pooler"):
            proyecto_settings._postgres_database(url.format(puerto=6543), "aza")

    def test_conexion_postgresql_fija_aza_y_se_cierra_si_no_esta_disponible(self):
        conexion = MagicMock(alias="default", vendor="postgresql")
        cursor = conexion.cursor.return_value.__enter__.return_value
        cursor.fetchone.return_value = (None,)
        with self.assertRaisesMessage(ImproperlyConfigured, "El esquema aza no existe"):
            proyecto_settings._aislar_esquema_postgresql(None, conexion)
        self.assertEqual(cursor.execute.call_args_list, [
            call("SET search_path TO aza"),
            call("SELECT pg_catalog.current_schema()"),
        ])
        conexion.close.assert_called_once_with()

    def test_produccion_exige_smtp_configurado(self):
        with self.assertRaisesMessage(ImproperlyConfigured, "Configure EMAIL_HOST"):
            self._cargar_settings({"DEBUG": "0", "SECRET_KEY": self.clave_produccion, "DATABASE_URL": self.url_postgresql})

    def test_produccion_rechaza_secret_key_ausente_o_trivial_sin_imprimirla(self):
        casos = {
            "ausente": None,
            "vacia": "",
            "desarrollo": "aza-clave-local-cambiar-en-produccion",
            "repetitiva": "z" * 64,
            "insegura": f"django-insecure-{self.clave_produccion}",
            "espacio": f"{self.clave_produccion} ",
        }
        for caso, clave in casos.items():
            entorno = {"DEBUG": "0", "DATABASE_URL": self.url_postgresql}
            if clave is not None:
                entorno["SECRET_KEY"] = clave
            with self.subTest(caso=caso):
                with self.assertRaisesMessage(ImproperlyConfigured, "Configure SECRET_KEY") as error:
                    self._cargar_settings(entorno)
                if clave:
                    self.assertNotIn(clave, str(error.exception))

    def test_produccion_usa_smtp_con_starttls(self):
        entorno = {
            "DEBUG": "0",
            "SECRET_KEY": self.clave_produccion,
            "DATABASE_URL": self.url_postgresql,
            "EMAIL_HOST": "smtp.example.invalid",
            "EMAIL_HOST_USER": "usuario",
            "EMAIL_HOST_PASSWORD": "prueba",
            "DEFAULT_FROM_EMAIL": "aza@example.org",
            "EMAIL_PORT": "2525",
        }
        configuracion = self._cargar_settings(entorno)
        self.assertEqual(configuracion["DATABASES"]["default"]["ENGINE"], "django.db.backends.postgresql")
        self.assertEqual(configuracion["SECRET_KEY"], self.clave_produccion)
        self.assertEqual(configuracion["EMAIL_BACKEND"], "django.core.mail.backends.smtp.EmailBackend")
        self.assertEqual(configuracion["EMAIL_PORT"], 2525)
        self.assertTrue(configuracion["EMAIL_USE_TLS"])

    def test_produccion_acepta_solo_hosts_configurados_y_prefiere_el_origen_canonico(self):
        entorno = {
            "DEBUG": "0",
            "SECRET_KEY": self.clave_produccion,
            "DATABASE_URL": self.url_postgresql,
            "EMAIL_HOST": "smtp.example.invalid",
            "EMAIL_HOST_USER": "usuario",
            "EMAIL_HOST_PASSWORD": "prueba",
            "DEFAULT_FROM_EMAIL": "aza@example.org",
            "ALLOWED_HOSTS": "interfaz.example.org",
            "RENDER_EXTERNAL_URL": "https://aza.example.org",
            "PUBLIC_BASE_URL": "https://portal.example.org/",
        }
        configuracion = self._cargar_settings(entorno)
        self.assertEqual(configuracion["ALLOWED_HOSTS"], ["interfaz.example.org", "aza.example.org", "portal.example.org"])
        self.assertEqual(configuracion["PUBLIC_BASE_URL"], "https://portal.example.org")

    def test_produccion_rechaza_origen_canonico_http(self):
        entorno = {"DEBUG": "0", "SECRET_KEY": self.clave_produccion, "PUBLIC_BASE_URL": "http://portal.example.org"}
        with self.assertRaisesMessage(ImproperlyConfigured, "En producción requiere HTTPS"):
            self._cargar_settings(entorno)


class SQLiteTestRunnerTests(SimpleTestCase):
    @patch("aza_project.test_runner.connections")
    @patch("django.test.runner.DiscoverRunner.run_tests")
    def test_call_command_rechaza_postgresql_antes_de_ejecutar_pruebas(self, ejecutar, conexiones):
        conexiones.settings = {"default": {"ENGINE": "django.db.backends.postgresql"}}
        with self.assertRaisesMessage(CommandError, "Las pruebas requieren SQLite"):
            call_command("test", verbosity=0)
        ejecutar.assert_not_called()

    @patch("aza_project.test_runner.connections")
    @patch("django.test.runner.DiscoverRunner.setup_databases")
    def test_preparacion_directa_rechaza_otro_alias_postgresql(self, preparar, conexiones):
        conexiones.settings = {
            "default": {"ENGINE": "django.db.backends.sqlite3"},
            "postgresql": {"ENGINE": "django.db.backends.postgresql"},
        }
        with self.assertRaisesMessage(CommandError, "Las pruebas requieren SQLite"):
            SQLiteTestRunner().setup_databases()
        preparar.assert_not_called()


class VerificarBaseDatosTests(SimpleTestCase):
    def test_rechaza_sqlite(self):
        salida = StringIO()
        with self.assertRaisesMessage(CommandError, "AZA requiere PostgreSQL"):
            call_command("verificar_base_datos", stdout=salida)
        self.assertEqual(salida.getvalue().splitlines(), ["Motor: sqlite", "Esquema: no aplica"])

    @patch("trefilado.management.commands.verificar_base_datos.connection", vendor="postgresql")
    def test_rechaza_fallback_a_public(self, conexion):
        conexion.cursor.return_value.__enter__.return_value.fetchone.return_value = ("aza", ["aza", "public"])
        with self.assertRaisesMessage(CommandError, "debe usar únicamente el esquema aza"):
            call_command("verificar_base_datos", stdout=StringIO())

    @patch("trefilado.management.commands.verificar_base_datos.connection", vendor="postgresql")
    def test_error_de_conexion_omite_detalles_del_driver(self, conexion):
        conexion.cursor.side_effect = OperationalError("detalle-sensible-de-prueba")
        with self.assertRaisesMessage(CommandError, "No se pudo verificar la conexión") as error:
            call_command("verificar_base_datos", stdout=StringIO())
        self.assertNotIn("detalle-sensible-de-prueba", str(error.exception))

    @patch("trefilado.management.commands.verificar_base_datos.connection", vendor="postgresql")
    def test_muestra_totales_del_esquema_aza(self, conexion):
        conexion.cursor.return_value.__enter__.return_value.fetchone.return_value = ("aza", ["aza"])
        conexion.settings_dict = {
            "HOST": "aws-1-us-east-2.pooler.supabase.com",
            "USER": "usuario.abcdefghijklmnopqrst",
            "PASSWORD": "detalle-sensible-de-prueba",
        }
        salida = StringIO()
        with (
            patch.object(MetricaCaptura.objects, "aggregate", return_value={"total": 5, "con_angulo": 2}),
            patch.object(Usuario.objects, "count", return_value=3),
        ):
            call_command("verificar_base_datos", stdout=salida)
        self.assertEqual(salida.getvalue().splitlines(), [
            "Motor: postgresql", "Esquema: aza", "Proyecto Supabase: abcdefghijklmnopqrst",
            "Capturas: 5 (2 con ángulo)", "Usuarios: 3",
        ])

    @patch("trefilado.management.commands.verificar_base_datos.connection", vendor="postgresql")
    def test_fuera_del_pooler_no_infiere_proyecto_del_usuario(self, conexion):
        conexion.cursor.return_value.__enter__.return_value.fetchone.return_value = ("aza", ["aza"])
        conexion.settings_dict = {"HOST": "postgres.example.invalid", "USER": "usuario.abcdefghijklmnopqrst"}
        salida = StringIO()
        with (
            patch.object(MetricaCaptura.objects, "aggregate", return_value={"total": 0, "con_angulo": 0}),
            patch.object(Usuario.objects, "count", return_value=0),
        ):
            call_command("verificar_base_datos", stdout=salida)
        self.assertIn("Proyecto Supabase: no identificable", salida.getvalue())
        self.assertNotIn("abcdefghijklmnopqrst", salida.getvalue())
