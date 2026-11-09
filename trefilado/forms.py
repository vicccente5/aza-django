import ipaddress

from django import forms
from django.db.models import Q

from .models import IpPermitida, Lote, Receta, Usuario
from .services import FRECUENCIAS_RESPALDO, validar_politica_clave


def fecha_widget():
    return forms.DateInput(attrs={"type": "date"}, format="%Y-%m-%d")


# ------------------------------------------------------------------ autenticación
class LoginForm(forms.Form):
    username = forms.CharField(label="Usuario", max_length=150)
    password = forms.CharField(label="Contraseña", widget=forms.PasswordInput)


class OTPForm(forms.Form):
    codigo = forms.CharField(label="Código OTP (6 dígitos)", min_length=6, max_length=6)


class RecuperarForm(forms.Form):
    identificador = forms.CharField(label="Nombre de usuario o correo registrado", max_length=150)


class NuevaClaveForm(forms.Form):
    password1 = forms.CharField(
        label="Nueva contraseña",
        widget=forms.PasswordInput,
        help_text="Mínimo 8 caracteres, una mayúscula y un número.",
    )
    password2 = forms.CharField(label="Confirmar contraseña", widget=forms.PasswordInput)

    def clean(self):
        datos = super().clean()
        p1, p2 = datos.get("password1"), datos.get("password2")
        if p1:
            errores = validar_politica_clave(p1)
            if errores:
                self.add_error("password1", errores)
        if p1 and p2 and p1 != p2:
            self.add_error("password2", "Las contraseñas no coinciden.")
        return datos


# ------------------------------------------------------------------ administración
class UsuarioForm(forms.ModelForm):
    password = forms.CharField(
        label="Contraseña inicial",
        widget=forms.PasswordInput,
        required=False,
        help_text="Mínimo 8 caracteres, una mayúscula y un número. En edición, déjela en blanco para no cambiarla.",
    )

    class Meta:
        model = Usuario
        fields = ["username", "first_name", "last_name", "email", "rol"]
        labels = {"username": "Nombre de usuario", "first_name": "Nombre", "last_name": "Apellido", "email": "Correo", "rol": "Rol"}

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["email"].required = True
        if not self.instance.pk:
            self.fields["password"].required = True

    def clean_password(self):
        clave = self.cleaned_data.get("password")
        if clave:
            errores = validar_politica_clave(clave)
            if errores:
                raise forms.ValidationError(errores)
        return clave

    def save(self, commit=True):
        usuario = super().save(commit=False)
        clave = self.cleaned_data.get("password")
        if clave:
            usuario.set_password(clave)
            from django.utils import timezone

            usuario.fecha_cambio_clave = timezone.now()
        if commit:
            usuario.save()
        return usuario


class RecetaForm(forms.ModelForm):
    class Meta:
        model = Receta
        fields = ["nombre", "espesor", "materialidad", "limite_min", "limite_max", "vigente"]
        labels = {"nombre": "Nombre de la receta", "materialidad": "Materialidad", "vigente": "Vigente (disponible en planta)"}

    def clean(self):
        datos = super().clean()
        minimo, maximo = datos.get("limite_min"), datos.get("limite_max")
        if minimo is not None and maximo is not None and minimo >= maximo:
            raise forms.ValidationError("El límite mínimo debe ser menor que el límite máximo.")
        return datos


class IpForm(forms.ModelForm):
    class Meta:
        model = IpPermitida
        fields = ["direccion", "descripcion"]
        help_texts = {"direccion": "Ejemplo: 192.168.0.15 o 192.168.0.0/24"}

    def clean_direccion(self):
        valor = self.cleaned_data["direccion"].strip()
        try:
            red = ipaddress.ip_network(valor, strict=False)
        except ValueError:
            raise forms.ValidationError("Formato de IP o subred inválido.")
        return str(red) if "/" in valor else str(red.network_address)


class ConfigRespaldoForm(forms.Form):
    frecuencia = forms.ChoiceField(label="Frecuencia del respaldo automático", choices=FRECUENCIAS_RESPALDO)


# ------------------------------------------------------------------ supervisor
class LoteForm(forms.ModelForm):
    class Meta:
        model = Lote
        fields = ["identificador", "receta", "fecha", "turno"]
        labels = {"identificador": "Identificador único", "receta": "Receta asociada", "fecha": "Fecha", "turno": "Turno"}
        widgets = {"fecha": fecha_widget()}

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        filtro = Q(vigente=True)
        if self.instance.pk:
            filtro |= Q(pk=self.instance.receta_id)
        self.fields["receta"].queryset = Receta.objects.filter(filtro)

    def clean_identificador(self):
        ident = self.cleaned_data["identificador"].strip()
        repetido = Lote.objects.filter(identificador__iexact=ident, estado=Lote.Estado.ABIERTO).exclude(pk=self.instance.pk)
        if repetido.exists():
            raise forms.ValidationError("Ya existe un lote abierto con ese identificador.")
        return ident


class FiltroFechasMixin(forms.Form):
    desde = forms.DateField(label="Desde", required=False, widget=fecha_widget())
    hasta = forms.DateField(label="Hasta", required=False, widget=fecha_widget())

    def clean(self):
        datos = super().clean()
        if datos.get("desde") and datos.get("hasta") and datos["desde"] > datos["hasta"]:
            raise forms.ValidationError("Rango de fechas inválido: la fecha inicial es posterior a la final.")
        return datos


class MetricasFiltroForm(FiltroFechasMixin):
    escena = forms.CharField(label="Escena", required=False, max_length=30)
    angulo = forms.ChoiceField(
        label="Ángulo",
        required=False,
        choices=[("", "Todas"), ("con", "Con medición"), ("sin", "Sin medición")],
    )


class AuditoriaFiltroForm(FiltroFechasMixin):
    usuario = forms.ModelChoiceField(label="Usuario", queryset=Usuario.objects.all(), required=False)
    accion = forms.CharField(label="Tipo de acción", required=False)


# ------------------------------------------------------------------ operador
class EvidenciaForm(forms.Form):
    archivo = forms.FileField(label="Imagen (JPG, PNG, GIF o WEBP, máx. 5 MB)", required=False)
    referencia = forms.CharField(label="o referencia visual (ruta / URL)", required=False, max_length=255)

    def clean_archivo(self):
        archivo = self.cleaned_data.get("archivo")
        if archivo:
            nombre = archivo.name.lower()
            if not nombre.endswith((".jpg", ".jpeg", ".png", ".gif", ".webp")):
                raise forms.ValidationError("Archivo inválido: solo se aceptan imágenes JPG, PNG, GIF o WEBP.")
            if archivo.size > 5 * 1024 * 1024:
                raise forms.ValidationError("Archivo inválido: supera el tamaño máximo de 5 MB.")
        return archivo
