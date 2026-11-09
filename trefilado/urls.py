from django.urls import path

from . import views

urlpatterns = [
    path("", views.home, name="home"),
    # Autenticación (CU01, CU02)
    path("login/", views.login_view, name="login"),
    path("login/otp/", views.login_otp, name="login_otp"),
    path("logout/", views.logout_view, name="logout"),
    path("clave/cambiar/", views.cambiar_clave_view, name="cambiar_clave"),
    path("recuperar/", views.recuperar, name="recuperar"),
    path("recuperar/<str:token>/", views.recuperar_confirmar, name="recuperar_confirmar"),
    # Operador (CU03-CU06)
    path("operador/seleccion/", views.seleccion, name="seleccion"),
    path("operador/panel/", views.panel, name="panel"),
    path("operador/alerta/<int:pk>/revisar/", views.alerta_revisar, name="alerta_revisar"),
    path("inspeccion/<int:pk>/", views.inspeccion_detalle, name="inspeccion_detalle"),
    path("inspeccion/<int:pk>/imagen/", views.evidencia, name="evidencia"),
    # Supervisor (CU07-CU09)
    path("supervisor/historial/", views.historial, name="historial"),
    path("captura/<int:pk>/", views.metrica_detalle, name="metrica_detalle"),
    path("supervisor/dashboard/", views.dashboard, name="dashboard"),
    path("supervisor/lotes/", views.lotes, name="lotes"),
    path("supervisor/lotes/nuevo/", views.lote_nuevo, name="lote_nuevo"),
    path("supervisor/lotes/<int:pk>/editar/", views.lote_editar, name="lote_editar"),
    path("supervisor/lotes/<int:pk>/cerrar/", views.lote_cerrar, name="lote_cerrar"),
    # Auditoría (CU10)
    path("auditoria/", views.auditoria, name="auditoria"),
    # Administrador (CU11-CU16)
    path("administracion/usuarios/", views.usuarios, name="usuarios"),
    path("administracion/usuarios/nuevo/", views.usuario_nuevo, name="usuario_nuevo"),
    path("administracion/usuarios/<int:pk>/editar/", views.usuario_editar, name="usuario_editar"),
    path("administracion/usuarios/<int:pk>/estado/", views.usuario_estado, name="usuario_estado"),
    path("administracion/recetas/", views.recetas, name="recetas"),
    path("administracion/recetas/nueva/", views.receta_nueva, name="receta_nueva"),
    path("administracion/recetas/<int:pk>/editar/", views.receta_editar, name="receta_editar"),
    path("administracion/parametros/", views.parametros, name="parametros"),
    path("administracion/respaldos/", views.respaldos, name="respaldos"),
    path("administracion/respaldos/ejecutar/", views.respaldo_ejecutar, name="respaldo_ejecutar"),
    path("administracion/ips/", views.ips, name="ips"),
    path("administracion/ips/nueva/", views.ip_nueva, name="ip_nueva"),
    path("administracion/ips/<int:pk>/editar/", views.ip_editar, name="ip_editar"),
    path("administracion/ips/<int:pk>/eliminar/", views.ip_eliminar, name="ip_eliminar"),
    path("administracion/control/", views.control, name="control"),
    path("administracion/bloqueos/<int:pk>/levantar/", views.bloqueo_levantar, name="bloqueo_levantar"),
    # API de captura (CU17-CU19)
    path("api/inspecciones/", views.api_inspecciones, name="api_inspecciones"),
]
