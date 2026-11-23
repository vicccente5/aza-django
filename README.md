# Monitoreo de capturas de trefilado · Aceros AZA

Aplicación Django que muestra las mediciones originales de `METRICAS_CONSOLIDADAS`.
El archivo `METRICAS_CONSOLIDADAS.zip` contiene 859 capturas JSON registradas entre el
14 y el 21 de julio de 2026. De ellas, 128 incluyen un ángulo de salida y 731 no
incluyen esa medición. La aplicación conserva esta diferencia y no asigna estados
«aprobado» o «rechazado» a estos datos: los JSON no contienen límites de tolerancia,
receta ni lote.

## Puesta en marcha

```powershell
python -m venv .venv
& .\.venv\Scripts\python.exe -m pip install -r requirements.txt
if (!(Test-Path .env)) { Copy-Item .env.example .env }
```

Complete `DATABASE_URL` en `.env` con la cadena del Session pooler de Supabase.
El arranque normal requiere PostgreSQL y el esquema `aza`. Cuando la base ya está
inicializada, compruebe la conexión y ejecute el servidor de desarrollo.

```powershell
& .\.venv\Scripts\python.exe manage.py verificar_base_datos
& .\.venv\Scripts\python.exe manage.py runserver
```

Abra `http://127.0.0.1:8000/` en el navegador del mismo equipo.

Al preparar una base nueva, ejecute `migrate`, `importar_metricas` y `crear_admin`
desde el entorno virtual. El comando `crear_admin` solicita los datos reales del
primer administrador y oculta la contraseña al escribirla. Después, el administrador
puede crear usuarios de los otros roles y configurar la lista de IPs de Operadores.

Para desarrollo aislado, establezca `DEBUG=1` y `AZA_SQLITE_LOCAL=1` con
`DATABASE_URL` vacía. Django usa `db.sqlite3`. Ejecute `migrate` para inicializar esa
base si está vacía. Quite `AZA_SQLITE_LOCAL` al volver a la base compartida. El
arranque se detiene si ambas opciones están configuradas.

`python manage.py test` usa SQLite en memoria e ignora `.env` y `DATABASE_URL`.
Si llama a `call_command("test")` desde un proceso configurado con PostgreSQL, el
ejecutor de pruebas de AZA se detiene antes de preparar la base de pruebas. Ejecute
el comando en un proceso nuevo para usar SQLite en memoria.

## Datos reales

- `/operador/panel/`: últimas capturas, con «Sin medición» donde el JSON no trae ángulo.
- `/supervisor/dashboard/`: total de capturas, cobertura y rango de ángulos
  disponibles, capturas por día y confianza reportada por el análisis.
- `/supervisor/historial/`: filtros por fecha, escena y presencia de ángulo; exportación
  CSV con todos los campos originales.
- `/captura/<id>/`: detalle de una captura. La ruta de diagnóstico es una referencia al
  equipo de origen; las imágenes de diagnóstico no están incluidas en el ZIP.
- `/administracion/control/`: resumen de capturas reales y alertas de seguridad.

La importación es repetible: `python manage.py importar_metricas` actualiza cada captura
por nombre de archivo y evita duplicados. Acepta una carpeta o ZIP con
`--source <ruta>`. Por defecto lee la carpeta extraída si existe y, en caso contrario,
`METRICAS_CONSOLIDADAS.zip`. Ambos archivos de origen se mantienen fuera del repositorio.
La importación a PostgreSQL de Supabase se hace una sola vez desde el equipo local.

En [SQL Editor de Letterboxd](https://supabase.com/dashboard/project/hxgewarawsnhttcxpnhw/sql/new),
consulte las capturas con el nombre completo del esquema:

```sql
SELECT archivo_origen, fecha_hora, scene, exit_angle_deg
FROM aza.trefilado_metricacaptura
ORDER BY fecha_hora DESC
LIMIT 50;
```

Para contrastar los totales del panel y la base:

```sql
SELECT COUNT(*) AS total, COUNT(exit_angle_deg) AS con_angulo
FROM aza.trefilado_metricacaptura;
```

## Supabase y despliegue

El proyecto **Letterboxd** de Supabase tiene un esquema privado `aza` para esta
aplicación. Las tablas existentes de Letterboxd en `public` no se borran ni se usan.
El esquema `aza` no concede acceso a los roles `anon` y `authenticated` de la API.

Para conectar Django, abra [Connect de Letterboxd](https://supabase.com/dashboard/project/hxgewarawsnhttcxpnhw?showConnect=true&method=session), elija **Session pooler** y copie la
cadena PostgreSQL del puerto **5432**. En el archivo local `.env`, reemplace
`DATABASE_URL=` por esa cadena con la contraseña real en lugar de
`[YOUR-PASSWORD]`. Si la contraseña contiene caracteres reservados de URL,
codifíquelos. No comparta la contraseña en el chat ni suba `.env` al repositorio.
`DB_SCHEMA=aza` ya está preparado. `python manage.py verificar_base_datos` muestra
el motor, el esquema, la referencia del proyecto si reconoce el Session pooler y
los totales de capturas y usuarios. El comando devuelve un error si la conexión
activa no usa PostgreSQL con `aza`. Si muestra «Proyecto Supabase: no identificable»,
compare el proyecto configurado en cada equipo por un canal seguro.

La URL de ejemplo utiliza el rol `postgres`, que también tiene permisos sobre las
tablas de Letterboxd. Guarde esa URL maestra para tareas de administración y evite
distribuirla a otros equipos. Antes de desplegar AZA, configure un usuario de base de
datos limitado al esquema `aza` y actualice `DATABASE_URL` con ese usuario.

En un despliegue central, el servicio Django guarda las credenciales de conexión
y cada equipo abre la misma URL desde el navegador. En Render, configure
`DATABASE_URL` como variable de entorno secreta, mantenga `DEBUG=0` y configure
el correo SMTP según `.env.example`. En producción, `SECRET_KEY` requiere un valor
aleatorio de al menos 43 caracteres. El Blueprint de Render la genera al crear el
servicio. `start.sh` aplica las migraciones y luego inicia Gunicorn. Las capturas se
importan como una operación separada.

Si ejecuta Django en varias máquinas, configure cada instancia para conectarse a
la misma base PostgreSQL y al esquema `aza`. Verifique cada instancia con
`verificar_base_datos`. Para servir una sola URL con varias réplicas, use la misma
`SECRET_KEY` y la misma configuración de URL pública en todas ellas. Reserve
`DEBUG=1` para acceso local. Toda instancia con la base compartida que quede
accesible a terceros debe usar `DEBUG=0`.

Los archivos adjuntos de evidencia se guardan en `MEDIA_ROOT`, en el sistema de
archivos de la instancia que los recibe. PostgreSQL comparte las referencias a esos
archivos. Para conservar los adjuntos después de un reinicio o compartirlos entre
instancias, se necesita almacenamiento persistente y accesible desde todas ellas.
Los respaldos de PostgreSQL se gestionan en Supabase. El respaldo de archivos de
la aplicación solo está disponible en modo SQLite.

La API `/api/inspecciones/` y la gestión de recetas/lotes pertenecen al flujo de
captura por lote. Los JSON consolidados no tienen esos campos y se guardan por
separado en `MetricaCaptura`; no se les atribuye una receta o lote inventado.

El inicio de sesión de Administradores requiere OTP. En desarrollo local el código
se muestra en pantalla; para un despliegue real se necesita configurar un servicio
de correo. La API de captura queda deshabilitada hasta configurar
`API_TOKEN_CAPTURA`. El proyecto Supabase contiene tablas previas en `public` sin
RLS; deben revisarse por separado antes de utilizar su Data API.



la base se conecta asi se tiene que ver

"
DATABASE_URL=postgresql://postgres.hxgewarawsnhttcxpnhw:aza_project%40123@aws-1-us-east-2.pooler.supabase.com:5432/postgres
DB_SCHEMA=aza
"