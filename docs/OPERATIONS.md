# Instalación y operación por revista

## 1. Preparar una instalación confiable

Este programa endurece una instalación existente y limpia. Antes de activarlo, crea una copia consistente de código, configuración, base de datos y documentos, y verifica una restauración aislada. Si sospechas un compromiso, conserva evidencias protegidas, elimina la persistencia y revisa usuarios, tareas, plugins y servicios antes de definir la línea base.

Usa una cuenta Linux dedicada. Actualiza OJS desde PKP, siguiendo sus requisitos y guía de actualización. Prueba la migración en una base de datos distinta, con copia de documentos, correo saliente desactivado y tareas programadas desactivadas. No basta con mostrar la portada: comprueba autenticación, envíos, ajustes, un artículo, PDF, recursos públicos y sitemap.

El programa usa únicamente la biblioteca estándar de Python. Se verificó con Python 3.6 y 3.12; utiliza una versión de Python mantenida por tu distribución. Requiere Linux, root, un sistema de archivos con `FS_IMMUTABLE_FL` y `CAP_LINUX_IMMUTABLE`. Contenedores sin esa capacidad y algunos montajes no sirven para este modo. Necesita `curl`, un daemon ClamAV accesible y comandos de validación/recarga propios del servidor.

## 2. Separar documentos y código

Ejemplo de estructura; sustituye usuario, UID/GID, rutas, dominio y contexto de revista:

| Ruta ficticia | Uso |
| --- | --- |
| `/home/journal/public_html` | Código OJS; `cache/` y `public/` continúan escribibles. |
| `/home/journal/ojs-private` | Manuscritos y archivos privados; nunca servidos directamente por la web. |
| `/home/journal/tmp` | Sesiones, temporales y subidas de PHP-FPM, si se usa ese ejemplo. |
| `/etc/ojs-fix` | Perfil y configuraciones aprobadas, controlados por root. |
| `/var/lib/ojs-fix/journal` | Línea base, código sellado, estado y cuarentena; root `0700`. |

Configura `files_dir` de OJS con la ruta privada. Mueve los documentos durante una ventana sin escrituras y comprueba que la ruta efectiva cambió. No dejes un alias web, symlink o copia accesible en `/files/`. Conserva propietarios y permisos suficientes para que OJS trabaje con sus documentos.

En algunos servidores CWP, el control de ejecución exige que el código pertenezca a la cuenta de la aplicación: ponerlo a nombre de root causa errores de FPM. Este guardián conserva UID/GID de la cuenta y añade protección del kernel. Los archivos quedan `0444`, `config.inc.php` queda `0400`, y los directorios de código y el home quedan `0755` e inmutables. El home inmutable impide reemplazar todo `public_html`; las carpetas de runtime siguen operativas. La cuenta no podrá instalar plugins ni modificar temas desde el panel web.

## 3. Adaptar las políticas web

Revisa los archivos de `examples/`; son ejemplos para nginx delante de Apache en CWP, con OJS bajo `/index.php/journal`. No reemplaces un vhost ni un pool completo con un fragmento.

- `nginx-http.conf` pertenece al contexto `http`, cargado una sola vez. Define un mapa y una zona de límite de solicitudes con nombre exclusivo por instalación.
- `nginx-site.conf` pertenece al bloque `server` de esta revista. Adapta root, flag, IP del origen y rutas. Ajusta el mapa de login si utilizas URLs limpias o rutas diferentes. El ejemplo permite cinco POST de autenticación por minuto y una ráfaga de diez; verifica que tu política sea adecuada.
- `apache-site.conf` se incluye únicamente dentro de los vhosts de esta revista. Deniega scripts ajenos a `index.php`, incluso al acceder directamente al backend. Revisa conflictos con reglas o plugins existentes.
- `php-fpm-security.conf` se fusiona con el pool de la cuenta. Crea antes sus temporales privados, elimina directivas duplicadas y prueba compatibilidad. Las funciones deshabilitadas pueden afectar plugins que ejecutan programas externos; las tareas CLI confiables deben evaluarse aparte.

Prueba también HTML galleys, recursos subidos y plugins de tu revista. El ejemplo bloquea HTML y JavaScript en `public/`; si necesitas servir contenido activo, diseña otro origen aislado o adapta una política específica sin permitir ejecución de scripts en el servidor. Las cabeceras incluidas no sustituyen la actualización del visor PDF.

Si hay un proxy o Cloudflare, configura la IP real usando únicamente proxies de confianza. No aceptes `X-Real-IP` o `X-Forwarded-For` de cualquier cliente. Verifica que el límite no agrupe a todos los lectores bajo la IP del proxy y que la excepción de mantenimiento no deje pasar a todos los visitantes.

Coloca los includes usados por los daemons en sus directorios de configuración normales: por ejemplo `/etc/nginx/ojs-fix-journal.conf` y `/usr/local/apache/conf/ojs-fix-journal.conf`. En el caso original, un módulo de seguridad rechazaba includes en una carpeta nueva: `nginx -t` y la orden de recarga parecían correctos, pero los workers seguían usando la configuración anterior. `Include` en Apache hace visible la ausencia del archivo; `IncludeOptional` puede ocultarla.

## 4. Instalar perfil y ejecutable

Desde una copia revisada del repositorio:

```bash
sudo install -d -m 0700 /etc/ojs-fix /etc/ojs-fix/approved
sudo install -d -m 0700 /var/lib/ojs-fix /var/lib/ojs-fix/journal
sudo install -m 0700 ojs_fix.py /usr/local/sbin/ojs-fix
sudo install -m 0600 examples/profile.example.json /etc/ojs-fix/profile.json
```

Edita el perfil y prepara las copias **ya adaptadas** bajo `/etc/ojs-fix/approved/`. Cada entrada de `managed_files` relaciona un destino con una fuente aprobada, su servicio y su modo. No apuntes a configuraciones globales sin revisar sus efectos. Los comandos son arrays de argumentos, nunca texto de shell.

El ejemplo registra los dos includes de la revista y la zona de nginx. Para proteger un pool PHP o plantillas CWP, añade su contenido completo revisado a `managed_files`, y añade el servicio PHP correspondiente con sus comandos `test` y `reload`. Si agregas FPM, inclúyelo en `reload_order` antes de Apache y nginx.

```bash
sudo /usr/bin/python3 /usr/local/sbin/ojs-fix --check-config
```

El comando valida rutas y confianza del perfil; no demuestra que las reglas web sean correctas ni comprueba por sí solo la capacidad inmutable del kernel. Haz la prueba aislada del kernel y las verificaciones HTTP antes de dar por concluida la instalación.

## 5. Mantenimiento inicial y aprobación

Instala primero los includes adaptados y verifica sintaxis, mantenimiento externo y acceso al origen. Mantén detenidos los trabajos que puedan escribir en la revista durante el corte. La excepción de mantenimiento para el origen debe permitir las comprobaciones locales y responder `503` a visitantes externos.

```bash
sudo /usr/bin/python3 /usr/local/sbin/ojs-fix --maintenance-minutes 60
```

Con la revista limpia, actualizada y verificada, aprueba explícitamente su código:

```bash
sudo /usr/bin/python3 /usr/local/sbin/ojs-fix --approve
sudo /usr/bin/python3 /usr/local/sbin/ojs-fix --finish-maintenance
sudo /usr/bin/python3 /usr/local/sbin/ojs-fix
```

`--approve` incluye `config.inc.php`, plugins y demás archivos fuera de `cache/` y `public/` en el archivo sellado; no distingue malware de código legítimo. El archivo aprobado contiene credenciales y queda protegido en el servidor. Nunca lo añadas al repositorio.

`--finish-maintenance` requiere código idéntico al aprobado, bloqueos activos y probes correctos. Si falla, conserva el mantenimiento. El vigilante no elimina automáticamente un mantenimiento vencido: deja una alerta y evita restaurar una versión antigua sobre una base de datos migrada. Renueva la ventana, termina la actualización o restaura **código y base de datos del mismo punto consistente**, y aprueba de nuevo el resultado revisado.

## 6. Persistencia en CWP

Haz copias de las plantillas usadas realmente por esta cuenta. En las versiones nginx `.tpl` y `.stpl`, inserta el include de la revista tras `server_name`. En las plantillas Apache correspondientes, inserta el `Include` tras `ServerName`. Dales un nombre exclusivo, por ejemplo `ojs_fix_journal`; registra las copias completas aprobadas en `managed_files`.

Solo después de crearlas y probarlas, puedes configurar `cwp_metadata` con el archivo de esta revista bajo su `.conf/webservers/`, y `cwp_values` con las claves verificadas de esa instalación (`nginx_template-name`, `apache_template-name` y, cuando corresponda, `php-fpm_ver`). El ejemplo deja esta modificación desactivada. No cambies las plantillas predeterminadas de otras cuentas ni reconstruyas todos los dominios.

El guardián reintroduce los includes en los vhosts listados si CWP los pierde; comprueba que el archivo pertenece al dominio esperado. `enforce_document_root` está desactivado por defecto: actívalo solo en vhosts revisados que deban conservar ese root. Los sockets de PHP solo se sustituyen si se enumeran explícitamente en `old_php_sockets` y se define el destino `php_socket`.

Las plantillas reducen el intervalo sin protección durante una reconstrucción; la reparación periódica por sí sola tiene un intervalo de hasta un ciclo. Prueba una reconstrucción controlada de **esta revista** en el ensayo.

## 7. Timer, avisos y seguimiento

Adapta las rutas de `systemd/ojs-fix.service` y `.path` antes de instalarlos; elimina rutas que no existan y añade las del pool FPM si lo administras. Los permisos de escritura del sandbox deben permitir los destinos del perfil y los logs que abren los comandos de validación. No concedas un sandbox más amplio de lo necesario.

```bash
sudo install -m 0644 systemd/ojs-fix.service systemd/ojs-fix.timer systemd/ojs-fix.path /etc/systemd/system/
sudo install -m 0644 systemd/ojs-fix.logrotate /etc/logrotate.d/ojs-fix
sudo systemctl daemon-reload
sudo systemctl enable --now ojs-fix.timer ojs-fix.path
sudo systemctl start ojs-fix.service
sudo systemctl status ojs-fix.timer ojs-fix.path ojs-fix.service
```

`latest.json` contiene la última ejecución; `healthy` confirma las comprobaciones efectuadas y `uploads_pending_scan` muestra la cola pendiente. Los errores devuelven código de salida 1. `ALERT.json` se crea cuando hay reparaciones o errores y desaparece tras una ejecución limpia; `events.jsonl` conserva las acciones. Conecta tu monitor al resultado del servicio, a la antigüedad de `latest.json`, a los eventos y a la cola de antivirus. El programa no envía correos ni mensajes por sí solo.

Para instalaciones grandes, un análisis inicial completo puede ser necesario antes de abrir al público. Esta edición no permite marcar archivos como limpios mediante una simple bandera: procesa toda la cola. Antivirus indisponible produce error. El análisis periódico no impide que un documento se abra durante el intervalo previo al escaneo.

## 8. Actualizaciones posteriores y retirada

1. Crea una copia consistente y ensaya la actualización. Conserva un plan para restaurar código y base de datos juntos.
2. Activa mantenimiento, confirma el `503` externo y detén tareas escritoras. Ejecuta `--unlock-code` en la ventana activa.
3. Realiza la actualización oficial de OJS y la migración de base de datos. Revisa plugins, archivos y configuración; prueba funcionalidades. Ajusta `release` en el perfil root a la versión realmente instalada.
4. Ejecuta `--approve`, después `--finish-maintenance`, y verifica la ejecución automática y una visita externa.
5. Crea y verifica una nueva copia consistente. No sustituyas la anterior hasta verificar la nueva.

Para retirar la herramienta, detén timer/path, entra en mantenimiento y usa `--unlock-code`. Sustituye o retira de forma controlada los includes y las plantillas/metadatos de CWP, valida sintaxis, recarga y comprueba el sitio. Restaurar permisos normales de escritura es una decisión administrativa explícita; no hagas `chmod -R 777`. Conserva los documentos, la base de datos y las evidencias de incidentes según tu política.
