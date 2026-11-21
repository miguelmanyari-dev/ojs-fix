# Adjuntos seguros: subidas y descargas de revisión

## El problema que corrige v0.2

Un archivo puede llamarse `manuscrito.docx` o anunciar un MIME de Word y contener un ejecutable, un documento con macros, un objeto externo o malware conocido. Revisar solo la extensión no verifica su contenido. Además, el análisis periódico deja un intervalo entre guardar un archivo y detectarlo: un revisor podría descargarlo durante ese intervalo.

La capa de adjuntos de OJS-Fix añade controles sin modificar el núcleo de OJS:

| Punto de control | Qué ocurre |
| --- | --- |
| Antes de aceptar la subida | Un `auto_prepend_file` del pool FPM inspecciona todos los archivos de `$_FILES` antes de ejecutar OJS, incluidos formularios y API de archivos temporales. |
| Antes de entregar una descarga | Un plugin para OJS 3.4 intercepta `File::download` y las descargas privadas de `FileManager::downloadFile`. Crea una copia temporal, la inspecciona y entrega los mismos bytes inspeccionados. |
| Antes del correo nativo de OJS | El plugin escucha `MessageSending`, inspecciona las partes MIME adjuntas e inline y fija los bytes comprobados antes del transporte SMTP. Un rechazo cancela el envío. |
| Antivirus local | Un proxy local autentica al cliente por UID real en Unix o por certificado en TLS mutuo, y solo admite un flujo `INSTREAM` acotado hacia el daemon ClamAV existente. No admite rutas, administración, parada del daemon ni ejecución de comandos. |
| Fallo o espera excesiva | Se rechaza la operación con 503. Una respuesta incompleta del antivirus nunca se interpreta como limpia. |
| Rechazo de contenido | Se devuelve 422; el archivo no llega a registrarse como una subida aceptada. Los originales históricos se conservan para revisión administrativa. |

**Las dos partes deben instalarse.** El guardián periódico continúa como recuperación y vigilancia, pero por sí solo no habilita el control sincrónico.

## Política de contenido

La política predeterminada admite PDF, DOC, DOCX, PPTX y las imágenes PNG/JPEG/GIF/WebP. Se ajusta por instalación y se verifica contra contenido real; el `Content-Type` enviado por el navegador no decide la aceptación.

- Se rechazan nombres con extensiones ejecutables, combinaciones peligrosas, controles, rutas o marcas Unicode que alteran visualmente el nombre.
- DOCX/PPTX deben ser contenedores Office del tipo indicado, con sus partes requeridas y XML válido. Se limitan entradas, tamaño expandido y relación de compresión; no se extraen archivos al sistema.
- Se bloquean componentes VBA, ActiveX, objetos incrustados y relaciones externas distintas de hipervínculos ordinarios. Esto puede exigir sustituir documentos legítimos con objetos enlazados por una copia aplanada.
- Los DOC antiguos deben tener estructura de directorio Compound File de Word; se rechazan los almacenes de macros, objetos y cifrado reconocidos. No se ejecuta Word ni sus macros.
- PDF requiere cabecera/tipo y terminación compatibles. Se examinan nombres visibles de acciones y cifrado, ignorando comentarios, cadenas y streams binarios para evitar falsos positivos. **Esto no es un parser completo de PDF ni inspecciona todos sus objetos comprimidos.** El antivirus y un visor actualizado siguen siendo necesarios; esta comprobación adicional no demuestra que todo PDF sea inocuo.
- Las imágenes deben corresponder a su formato real y tener dimensiones limitadas.

El máximo de ejemplo es 20 MiB por archivo; se coordina con PHP, nginx y los límites del daemon ClamAV. Los documentos cifrados o no analizables no deben darse por seguros. Los límites del formato, del antivirus o del proxy producen rechazo, nunca autorización por omisión.

## Instalar primero en un ensayo aislado

Requisitos nuevos: PHP 8 con `fileinfo`, `zip`, `dom`, `mbstring` y sockets de stream; el daemon ClamAV existente; Python para el proxy Unix. La integración de hooks se verificó con **OJS 3.4.0.12**. No se declara compatibilidad automática con OJS 3.3 o 3.5; comprueba sus hooks y flujos antes de adaptar el plugin.

1. Copia `plugins/generic/ojsFixAttachmentGuard` al mismo lugar en la instalación OJS de ensayo.
2. Copia `policy.example.php` como `policy.php`, sustituye rutas y socket, y protege el archivo junto con el código. El archivo local `policy.php` está excluido de Git. El directorio temporal debe ser privado de la cuenta, fuera del webroot, y existir antes de activar la protección.
3. Instala `tools/scan_proxy.py` como `/usr/local/libexec/ojs-fix-scan-proxy`, propiedad de root y modo `0755`. Adapta `systemd/ojs-fix-scan-proxy.service` al usuario que ya puede acceder al socket del daemon, al grupo de esta cuenta y a su UID.
4. El socket del proxy debe estar en un directorio que la aplicación pueda atravesar pero no modificar, con acceso solo al grupo autorizado. No añadas la cuenta web al grupo que administra el daemon ni abras ClamAV por TCP. No se necesita habilitar `exec`, `shell_exec` o `proc_open` en PHP.
5. Instala y habilita el servicio adaptado; prueba un flujo limpio y el patrón estándar inofensivo de prueba de antivirus, siempre dentro de tu ensayo.
6. Fusiona esta directiva con el **pool de esta cuenta** y con su plantilla persistente CWP:

```ini
php_admin_value[auto_prepend_file] = /home/journal/public_html/plugins/generic/ojsFixAttachmentGuard/prepend.php
```

7. Registra el descriptor del plugin con la herramienta oficial y habilítalo a nivel de sitio desde la administración OJS. Comprueba que la versión registrada y la opción `enabled` realmente se cargan; el pool FPM y el plugin protegen puntos distintos.

```bash
php lib/pkp/tools/installPluginVersion.php plugins/generic/ojsFixAttachmentGuard/version.xml
```

8. Incorpora los nuevos archivos a la línea base **solo después** de revisar y probarlos en mantenimiento. Conserva fuentes aprobadas del pool/plantilla y del servicio. Añade un control operativo que compruebe plugin habilitado, directiva FPM, socket, antigüedad de firmas y descargas. Activar un plugin una vez no demuestra que siga funcionando después de una reconstrucción o actualización.

No sobrescribas un `auto_prepend_file` ya usado por otra herramienta: integra ambos de forma revisada y ensaya el orden. No cambies los pools de otras cuentas.

## Alternativa para FPM con restricciones de conexión Unix

Algunos entornos de producción rechazan la conexión Unix desde el worker FPM aunque funcione desde PHP CLI. Compruébalo en el proceso real de FPM. En el caso revisado, la alternativa verificada fue **TLS mutuo exclusivamente sobre `127.0.0.1`**, sin modificar las restricciones del pool ni conceder acceso administrativo al daemon.

Usa `systemd/ojs-fix-scan-proxy-tls.service` como alternativa al servicio Unix, con otro puerto local si el de ejemplo está ocupado. El programa rechaza listeners TLS en direcciones distintas de `127.0.0.1`. El upstream sigue siendo el socket Unix privado del daemon. La CA es exclusiva de esta integración; el servidor exige certificado de cliente y PHP valida la CA y el nombre del servidor. Una CA equivocada o un cliente no autorizado producen rechazo.

Ejemplo de emisión **en un directorio nuevo protegido de root**, sin claves previas, con OpenSSL de la distribución:

```bash
openssl req -x509 -newkey rsa:2048 -nodes -keyout ca.key -out ca.pem -days 3650 -subj /CN=OJS-Fix-Local-CA
openssl req -newkey rsa:2048 -nodes -keyout server.key -out server.csr -subj /CN=localhost
openssl req -newkey rsa:2048 -nodes -keyout client.key -out client.csr -subj /CN=OJS-Fix-Journal
```

Firma las solicitudes con esa CA usando extensiones explícitas: `basicConstraints=critical,CA:FALSE`, `keyUsage=critical,digitalSignature,keyEncipherment`, y `extendedKeyUsage=serverAuth` para el servidor o `clientAuth` para el cliente. El certificado de servidor necesita `subjectAltName=DNS:localhost,IP:127.0.0.1`. Por ejemplo, con las extensiones correspondientes en `server.ext` y `client.ext`:

```bash
openssl x509 -req -in server.csr -CA ca.pem -CAkey ca.key -CAcreateserial -out server.pem -days 730 -extfile server.ext
openssl x509 -req -in client.csr -CA ca.pem -CAkey ca.key -CAcreateserial -out client.pem -days 730 -extfile client.ext
```

Conserva `ca.key` solo para root, modo `0600`. El servicio necesita leer `server.pem`, `server.key` y `ca.pem` mediante su usuario/grupo del antivirus, sin permiso de escritura. Instala únicamente las copias de `ca.pem`, `client.pem` y `client.key` que necesita PHP en una carpeta privada fuera del webroot; protege la clave con `0400` y bloquea archivos y carpeta contra sustitución. En CWP puede ser necesario mantener la propiedad de esos archivos en el UID de la aplicación y protegerlos con atributos inmutables, igual que el código. No publiques esas claves ni las pongas en backups accesibles a la web.

Adapta `policy.php`:

```php
'socket' => 'tls://127.0.0.1:3327',
'tls_ca' => '/home/journal/tmp/ojs-fix-tls/ca.pem',
'tls_cert' => '/home/journal/tmp/ojs-fix-tls/client.pem',
'tls_key' => '/home/journal/tmp/ojs-fix-tls/client.key',
```

Incluye ambas carpetas de certificados en el respaldo protegido y supervisa su caducidad; renuévalos en mantenimiento antes de vencer. No desactives `verify_peer` ni `verify_peer_name`, no uses una conexión TCP sin TLS y no abras el puerto fuera del loopback. Verifica también el plugin cargado, el escaneo desde FPM y la renovación después de cambios de servidor.

## Pruebas reproducibles

```bash
PHP_BINARY=/ruta/al/php8 OJS_VENDOR_AUTOLOAD=/ruta/a/ojs/lib/pkp/lib/vendor/autoload.php python3 -m unittest discover -s tests -v
```

La suite incluye pruebas del proxy con socket Unix y TLS mutuo, documentos ficticios, errores y respuestas incompletas del scanner, nombres engañosos, macros, relaciones externas, límites ZIP y escapes por symlink. Un servidor PHP local demuestra que un rechazo ocurre antes de ejecutar la aplicación. Las pruebas que requieren PHP se omiten si no está disponible y las tres de MIME necesitan el autoloader de OJS indicado en `OJS_VENDOR_AUTOLOAD`; el registro del caso incluye una ejecución completa con PHP 8.3 y **42 pruebas aprobadas**.

Para validar en OJS, usa una copia con base de datos, archivos, sesiones y temporales separados, correo externo desactivado y acceso solo local. Prueba, como usuario autenticado, subidas PDF/DOCX/DOC por API y el asistente habitual de tu revista. Los rechazos no deben crear filas de archivos temporales. En una copia ficticia de una descarga, sustituye temporalmente solo ese archivo por el patrón estándar inofensivo de prueba y confirma el bloqueo; restaura la copia al terminar. Nunca uses malware real ni alteres documentos de producción para una prueba.

## Adjuntos por correo

El control del evento nativo de correo examina el árbol MIME que va al transporte, incluidas imágenes inline. Reconstruye los adjuntos con los bytes ya analizados, preservando el cuerpo de texto/HTML y los identificadores de imágenes. Así se evita el camino que reenviaba un archivo guardado sin pasar por el controlador de descarga. El límite total de adjuntos usa el máximo configurado por la política. Si se detecta un archivo o el antivirus falla, se interrumpe el envío; revisa el error antes de reintentarlo con un original válido.

El plugin debe estar cargado en el proceso que envía el correo. Comprueba también tus workers CLI o integraciones de cola personalizados; no se declara cobertura de plugins que omiten el sistema nativo y utilizan su propio cliente SMTP. El filtro de correo del proveedor sigue siendo una capa adicional, especialmente para mensajes ajenos a OJS.

Las pruebas MIME construyen mensajes con direcciones ficticias y los serializan localmente: no llaman a un transporte ni envían mensajes. En el despliegue se verificó también el listener real de OJS mediante el evento previo al envío, con un adjunto válido y el patrón estándar inofensivo de antivirus, sin invocar SMTP.

## Históricos, privacidad y operación

Antes de activar la política en una revista con documentos previos, analiza sus adjuntos y revisa los rechazos. Un rechazo de política no equivale a una detección de virus. No borres manuscritos ni apruebes excepciones de forma automática. Los autores pueden enviar una copia válida, sin macros, objetos externos ni contraseña, cuando un original no cumpla la política.

El contenido se analiza localmente; no se envía a servicios públicos de análisis. Los registros de rechazo usan motivo, tamaño y hash, sin nombre de autor ni contenido. Los snapshots temporales se eliminan al terminar normalmente; después de una caída de FPM pueden quedar residuos en el directorio privado. Revísalos y límpialos con una política de antigüedad superior al tiempo máximo de una solicitud, sin borrar subidas en curso.

El proxy limita concurrencia y tiempo para compartir el antivirus con otros servicios. El límite de cuerpo y un límite de solicitudes multipart por cuenta ayudan a acotar abusos antes del análisis. Vigila CPU, memoria, cola, firmas y denegaciones del servicio. No se garantiza detectar malware nuevo, todo contenido activo o todos los fallos posibles de un lector Word/PDF. Se mantienen necesarias las actualizaciones de OJS, antivirus y estaciones de los revisores.

El registro de validación distingue esta integración del mecanismo previo de integridad. No incluye documentos reales, muestras de malware, configuración privada ni credenciales.

Referencias: [PKP: inventario de plugins](https://github.com/pkp/pkp-docs/blob/main/plugin-inventory/en/README.md), [PKP: hooks de descarga 3.4](https://github.com/pkp/pkp-lib/blob/stable-3_4_0/classes/services/PKPFileService.php), [ClamAV: protocolo del daemon](https://docs.clamav.net/manual/Usage/ClamdProtocol.html), [OWASP: subidas sin restricciones](https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload).
