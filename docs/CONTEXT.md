# Contexto anonimizado: revista OJS y spam SEO

Registro de trabajo del **21 de noviembre de 2026**. Se omiten dominio, IP, cuenta Linux, correos, tokens, credenciales y documentos de la revista.

## Evidencia y alcance

| Hallazgo observado | Interpretación y respuesta |
| --- | --- |
| Aviso de Search Console sobre una página alternativa con canonical correcto. | El aviso aislado no prueba un ataque. Se revisaron las URLs concretas. |
| Dos URLs de spam relacionadas con apuestas y una ruta ajena a la revista. | Correspondían al incidente previo; no se identificó una nueva infección a partir de ese correo. |
| Un propietario verificado no autorizado y otro delegado en Search Console. | Se revocaron ambos y se revisaron las propiedades de dominio y prefijo HTTPS. |
| Un archivo HTML de verificación seguía publicado después de una limpieza anterior. | Se retiró la verificación persistente y se bloquearon sus rutas. Limpiar PHP no revoca la propiedad en Google. |
| Un sitemap de spam registrado y otro obsoleto. | Se eliminaron de Search Console y se registró el sitemap legítimo de OJS. |
| OJS 3.4.0.9 y un aviso oficial sobre el visor PDF. | Se actualizó a 3.4.0.12 tras ensayo aislado. No se demostró que esa vulnerabilidad fuera la vía de entrada. |
| Solicitudes a rutas de configuración y otros sondeos desde distintos orígenes. | Actividad compatible con escaneo automatizado; no permite atribuir una identidad o intención personal. |
| CWP podía regenerar la configuración web. | Se añadieron plantillas por revista, reparación y verificaciones al origen. |

Search Console mostraba el sitemap legítimo leído correctamente, con 89 URLs descubiertas. Las secciones de acciones manuales y problemas de seguridad no mostraban incidencias en la revisión. Eso no garantiza que todas las URLs estén indexadas ni que Google elimine inmediatamente el spam histórico.

## Corrección y endurecimiento realizados

Se preparó una copia de ensayo con base de datos y archivos independientes, correo externo desactivado y tareas automáticas detenidas. La actualización oficial a OJS 3.4.0.12 se probó antes del cambio de producción. Se mantuvo el plugin de autenticación existente después de comparar sus archivos con la copia revisada.

Los documentos privados se trasladaron fuera del directorio web. Se aplicaron políticas por revista en nginx, Apache y PHP-FPM; se bloquearon scripts PHP distintos del front controller y rutas sensibles. Se establecieron temporales privados, restricciones del pool y límites de acceso, sin cambiar los defaults de las demás cuentas.

Se sellaron 18.533 archivos de código aprobados, con bloqueo inmutable de archivos, directorios y home. Se instaló un vigilante por minuto y un disparador ante cambios de CWP. Las pruebas verificaron bloqueo al usuario de aplicación, restauración de un archivo de prueba, cuarentena de un script inofensivo, detección del patrón estándar inofensivo de prueba de antivirus y recuperación de un include retirado durante la simulación de una reconstrucción.

Finalmente se creó una nueva copia protegida de código, documentos, base de datos y estado de protección, con sumas SHA-256. El ensayo y sus credenciales temporales se eliminaron después de completar las verificaciones. Ninguno de esos respaldos o datos se incluye en este repositorio.

## Lecciones para otras revistas

- Una alerta de indexación requiere revisar las URLs. No se debe borrar canonical, bloquear robots o pedir indexación de spam como respuesta automática.
- La respuesta debe revisar tanto el servidor como la persistencia fuera de él: propietarios, verificaciones y sitemaps de Search Console.
- Una copia limpia y conocida sirve como fuente de recuperación. Una copia reciente puede conservar la misma persistencia que se está intentando quitar.
- Una orden de recarga exitosa no demuestra que el daemon cargó las reglas. Hay que verificar resultados observables.
- Las defensas deben sobrevivir a reconstrucciones del panel y permitir actualizaciones controladas de OJS.

No se conocen el punto de entrada original ni el autor del incidente. El aprovechamiento de la reputación de una revista para spam de apuestas es una **inferencia** a partir del contenido encontrado. No hay base para concluir que todas las instalaciones de OJS estén comprometidas o que una revista haya sido elegida por razones personales.

El repositorio es una generalización de los controles de ese despliegue. No distribuye OJS, copias del servidor ni herramientas ofensivas. La licencia MIT de OJS-Fix cubre el código de esta herramienta; OJS y sus componentes conservan sus propias licencias.

## Ampliación: archivos de revisión que aparentan ser Word o PDF

El operador recordó un incidente previo con adjuntos que aparentaban ser documentos. Esa observación motivó revisar una limitación del primer mecanismo: escanear cada minuto dejaba un intervalo antes de detectar un archivo ya guardado. La ampliación v0.2 añade análisis antes de aceptar la subida y antes de entregar descargas privadas, con verificación del contenido real y rechazo ante errores del antivirus.

La auditoría posterior de 402 adjuntos no encontró firmas conocidas de virus. Identificó 7 documentos Word con objetos externos y 2 archivos con extensión incompatible con su contenido. Se preservaron los originales y se aplica la política de bloqueo; no se atribuyen retrospectivamente esos archivos al ataque original. El mecanismo, las pruebas y las limitaciones se describen en [ATTACHMENTS.md](ATTACHMENTS.md).

También se cerró el camino del correo nativo con adjuntos ya guardados: se inspeccionan las partes MIME antes de SMTP, conservando únicamente los bytes comprobados. Las pruebas de integración no enviaron mensajes.
