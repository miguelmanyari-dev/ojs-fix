# Seguridad y límites de confianza

OJS-Fix se ejecuta como root. Su perfil, el ejecutable, las configuraciones aprobadas, el estado y todos sus directorios padre deben estar controlados por root. Una persona que modifica esos elementos ya está dentro del límite de confianza; el programa no intenta defender el servidor frente a root.

La cuenta debe ser exclusiva de OJS. El bloqueo inmutable del directorio de la cuenta puede interferir con creación de carpetas, instaladores, copias y mantenimiento del panel. No lo apliques a una cuenta compartida con otras aplicaciones sin separar primero la revista.

La línea base es una aprobación administrativa explícita del código y de `config.inc.php`, no un análisis de malware ni una firma oficial. Antes de aprobar: verifica el origen de OJS, revisa plugins y configuración, examina cambios, ejecuta antivirus y prueba una copia aislada. No ejecutes `--approve` como respuesta automática a una alerta.

Los directorios `cache/` y `public/` permanecen escribibles. Las reglas web, los permisos y la política de PHP-FPM son parte de la protección. El directorio privado debe quedar fuera del webroot; el antivirus periódico no equivale a bloquear cada descarga hasta que termine un análisis. La cuarentena conserva contenido potencialmente dañino y exige acceso root.

El guardián no vigila ni revierte tablas SQL, sesiones, permisos de usuarios de OJS, cuentas del panel, DNS, Cloudflare ni Search Console. Estos se revisan durante la respuesta al incidente y en la operación habitual. Una inyección que solo cambia la base de datos puede requerir una investigación independiente.

Los errores de sintaxis restauran los archivos de configuración previos antes de recargar servicios. Una recarga que devuelve éxito puede no haber aplicado su configuración: el probe de PHP prohibido comprueba una consecuencia observable. También conviene revisar el diario del master y los workers. Las recargas de servicios compartidos no son una transacción única entre nginx, Apache y FPM.

Para un fallo de OJS o de sus plugins oficiales, usa el [canal de seguridad de PKP](https://github.com/pkp/pkp-lib/security). Para cambios en OJS-Fix puedes abrir un issue con un caso mínimo y datos ficticios. No publiques exploits activos contra una instalación, credenciales, originales de documentos, configuraciones reales ni volcados SQL. Este repositorio no declara disponer de un canal privado de denuncias ni de una auditoría independiente.
