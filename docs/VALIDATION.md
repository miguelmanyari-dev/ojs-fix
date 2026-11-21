# Registro de validación

Comprobaciones realizadas el 21 de noviembre de 2026. Se separan las pruebas del código público de las del despliegue específico del caso original. No constituye una auditoría independiente ni una certificación de todos los plugins o entornos OJS.

## Código público v0.1.0

| Prueba | Resultado |
| --- | --- |
| 17 regresiones con biblioteca estándar, Python 3.12 | Aprobadas. |
| Las mismas 17 regresiones, Python 3.6 de la distribución del servidor | Aprobadas. |
| Perfil ficticio y rutas peligrosas | Se acepta el ejemplo; se rechazan webroot privado, estado dentro de la cuenta, UID root, rutas amplias, caracteres inseguros y exclusiones arbitrarias de código. |
| Recuperación y cuarentena | Se restaura código cambiado desde tar protegido y se conservan los documentos; se aíslan archivos, directorios y symlinks no aprobados. |
| Archivo sellado corrupto | Su contenido no se restaura como código aprobado. |
| Antivirus simulado | Detección y extensión ejecutable se aíslan; errores no se registran como limpios; un archivo modificado durante el análisis queda pendiente. |
| Mantenimiento vencido y probes fallidos | Se conserva el bloqueo y se evita una reparación automática durante una migración incompleta. |
| Configuración con error de sintaxis | Se restaura el archivo anterior y no se recarga el servicio. |
| Prueba del kernel en una instalación ficticia aislada en Linux | Sobrescritura, chmod, creación de código y sustitución de webroot rechazados al UID de prueba; restauración sellada e inmutabilidad verificadas; runtime escribible. |

Las pruebas de regresión simulan los flags del kernel y algunos comandos para cubrir decisiones de seguridad de forma reproducible sin root. `tests/kernel_smoke.py` usa flags reales y cambios reales de UID/GID. No consulta un dominio ni toca una instalación OJS real.

## Despliegue específico del caso

Entorno: AlmaLinux 8.10 con controles adicionales de CWP, nginx delante de Apache, PHP-FPM 8.3.37 y OJS actualizado de 3.4.0.9 a 3.4.0.12. Esta edición tenía rutas y perfil específicos del operador; el repositorio publica su generalización configurable, no la configuración privada.

| Verificación | Resultado observado |
| --- | --- |
| Ensayo con base de datos y documentos independientes | Migración completada; autenticación de administrador, API de envíos y ajustes de flujo correctos. |
| Navegación de producción | Portada, login, artículo, PDF, logo y sitemap respondieron 200 con tipos adecuados. |
| Aislamiento web | Documentos privados, cache, herramientas, subidas ejecutables y PHP no aprobado respondieron 403; rutas conocidas de spam respondieron 410. |
| Apache directo | Acceso a PHP no autorizado bloqueado también en el backend. |
| Runtime PHP | Se comprobó el binario FPM 8.3 del proceso que atendía solicitudes reales. |
| Código | 18.533 archivos aprobados; escritura, chmod y creación de scripts rechazados al usuario de la aplicación. |
| Restauración | Archivo inofensivo cambiado por root durante la prueba restaurado desde el código aprobado y bloqueado de nuevo. |
| Subidas y antivirus | Script inofensivo y patrón estándar de prueba antivirus aislados; cola de análisis final sin pendientes. |
| Reconstrucción simulada | Include de nginx eliminado durante la prueba y reparado por el guardián; probe final 403. |
| Límite de autenticación | Ráfaga de formularios vacíos enviada solo desde el origen de prueba terminó en 429. |
| Planificación | Timer y path habilitados; se observó ejecución posterior automática saludable. |
| Respaldo | Copia nueva completada y archivos con hashes; mantenimiento retirado; ensayo y credenciales temporales eliminados. |

En OJS 3.4.0.12 el visor comprobado conservaba la versión PDF.js 2.6.347 con `isEvalSupported` desactivado por el parche oficial. No se afirma haber migrado ese componente a PDF.js 4. La vulnerabilidad oficial se corrigió, pero no se estableció que fuera la entrada original del incidente.

Cada instalación debe repetir sus pruebas de negocio, cabeceras, proxies, límites, pool FPM, kernel y reconstrucciones CWP. El éxito de este caso no garantiza compatibilidad automática con otra revista.

## Ampliación v0.2: adjuntos de revisión

El mismo día se completaron **39 pruebas** con Python 3.6 y PHP 8.3.37, sin omisiones: 17 del guardián original, 17 de la política de adjuntos y 5 del proxy. Incluyen rechazo previo a ejecutar la aplicación PHP, contenido ejecutable inofensivo renombrado, patrón estándar de prueba antivirus, macros, objetos externos, ZIP con expansión excesiva, fallos del scanner, respuesta parcial, escapes por symlink y entrega de los mismos bytes que se analizaron.

En una copia de OJS 3.4.0.12 con base de datos y documentos separados se verificó autenticación y la API real de archivos temporales: PDF, DOCX y DOC válidos devolvieron 200; tres adjuntos de prueba rechazados devolvieron 422 y no crearon registros. La descarga de un PDF válido pasó por el plugin; la copia de ese archivo sustituida por el patrón de prueba fue bloqueada antes de entregar contenido. Se comprobó que el archivo de producción conservaba su hash original.

El análisis histórico examinó 402 documentos e imágenes. No obtuvo detecciones de firmas conocidas de virus; 9 archivos no cumplieron la política: 7 Word con relaciones a objetos externos y 2 con contenido que no correspondía a su extensión. Se conservaron los originales. Estos resultados no demuestran que los 9 archivos sean malware ni descartan amenazas desconocidas.

El proxy de escaneo usa el daemon existente, admite únicamente INSTREAM, autentica UID por el kernel y limita concurrencia/bytes/tiempo. Sus pruebas rechazaron órdenes administrativas y escaneo por ruta sin enviarlos al antivirus. La integración requiere validar el pool real de FPM y la carga del plugin en cada instalación.

En el FPM de producción la conexión Unix fue rechazada; la primera activación se revirtió automáticamente. Se validó TLS mutuo por loopback, manteniendo las restricciones de PHP. Una prueba adicional verificó rechazo de CA o certificado de cliente incorrectos. La activación posterior confirmó navegación y PDF 200, rechazo inmediato 422 del patrón antivirus y del archivo disfrazado, plugin habilitado y control local saludable. El código aprobado pasó a 18.539 archivos.
