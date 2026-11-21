# ojs-fix

**Protección y vigilancia de integridad para Open Journal Systems (OJS) en Linux.** Nace de la recuperación de una revista con spam SEO y accesos no autorizados en Google Search Console. Publicado por Miguel Manyari bajo licencia [MIT](LICENSE).

Código reutilizable para administradores y desarrolladores: perfil por sitio, código inmutable, documentos privados fuera del directorio web, cuarentena de subidas, antivirus y recuperación de configuraciones de nginx/Apache después de cambios de CWP.

> English: a configurable Linux integrity and upload guard for OJS, with per-site web policies and a sanitized incident case study. Requires root, a dedicated account, an approved clean baseline and a filesystem supporting immutable flags. Not an official PKP product.

## Nuevo: antivirus antes de aceptar y entregar adjuntos

La edición v0.2 incorpora una [capa de adjuntos](docs/ATTACHMENTS.md): analiza las subidas antes de que OJS las acepte y las descargas privadas antes de entregarlas al revisor. Comprueba contenido real, formatos Office/PDF, nombres engañosos y componentes activos; si el antivirus falla, bloquea la operación. Necesita el prepend FPM y el plugin de descargas, además del guardián periódico.

## Qué hace

| Capa | Comportamiento |
| --- | --- |
| Código | Bloquea cambios con el atributo inmutable del kernel; verifica archivos y restaura únicamente una copia aprobada por root. |
| Directorios | Bloquea la sustitución del directorio web y pone en cuarentena archivos o directorios de código no aprobados. |
| Documentos | Mantiene `files_dir` fuera del webroot; separa `cache/` y `public/` del código. |
| Subidas | Aísla extensiones ejecutables y enlaces simbólicos; escanea archivos nuevos o modificados con ClamAV en lotes limitados. |
| Web | Ofrece reglas por revista para nginx y Apache, bloqueo de PHP ajeno al front controller y límite de intentos de acceso. |
| CWP | Repara los includes de vhosts definidos en el perfil; admite copias aprobadas de plantillas y metadatos por cuenta. |
| Operación | Timer de un minuto, registros locales, comprobaciones HTTP al origen y mantenimiento explícito para actualizar código y base de datos juntos. |

No instala ni actualiza OJS automáticamente. Primero se corrige y revisa la instalación; después se aprueba su código. La protección no cubre un atacante con acceso root, un administrador que aprueba código malicioso, todos los ataques a la base de datos ni malware desconocido que el antivirus no detecte. Las instalaciones que solo activen el guardián periódico siguen teniendo un intervalo de espera hasta su análisis. Las actualizaciones oficiales siguen siendo necesarias.

## Empezar

1. Lee el [contexto del incidente](docs/CONTEXT.md), los [límites de confianza](SECURITY.md) y la [guía de operación](docs/OPERATIONS.md).
2. Prepara una copia de ensayo con base de datos y documentos independientes. Actualiza OJS desde una distribución oficial compatible.
3. Adapta [profile.example.json](examples/profile.example.json) y los ejemplos de nginx, Apache y PHP-FPM. El dominio y la IP de los ejemplos son ficticios.
4. Revisa las configuraciones y prueba los bloqueos en el origen y en el backend. Aprueba el código limpio en mantenimiento.
5. Activa el timer y conecta tu monitor al resultado del servicio y a `latest.json`/`events.jsonl`.

El perfil predeterminado se instala en `/etc/ojs-fix/profile.json`, propiedad de root, sin escritura para grupo u otros. El estado y las copias aprobadas quedan en `/var/lib/ojs-fix/journal`, modo `0700`. **Ese directorio contiene `config.inc.php` en el archivo sellado y puede contener documentos en cuarentena: nunca se publica en Git.**

```bash
sudo /usr/bin/python3 /usr/local/sbin/ojs-fix --profile /etc/ojs-fix/profile.json --check-config
```

Consulta la guía antes de ejecutar `--approve`: convierte el código presente en una fuente confiable para restauraciones futuras. Las instalaciones y actualizaciones de plugins desde el panel web necesitan mantenimiento administrado por root.

## Pruebas

Sin dependencias externas para las pruebas de regresión:

```bash
python3 -m unittest discover -s tests -v
```

La [prueba opcional del kernel](tests/kernel_smoke.py) requiere root y `CAP_LINUX_IMMUTABLE`. Crea y elimina una instalación ficticia aislada bajo `/var/lib/ojs-fix-test-*`; no lee ninguna revista real:

```bash
sudo python3 tests/kernel_smoke.py --uid 65534 --gid 65534
```

La suite completa tiene **39 pruebas aprobadas** con Python 3.6 y PHP 8.3: las 17 regresiones de integridad originales, 17 de adjuntos y 5 del proxy. Las 17 originales se verificaron también en Python 3.12; además se verificó el bloqueo y restauración reales del kernel. Las pruebas de adjuntos requieren PHP y las del proxy requieren sockets Unix de Linux. La edición específica desplegada en el caso original tiene verificaciones de navegación, PDF, login, cuarentena, antivirus, recuperación de configuración y ejecución automática. La generalización pública usa un perfil configurable y requiere validación en cada servidor. Consulta el [registro de validación](docs/VALIDATION.md).

## Por qué surgió

El correo de Search Console decía «Alternate page with proper canonical tag». Ese aviso aislado puede ser normal. En el caso revisado, las URLs afectadas correspondían a spam del incidente anterior. Además había propietarios no autorizados, un archivo de verificación persistente y un sitemap ajeno a la revista.

Se retiraron esos accesos y la verificación, se sustituyó el sitemap, se actualizó OJS y se endureció la cuenta. **No se estableció el punto de entrada original ni la identidad del atacante.** La actividad es compatible con campañas automatizadas de spam SEO; no demuestra un ataque personal ni que todas las revistas con OJS estén comprometidas.

## Fuentes oficiales

- [PKP: seguridad del servidor](https://github.com/pkp/pkp-docs/blob/main/admin-guide/en/securing-your-system.md).
- [PKP: descargas de OJS](https://pkp.sfu.ca/software/ojs/download/).
- [PKP: aviso GHSA-57gv-qm86-cxr9 sobre el visor PDF](https://github.com/pkp/pkp-lib/security/advisories/GHSA-57gv-qm86-cxr9).
- [Google: informe de indexación de páginas](https://support.google.com/webmasters/answer/7440203?hl=es).

Las versiones citadas describen el trabajo verificado el **21 de noviembre de 2026**; consulta PKP para las versiones vigentes al instalar. Se agradecen mejoras acompañadas de pruebas y contexto anonimizado.
