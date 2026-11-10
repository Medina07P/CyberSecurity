"""Catálogo de textos por regla del motor de informes.

Cada regla trae su severidad y confianza por defecto, el título, la
descripción, el impacto de negocio, la recomendación, el esfuerzo y las
referencias. Los parsers solo aportan la clave, el activo, la evidencia y las
variables que conozcan; los textos se completan aquí con valores por defecto,
de modo que toda regla se puede renderizar sin datos.

La descripción nombra la herramienta porque alimenta el informe técnico. El
impacto y la recomendación hablan de negocio y no repiten nombres de
herramientas ni rutas internas: son los que llegan al informe de cliente.
"""

from lib.model import Evidence, Finding

# Severidad y confianza por defecto: (severidad, confianza, título,
# descripción, impacto de cliente, recomendación, esfuerzo, referencias).
_RULES: dict[str, tuple[str, str, str, str, str, str, str, tuple[str, ...]]] = {
    "nmap.open_port": (
        "info",
        "observacion",
        "Puerto de red abierto",
        "nmap obtuvo respuesta en el puerto {puerto} del activo y lo identificó "
        "como {servicio}. Un puerto abierto es superficie de ataque observable: "
        "por sí mismo no es una vulnerabilidad, pero amplía lo que un tercero "
        "puede intentar.",
        "Cada servicio expuesto es una puerta de entrada que debe estar "
        "justificada. Un servicio innecesario o desactualizado puede dar acceso "
        "a información o a sistemas del negocio.",
        "Confirmar que el servicio es necesario, mantenerlo actualizado y "
        "restringirlo a los orígenes que deban usarlo. Cerrar los puertos que "
        "no presten servicio.",
        "bajo",
        ("https://nmap.org/book/man-port-scanning-basics.html",),
    ),
    "nmap.cve": (
        "alta",
        "confirmado",
        "Vulnerabilidad conocida en un servicio expuesto",
        "El script vulners de nmap asoció {cve} al servicio del activo. "
        "Puntuación de referencia: {cvss}. Es una coincidencia de versión, no "
        "una explotación demostrada: hay que confirmarla contra la fuente del "
        "fabricante.",
        "Una vulnerabilidad conocida en un servicio expuesto puede permitir a un "
        "tercero leer, alterar o interrumpir información del negocio si la "
        "versión detectada está afectada.",
        "Verificar la versión real del servicio, aplicar la actualización del "
        "fabricante que corrige la vulnerabilidad y, mientras tanto, limitar el "
        "acceso al servicio.",
        "medio",
        ("https://nvd.nist.gov/", "https://nmap.org/nsedoc/scripts/vulners.html"),
    ),
    "nuclei.template": (
        "media",
        "confirmado",
        "Coincidencia con una firma de vulnerabilidad conocida",
        "nuclei encontró una coincidencia con la plantilla {plantilla} en el "
        "activo. Referencia CVE del hallazgo: {cve_ref}. nuclei confirma que la "
        "firma coincidió, no que la vulnerabilidad se haya explotado; la "
        "plantilla dice qué se comprobó.",
        "La firma detectada corresponde a un problema conocido que puede afectar "
        "a la confidencialidad, integridad o disponibilidad del servicio. La "
        "gravedad real depende de si el activo es alcanzable desde fuera del "
        "negocio.",
        "Revisar la comprobación ejecutada y su referencia, confirmar la versión "
        "afectada y aplicar la corrección del fabricante. Repetir la prueba "
        "después de corregir.",
        "medio",
        ("https://nuclei.projectdiscovery.io/", "https://owasp.org/www-project-top-ten/"),
    ),
    "nikto.cve": (
        "media",
        "confirmado",
        "Referencia a vulnerabilidad conocida en el servidor web",
        "nikto encontró una referencia a {cve} mientras revisaba el servidor "
        "web. La marca sale de una coincidencia de versión o de recurso, no de "
        "una explotación: la confirmación exige revisar la fuente del "
        "fabricante.",
        "Un componente del sitio web con una vulnerabilidad conocida puede ser "
        "aprovechado para alterar el contenido, obtener información o dejar el "
        "servicio fuera de línea.",
        "Actualizar el servidor web y sus componentes, revisar la configuración "
        "publicada y volver a comprobar el recurso señalado.",
        "medio",
        ("https://nvd.nist.gov/", "https://github.com/sullo/nikto"),
    ),
    "nikto.osvdb": (
        "baja",
        "observacion",
        "Recurso o versión obsoleta en el servidor web",
        "nikto registró la referencia OSVDB {osvdb} sobre un recurso del servidor "
        "web. Es una observación de inventario: la base OSVDB está congelada y "
        "la referencia no confirma explotación.",
        "Un recurso o una versión antigua expuesta amplía la superficie de "
        "ataque y puede revelar información útil para un tercero.",
        "Revisar el recurso citado, retirarlo si no es necesario y mantener el "
        "servidor web y sus componentes actualizados.",
        "bajo",
        ("https://github.com/sullo/nikto", "https://www.cirt.net/nikto2"),
    ),
    "ffuf.resource": (
        "info",
        "observacion",
        "Recurso accesible no enlazado",
        "ffuf encontró {recurso} con un tamaño distinto de la respuesta por "
        "defecto, así que no es el eco del servidor. Es inventario de "
        "superficie: un recurso accesible no es una vulnerabilidad y su "
        "contenido no se ha revisado.",
        "Un recurso que no está enlazado puede contener información, paneles o "
        "funcionalidad que el negocio no sabe que expone. Hay que revisar qué se "
        "está publicando.",
        "Revisar el recurso, decidir si debe ser público y, si no lo es, "
        "retirarlo o protegerlo con autenticación y control de acceso.",
        "bajo",
        ("https://github.com/ffuf/ffuf",),
    ),
    "http_inject.cmd": (
        "critica",
        "confirmado",
        "Posible inyección de comandos del sistema",
        "http_inject observó que el parámetro {parametro} altera el tiempo de "
        "respuesta del servidor de forma repetible, señal de ejecución de "
        "comandos del sistema. La clasificación procede del veredicto de la "
        "herramienta y los intentos débiles se descartan.",
        "La ejecución de comandos permite a un atacante operar el servidor con "
        "los permisos del servicio web: leer archivos, modificar datos o usarlo "
        "como punto de entrada a la red interna.",
        "No construir comandos con datos del usuario: usar interfaces que no "
        "invoquen la shell, listas blancas de valores y el mínimo privilegio. "
        "Corregir el parámetro {parametro} y revisar los registros del servidor.",
        "alto",
        (
            "https://cwe.mitre.org/data/definitions/78.html",
            "https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html",
        ),
    ),
    "http_inject.sqli": (
        "critica",
        "confirmado",
        "Posible inyección SQL",
        "http_inject obtuvo un diferencial repetible en el parámetro "
        "{parametro}: la respuesta cambia con el valor inyectado y vuelve a la "
        "línea base con el valor seguro. Es una señal fuerte; confirmar la "
        "inyección es un paso posterior.",
        "Una inyección SQL puede permitir leer o modificar toda la base de "
        "datos, incluidos datos personales y credenciales y, en algunos motores, "
        "ejecutar comandos en el servidor.",
        "Usar consultas parametrizadas, validar el tipo del parámetro "
        "{parametro} y retirar privilegios innecesarios a la cuenta de base de "
        "datos. Confirmar el hallazgo con una prueba adicional autorizada antes "
        "de cerrarlo.",
        "alto",
        (
            "https://cwe.mitre.org/data/definitions/89.html",
            "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
        ),
    ),
    "http_inject.ssti": (
        "critica",
        "confirmado",
        "Posible inyección de plantillas del lado del servidor",
        "La expresión inyectada en el parámetro {parametro} se evaluó en el "
        "servidor y devolvió el resultado aritmético esperado, de forma "
        "repetible. Eso apunta a una plantilla que interpreta datos del usuario.",
        "La evaluación de plantillas puede escalar a ejecución de código en el "
        "servidor y exponer información interna; el alcance depende del motor de "
        "plantillas utilizado.",
        "No pasar datos del usuario como plantilla: usar variables de contexto "
        "escapadas. Actualizar el motor de plantillas y revisar el parámetro "
        "{parametro}.",
        "alto",
        (
            "https://cwe.mitre.org/data/definitions/1336.html",
            "https://portswigger.net/web-security/server-side-template-injection",
        ),
    ),
    "http_inject.xss": (
        "alta",
        "confirmado",
        "Posible ejecución de scripts en el navegador",
        "El valor inyectado en el parámetro {parametro} se reflejó en la "
        "respuesta dentro de un contexto ejecutable. http_inject distingue el "
        "reflejo literal del contexto no ejecutable y solo publica el primero.",
        "Un tercero podría ejecutar acciones en el navegador de un usuario "
        "legítimo: robar su sesión, suplantarlo o modificar lo que ve.",
        "Escapar la salida según el contexto, publicar una política de seguridad "
        "de contenido y validar la entrada del parámetro {parametro}. Revisar el "
        "resto de puntos de reflejo.",
        "medio",
        (
            "https://cwe.mitre.org/data/definitions/79.html",
            "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
        ),
    ),
    "http_inject.redirect": (
        "media",
        "confirmado",
        "Redirección a un destino externo",
        "El parámetro {parametro} controla el destino de una redirección y el "
        "servidor respondió con una ubicación externa al valor inyectado. Solo "
        "se publica cuando el diferencial es repetible.",
        "Una redirección abierta se usa en campañas de suplantación: el enlace "
        "sale del dominio del negocio y lleva al usuario a un sitio controlado "
        "por un tercero.",
        "Aceptar solo destinos de una lista blanca o rutas internas y no "
        "construir la redirección con la entrada del usuario. Revisar el "
        "parámetro {parametro}.",
        "bajo",
        (
            "https://cwe.mitre.org/data/definitions/601.html",
            "https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html",
        ),
    ),
    "sqlmap.sqli": (
        "critica",
        "confirmado",
        "Inyección SQL confirmada",
        "sqlmap confirmó la inyección en el parámetro {parametro} mediante "
        "{tecnica_sqlmap}. El veredicto y la técnica literales están en la "
        "evidencia; un NO DETERMINADO nunca se convierte en inyectable.",
        "Acceso de lectura y, según los privilegios de la cuenta, de escritura a "
        "la base de datos. Puede exponer datos personales, credenciales y "
        "permitir alterar registros.",
        "Parametrizar todas las consultas, revisar el parámetro {parametro}, "
        "limitar los privilegios de la cuenta de base de datos y rotar "
        "credenciales si el acceso pudo quedar expuesto.",
        "alto",
        (
            "https://cwe.mitre.org/data/definitions/89.html",
            "https://github.com/sqlmapproject/sqlmap/wiki/Usage",
        ),
    ),
    "sqli_findings.differential": (
        "media",
        "candidato",
        "Diferencial de respuesta compatible con inyección SQL",
        "sql_injection.sh obtuvo una respuesta distinta de la línea base en el "
        "parámetro {parametro} y solo guardó el diferencial. Es un candidato: el "
        "diferencial no prueba la inyección, así que se publica para revisión, "
        "no como explotación.",
        "Puede indicar una entrada sin validar que, si se confirma, permitiría "
        "consultar o modificar la base de datos. Mientras no se confirme, el "
        "riesgo es potencial.",
        "Repetir la prueba con una herramienta de confirmación sobre una copia "
        "autorizada y, entretanto, revisar la validación y la parametrización "
        "del parámetro {parametro}.",
        "medio",
        (
            "https://cwe.mitre.org/data/definitions/89.html",
            "https://owasp.org/www-community/attacks/SQL_Injection",
        ),
    ),
    "rate_limit.no_throttle": (
        "alta",
        "confirmado",
        "Inicio de sesión sin límite de intentos observable",
        "Se repitieron {intentos} intentos de inicio de sesión contra {endpoint} "
        "variando solo la contraseña y no apareció ningún freno: mismo código de "
        "respuesta y sin retardo creciente. Esto no prueba que el login no tenga "
        "freno más adelante: puede aparecer por IP, por cuenta o tras más "
        "intentos.",
        "Sin freno, un tercero puede probar contraseñas de forma sostenida; si "
        "los usuarios eligen contraseñas débiles o reutilizadas, la cuenta puede "
        "quedar comprometida.",
        "Aplicar límite de intentos por cuenta y por origen con retardo "
        "exponencial, alertas de intentos fallidos y autenticación multifactor "
        "en el acceso.",
        "medio",
        (
            "https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html",
            "https://cwe.mitre.org/data/definitions/799.html",
            "https://www.rfc-editor.org/rfc/rfc6585",
        ),
    ),
    "headers.missing.csp": (
        "media",
        "observacion",
        "Cabecera Content-Security-Policy ausente",
        "La respuesta exitosa del activo no incluye Content-Security-Policy. La "
        "comprobación exige una respuesta 2xx o 3xx pareada; sin ella no se "
        "afirma nada. CSP es la defensa principal frente a la ejecución de "
        "scripts inyectados en el navegador.",
        "Sin esta política, un script inyectado que llegue al navegador "
        "encuentra menos obstáculos para ejecutarse y robar la sesión del "
        "usuario.",
        "Publicar una política de seguridad de contenido que permita solo los "
        "orígenes necesarios, empezando en modo de informe para no romper la "
        "aplicación.",
        "medio",
        (
            "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy",
            "https://owasp.org/www-project-secure-headers/",
        ),
    ),
    "headers.missing.xfo": (
        "media",
        "observacion",
        "Cabecera X-Frame-Options ausente",
        "La respuesta exitosa del activo no incluye X-Frame-Options ni una "
        "directiva frame-ancestors. Se comprobó sobre una respuesta pareada. Sin "
        "esta protección el navegador permite incrustar la página en un marco "
        "ajeno.",
        "Un tercero puede superponer contenido y engañar al usuario para que "
        "pulse acciones en una sesión autenticada.",
        "Enviar X-Frame-Options con DENY o SAMEORIGIN y, preferentemente, la "
        "directiva frame-ancestors en la política de contenido.",
        "bajo",
        (
            "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options",
            "https://owasp.org/www-community/attacks/Clickjacking",
        ),
    ),
    "headers.missing.xcto": (
        "baja",
        "observacion",
        "Cabecera X-Content-Type-Options ausente",
        "La respuesta exitosa del activo no incluye X-Content-Type-Options: "
        "nosniff, comprobado sobre una respuesta pareada. Sin ella el navegador "
        "puede interpretar un archivo con un tipo distinto del declarado.",
        "El navegador podría ejecutar como código un archivo que el negocio solo "
        "pretendía servir como texto o imagen.",
        "Enviar X-Content-Type-Options con nosniff en todas las respuestas y "
        "declarar el tipo de contenido correcto.",
        "bajo",
        (
            "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options",
            "https://owasp.org/www-project-secure-headers/",
        ),
    ),
    "headers.missing.hsts": (
        "media",
        "observacion",
        "Cabecera Strict-Transport-Security ausente",
        "El activo responde por HTTPS pero no envía Strict-Transport-Security, "
        "comprobado sobre una respuesta pareada. Solo se evalúa en activos "
        "HTTPS: en HTTP la cabecera no tendría sentido.",
        "Sin esta cabecera la primera petición puede hacerse por HTTP y ser "
        "interceptada, lo que permite degradar la conexión y leer o alterar el "
        "tráfico.",
        "Enviar Strict-Transport-Security con una vigencia de al menos un año, "
        "incluir los subdominios cuando proceda y evaluar el preload tras "
        "verificar que todo el sitio funciona por HTTPS.",
        "bajo",
        (
            "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security",
            "https://hstspreload.org/",
        ),
    ),
    "api.method": (
        "baja",
        "observacion",
        "Método HTTP con efecto de escritura habilitado",
        "La API respondió a {metodo} sobre el recurso probado (código {codigo}), "
        "un método que modifica estado. Es una observación de configuración: no "
        "se ha demostrado que la operación se ejecute sin autorización.",
        "Si el método no exige autorización, un tercero podría crear, modificar "
        "o borrar datos del negocio.",
        "Deshabilitar los métodos que la API no use y exigir autorización por "
        "recurso y por rol en los que permanezcan.",
        "medio",
        (
            "https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/",
            "https://cwe.mitre.org/data/definitions/749.html",
        ),
    ),
    "ssh.password_auth": (
        "media",
        "observacion",
        "Acceso SSH por contraseña habilitado",
        "El servicio SSH del activo anuncia autenticación por contraseña entre "
        "sus métodos. Es una observación de configuración: no se ha probado "
        "ninguna credencial.",
        "Las contraseñas de SSH se pueden probar por fuerza bruta y suelen "
        "reutilizarse; una cuenta débil abre acceso directo al servidor y desde "
        "ahí a la red interna.",
        "Deshabilitar la autenticación por contraseña y usar claves públicas o "
        "certificados, con acceso restringido por origen y sin la cuenta root.",
        "bajo",
        (
            "https://www.ssh.com/academy/ssh/public-key-authentication",
            "https://www.cisecurity.org/benchmark/distribution",
        ),
    ),
    "db.anonymous": (
        "alta",
        "confirmado",
        "Acceso anónimo a la base de datos",
        "Una consulta sin credenciales devolvió datos de la base de datos y el "
        "extracto de la respuesta queda como evidencia. La herramienta confirma "
        "que la conexión anónima se ejecutó, no qué permisos adicionales concede "
        "la cuenta.",
        "El acceso anónimo expone información sin necesidad de credenciales: "
        "datos de negocio, datos personales o metadatos que facilitan un ataque "
        "mayor.",
        "Exigir autenticación, revocar los accesos anónimos y restringir la "
        "escucha de la base de datos a los orígenes que la necesiten.",
        "medio",
        (
            "https://cwe.mitre.org/data/definitions/306.html",
            "https://owasp.org/www-project-top-ten/",
        ),
    ),
    "exploitation.hallazgo": (
        "alta",
        "confirmado",
        "Hallazgo confirmado en explotación",
        "Una capacidad de explotación se ejecutó con éxito sobre el activo y "
        "quedó registrada como confirmada. El detalle de la ejecución y sus "
        "artefactos se conservan en la evidencia privada del run.",
        "Un acceso o una ejecución confirmada sobre un servicio expuesto permite "
        "a un tercero operar sobre los datos o el sistema afectado.",
        "Corregir la causa raíz del hallazgo, rotar las credenciales que pudieron "
        "quedar expuestas y repetir la prueba autorizada para confirmar el cierre.",
        "alto",
        ("https://owasp.org/www-project-top-ten/",),
    ),
    "exploitation.diferencial": (
        "media",
        "candidato",
        "Diferencial observado en explotación",
        "La ejecución mostró un comportamiento distinto del esperado, pero no "
        "llegó a confirmarse como explotación. Se publica como candidato para "
        "revisión manual.",
        "Un diferencial no probado puede esconder una vulnerabilidad real o un "
        "falso positivo; conviene revisarlo antes de descartarlo.",
        "Repetir la prueba con una confirmación adicional autorizada y, entretanto, "
        "revisar la validación y la configuración del punto afectado.",
        "medio",
        ("https://owasp.org/www-project-top-ten/",),
    ),
    "exploitation.reflexion": (
        "alta",
        "candidato",
        "Reflexión observada en explotación",
        "La ejecución mostró que un valor inyectado se refleja en la respuesta "
        "del activo. Es una señal de reflexión que exige revisión del contexto de "
        "ejecución.",
        "Un valor reflejado puede ejecutarse en el navegador o en el servidor si "
        "no se escapa correctamente, lo que expone a los usuarios o al sistema.",
        "Escapar la salida según el contexto, validar la entrada y revisar el "
        "resto de puntos de reflejo del activo.",
        "medio",
        ("https://cwe.mitre.org/data/definitions/79.html",),
    ),
    "exploitation.guia": (
        "info",
        "observacion",
        "Ejecución de explotación registrada",
        "La capacidad de explotación se ejecutó sobre el activo y quedó registrada "
        "como evidencia operativa. No constituye por sí sola un hallazgo.",
        "Conviene saber qué capacidades se ejecutaron sobre el sistema para "
        "valorar el alcance real del trabajo.",
        "Revisar la evidencia operativa y conservarla como traza de la prueba.",
        "bajo",
        ("https://owasp.org/www-project-top-ten/",),
    ),
}

KNOWN_RULES: tuple[str, ...] = tuple(_RULES)

# Familia de la regla (prefijo) -> (categoría, técnica tal como se cita en el
# informe técnico).
_FAMILIA: dict[str, tuple[str, str]] = {
    "nmap": ("red", "nmap"),
    "nuclei": ("web", "nuclei"),
    "nikto": ("web", "nikto"),
    "ffuf": ("web", "ffuf"),
    "http_inject": ("web", "http_inject.sh (petición capturada)"),
    "sqlmap": ("web", "sqlmap"),
    "sqli_findings": ("web", "sql_injection.sh (diferencial)"),
    "rate_limit": ("web", "rate_limit_probe.sh"),
    "headers": ("web", "cabeceras de respuesta HTTP"),
    "api": ("web", "enum_api.sh"),
    "ssh": ("red", "enum_ssh.sh (ssh-auth-methods)"),
    "db": ("datos", "enum_mysql.sh (consulta anónima)"),
    "exploitation": ("explotacion", "05_Exploitation"),
}

# Valor por defecto de cada hueco. Los textos se leen bien sin variables: la
# regla se puede renderizar siempre, y un placeholder sin dato no parece roto.
_DEFAULTS: dict[str, str] = {
    "endpoint": "el endpoint de autenticación",
    "parametro": "afectado",
    "puerto": "detectado",
    "servicio": "el servicio detectado",
    "recurso": "el recurso detectado",
    "metodo": "un método de escritura",
    "codigo": "2xx",
    "plantilla": "detectada",
    "cve": "un CVE sin determinar",
    "cve_ref": "no consta",
    "cvss": "CVSS no consultado",
    "osvdb": "citada",
    "intentos": "varios",
    "tecnica_sqlmap": "la técnica que identificó la herramienta",
}


def _valores(
    variables: dict[str, str] | None, cve: str | None, cvss: float | None
) -> dict[str, str]:
    """Huecos del texto: defaults, datos del hallazgo y variables del parser."""
    valores = dict(_DEFAULTS)
    if cve:
        valores["cve"] = cve
        valores["cve_ref"] = cve
    if cvss is not None:
        valores["cvss"] = f"CVSS {cvss:g}"
    if variables:
        valores.update({clave: str(valor) for clave, valor in variables.items()})
    return valores


def build(
    rule: str,
    *,
    key: str,
    activo: str,
    evidencia: list[Evidence],
    variables: dict[str, str] | None = None,
    severidad: str | None = None,
    confianza: str | None = None,
    cve: str | None = None,
    cvss: float | None = None,
) -> Finding:
    """Construye un hallazgo con los textos en español de su regla.

    Una regla desconocida lanza `KeyError`: un typo en el nombre no puede
    degradarse a un hallazgo sin texto. La severidad y la confianza del
    llamante se aplican al final, después de las de la regla.
    """
    try:
        sev, conf, titulo, descripcion, impacto, recomendacion, esfuerzo, referencias = _RULES[rule]
    except KeyError:
        raise KeyError(f"regla desconocida en el catálogo: {rule!r}") from None

    valores = _valores(variables, cve, cvss)
    categoria, tecnica = _FAMILIA[rule.split(".", 1)[0]]
    return Finding(
        rule=rule,
        key=key,
        titulo=titulo,
        categoria=categoria,
        severidad=severidad or sev,
        confianza=confianza or conf,
        activo=activo,
        tecnica=tecnica,
        descripcion=descripcion.format(**valores),
        impacto_cliente=impacto.format(**valores),
        recomendacion=recomendacion.format(**valores),
        esfuerzo=esfuerzo,
        cve=cve,
        cvss=cvss,
        evidencia=list(evidencia),
        referencias=list(referencias),
    )
