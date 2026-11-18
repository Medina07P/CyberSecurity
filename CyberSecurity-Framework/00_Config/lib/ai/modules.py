"""Tabla fija de los 14 módulos del framework (00-13): tecla, nombre y una
línea de qué hace cada uno. Información pública y fija del propio
framework, derivada de ``docs/MENU-OPCIONES.md``; no se genera leyendo disco
para no depender de que cada README tenga un resumen de una línea útil.
"""

MODULES = (
    ("00", "Configuración y claves",
     "valida y edita datos locales (scope, targets, claves de API); no lanza ni autoriza una auditoría"),
    ("01", "OSINT",
     "busca información pública del objetivo (dominios, correos, redes sociales, metadatos)"),
    ("02", "Reconocimiento",
     "descubre hosts, DNS y huellas de red alrededor del objetivo"),
    ("03", "Escáneres",
     "analiza puertos y servicios con Nmap, Nikto, Nuclei y Burp, de básico a avanzado"),
    ("04", "Enumeración de servicios",
     "profundiza en un servicio concreto: SSH, FTP, SMB, LDAP, web, bases de datos"),
    ("05", "Explotación",
     "prueba activa de vulnerabilidades (inyección, fuerza bruta acotada, plantillas); no todo es un exploit funcional"),
    ("06", "Post-explotación",
     "mantenimiento tras el acceso: persistencia, movimiento lateral, botín"),
    ("07", "Wireless y radio",
     "mantenimiento y guías de redes inalámbricas; no transmite ni captura por sí solo"),
    ("08", "Forense",
     "análisis offline por copias de disco, memoria o red, sin tocar el objetivo en vivo"),
    ("09", "Automatización",
     "encadena otras fases bajo permisos explícitos, con vista previa antes de ejecutar"),
    ("10", "Evidencia",
     "organiza capturas, logs y pruebas del objetivo sin adoptarlo como sesión"),
    ("11", "Informes",
     "genera los informes técnico y de cliente a partir de los resultados existentes (tecla R)"),
    ("12", "Base de conocimiento",
     "consulta cheatsheets y referencias técnicas guardadas localmente"),
    ("13", "Laboratorios",
     "abre entornos de práctica (plantillas, VPN, limpieza) para entrenar sin un objetivo real"),
)


def modules_context_block() -> str:
    cabecera = "Módulos del framework (tecla → nombre — qué hace):"
    lineas = ["«%s» %s — %s." % t for t in MODULES]
    return cabecera + "\n" + "\n".join(lineas)
