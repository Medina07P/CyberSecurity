"""Renderizadores de informes técnico y cliente.

Genera informes en Markdown y HTML a partir de un ``Collected`` y metadatos.
El informe técnico incluye evidencia y detalles; el cliente omite paths,
payloads y nombres de herramientas internas.

Solo biblioteca estándar: html, json, pathlib.
"""

import html
import json
from pathlib import Path

from .model import finding_to_dict, finding_from_dict
from .engine import Collected

__all__ = ["write_reports", "to_json", "from_json"]


def to_json(collected: Collected, meta: dict) -> dict:
    """Serializa un ``Collected`` y sus metadatos a un diccionario."""
    return {
        "findings": [finding_to_dict(f) for f in collected.findings],
        "activos": collected.activos,
        "no_evaluable": collected.no_evaluable,
        "descartados": collected.descartados,
        "objetivos": collected.objetivos,
        "evaluado": collected.evaluado,
        "incidencias": collected.incidencias,
        "meta": meta,
    }


def from_json(data: dict) -> tuple[Collected, dict]:
    """Reconstruye un ``Collected`` y metadatos desde un diccionario."""
    findings = [finding_from_dict(f) for f in data["findings"]]
    collected = Collected(
        findings=findings,
        activos=data["activos"],
        no_evaluable=data["no_evaluable"],
        descartados=data["descartados"],
        objetivos=data["objetivos"],
        evaluado=data["evaluado"],
        incidencias=data.get("incidencias", []),
    )
    return collected, data["meta"]


def write_reports(
    collected: Collected,
    meta: dict,
    out_dir: Path,
    tipos: list[str],
) -> list[Path]:
    """Escribe informes en ``out_dir`` para los ``tipos`` indicados.

    ``tipos`` puede contener ``"tecnico"`` y/o ``"cliente"``.
    Para cada tipo se generan ``.md`` y ``.html``.
    Devuelve la lista de rutas creadas.
    """
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []

    if "tecnico" in tipos:
        md = _render_technical_md(collected, meta)
        html_ = _render_technical_html(collected, meta)
        (out_dir / "informe_tecnico.md").write_text(md, encoding="utf-8")
        (out_dir / "informe_tecnico.html").write_text(html_, encoding="utf-8")
        written.extend([out_dir / "informe_tecnico.md", out_dir / "informe_tecnico.html"])

    if "cliente" in tipos:
        md = _render_cliente_md(collected, meta)
        html_ = _render_cliente_html(collected, meta)
        (out_dir / "informe_cliente.md").write_text(md, encoding="utf-8")
        (out_dir / "informe_cliente.html").write_text(html_, encoding="utf-8")
        written.extend([out_dir / "informe_cliente.md", out_dir / "informe_cliente.html"])

    return written


# ---------------------------------------------------------------------------
# Informe técnico
# ---------------------------------------------------------------------------

def _render_technical_md(collected: Collected, meta: dict) -> str:
    """Genera el informe técnico en Markdown."""
    lines: list[str] = []

    # Portada
    lines.append("# Informe técnico")
    lines.append("")
    objetivo = ", ".join(collected.objetivos) if collected.objetivos else "No especificado"
    fecha = meta.get("fecha", "No especificada")
    lines.append(f"**Objetivo:** {objetivo}")
    lines.append(f"**Fecha:** {fecha}")
    alcance = meta.get("alcance", "No especificado")
    lines.append(f"**Alcance:** {alcance}")
    herramientas = meta.get("herramientas", [])
    if herramientas:
        lines.append(f"**Herramientas:** {', '.join(herramientas)}")
    lines.append("")

    # Activos
    lines.append("## Activos")
    lines.append("")
    if collected.activos:
        for host, data in sorted(collected.activos.items()):
            puertos = data.get("puertos", [])
            if puertos:
                puertos_str = ", ".join(f"{p['puerto']}/{p.get('protocolo', 'tcp')}" for p in puertos)
                lines.append(f"- {host}: {puertos_str}")
            else:
                lines.append(f"- {host}")
    else:
        lines.append("No se identificaron activos.")
    lines.append("")

    # Hallazgos confirmados
    lines.append("## Hallazgos")
    lines.append("")
    confirmados = [f for f in collected.findings if f.confianza == "confirmado"]
    if confirmados:
        for f in confirmados:
            lines.append(f"### {f.titulo}")
            lines.append("")
            lines.append(f"**Severidad:** {f.severidad}")
            lines.append(f"**Activo:** {f.activo}")
            lines.append(f"**Técnica:** {f.tecnica}")
            if f.evidencia:
                for e in f.evidencia:
                    linea_str = f":{e.linea}" if e.linea else ""
                    lines.append(f"- **Evidencia:** {e.archivo}{linea_str}")
                    lines.append(f"  ```")
                    lines.append(f"  {e.extracto}")
                    lines.append(f"  ```")
            lines.append(f"- **Descripción:** {f.descripcion}")
            lines.append(f"- **Recomendación:** {f.recomendacion}")
            if f.cve:
                lines.append(f"- **CVE:** {f.cve}")
            if f.cvss is not None:
                lines.append(f"- **CVSS:** {f.cvss}")
            lines.append("")
    else:
        lines.append("No se encontraron hallazgos confirmados.")
        lines.append("")

    # Candidatos
    lines.append("## Candidatos")
    lines.append("")
    candidatos = [f for f in collected.findings if f.confianza == "candidato"]
    if candidatos:
        for f in candidatos:
            lines.append(f"- **{f.titulo}** ({f.severidad}): {f.descripcion}")
    else:
        lines.append("No hay hallazgos candidatos.")
    lines.append("")

    # Observaciones
    lines.append("## Observaciones")
    lines.append("")
    observaciones = [f for f in collected.findings if f.confianza == "observacion"]
    if observaciones:
        for f in observaciones:
            lines.append(f"- **{f.titulo}** ({f.severidad}): {f.descripcion}")
    else:
        lines.append("No hay observaciones.")
    lines.append("")

    # Descartados
    lines.append("## Descartados")
    lines.append("")
    if collected.descartados:
        motivos: dict[str, int] = {}
        for d in collected.descartados:
            motivo = d.get("motivo", "desconocido")
            motivos[motivo] = motivos.get(motivo, 0) + 1
        for motivo, count in sorted(motivos.items()):
            lines.append(f"- {motivo}: {count}")
    else:
        lines.append("No se descartaron hallazgos.")
    lines.append("")

    # Incidencias de ejecución
    lines.append("## Incidencias de ejecución")
    lines.append("")
    if collected.incidencias:
        for inc in collected.incidencias:
            lines.append(f"- {inc.get('fuente', 'desconocido')}: {inc.get('motivo', 'desconocido')}")
    else:
        lines.append("No hubo incidencias de ejecución.")
    lines.append("")

    # No evaluable
    lines.append("## No evaluable")
    lines.append("")
    if collected.no_evaluable:
        for ne in collected.no_evaluable:
            lines.append(f"- {ne.get('fuente', 'desconocido')}: {ne.get('motivo', 'desconocido')}")
    else:
        lines.append("Todos los hallazgos pudieron evaluarse.")
    lines.append("")

    # Metodología
    lines.append("## Metodología")
    lines.append("")
    lines.append("Se aplicaron técnicas de reconocimiento activo y pasivo, escaneo de puertos,")
    lines.append("análisis de vulnerabilidades con herramientas automatizadas y revisión manual")
    lines.append("de hallazgos. Los resultados se clasificaron por severidad y confianza.")
    lines.append("")

    return "\n".join(lines)


def _render_technical_html(collected: Collected, meta: dict) -> str:
    """Genera el informe técnico en HTML con CSS embebido."""
    # Reutilizamos los datos del Markdown pero generamos HTML directamente.
    objetivo = html.escape(", ".join(collected.objetivos) if collected.objetivos else "No especificado")
    fecha = html.escape(str(meta.get("fecha", "No especificada")))
    alcance = html.escape(str(meta.get("alcance", "No especificado")))

    html_parts: list[str] = [
        "<!DOCTYPE html>",
        "<html lang='es'>",
        "<head>",
        "<meta charset='UTF-8'>",
        "<title>Informe técnico</title>",
        "<style>",
        "body { font-family: sans-serif; margin: 2em; }",
        "h1 { color: #333; }",
        "h2 { color: #555; border-bottom: 1px solid #ccc; }",
        "table { border-collapse: collapse; margin: 1em 0; }",
        "th, td { border: 1px solid #ccc; padding: 0.5em; text-align: left; }",
        "code { background: #f4f4f4; padding: 0.2em 0.4em; }",
        "pre { background: #f4f4f4; padding: 1em; overflow-x: auto; }",
        ".critica { color: #d32f2f; font-weight: bold; }",
        ".alta { color: #f57c00; font-weight: bold; }",
        ".media { color: #fbc02d; }",
        ".baja { color: #388e3c; }",
        ".info { color: #1976d2; }",
        "</style>",
        "</head>",
        "<body>",
        "<h1>Informe técnico</h1>",
        f"<p><strong>Objetivo:</strong> {objetivo}</p>",
        f"<p><strong>Fecha:</strong> {fecha}</p>",
        f"<p><strong>Alcance:</strong> {alcance}</p>",
    ]

    herramientas = meta.get("herramientas", [])
    if herramientas:
        herr_str = html.escape(", ".join(herramientas))
        html_parts.append(f"<p><strong>Herramientas:</strong> {herr_str}</p>")

    # Activos
    html_parts.append("<h2>Activos</h2>")
    if collected.activos:
        html_parts.append("<ul>")
        for host, data in sorted(collected.activos.items()):
            puertos = data.get("puertos", [])
            if puertos:
                puertos_str = ", ".join(f"{p['puerto']}/{p.get('protocolo', 'tcp')}" for p in puertos)
                html_parts.append(f"<li>{html.escape(host)}: {html.escape(puertos_str)}</li>")
            else:
                html_parts.append(f"<li>{html.escape(host)}</li>")
        html_parts.append("</ul>")
    else:
        html_parts.append("<p>No se identificaron activos.</p>")

    # Hallazgos
    html_parts.append("<h2>Hallazgos</h2>")
    confirmados = [f for f in collected.findings if f.confianza == "confirmado"]
    if confirmados:
        for f in confirmados:
            sev_class = html.escape(f.severidad)
            html_parts.append(f"<h3>{html.escape(f.titulo)}</h3>")
            html_parts.append(f"<p><strong>Severidad:</strong> <span class='{sev_class}'>{html.escape(f.severidad)}</span></p>")
            html_parts.append(f"<p><strong>Activo:</strong> {html.escape(f.activo)}</p>")
            html_parts.append(f"<p><strong>Técnica:</strong> {html.escape(f.tecnica)}</p>")
            if f.evidencia:
                html_parts.append("<ul>")
                for e in f.evidencia:
                    linea_str = f":{e.linea}" if e.linea else ""
                    html_parts.append(f"<li><strong>Evidencia:</strong> {html.escape(e.archivo)}{html.escape(linea_str)}<pre>{html.escape(e.extracto)}</pre></li>")
                html_parts.append("</ul>")
            html_parts.append(f"<p><strong>Descripción:</strong> {html.escape(f.descripcion)}</p>")
            html_parts.append(f"<p><strong>Recomendación:</strong> {html.escape(f.recomendacion)}</p>")
            if f.cve:
                html_parts.append(f"<p><strong>CVE:</strong> {html.escape(f.cve)}</p>")
            if f.cvss is not None:
                html_parts.append(f"<p><strong>CVSS:</strong> {html.escape(str(f.cvss))}</p>")
    else:
        html_parts.append("<p>No se encontraron hallazgos confirmados.</p>")

    # Candidatos
    html_parts.append("<h2>Candidatos</h2>")
    candidatos = [f for f in collected.findings if f.confianza == "candidato"]
    if candidatos:
        html_parts.append("<ul>")
        for f in candidatos:
            html_parts.append(f"<li><strong>{html.escape(f.titulo)}</strong> ({html.escape(f.severidad)}): {html.escape(f.descripcion)}</li>")
        html_parts.append("</ul>")
    else:
        html_parts.append("<p>No hay hallazgos candidatos.</p>")

    # Observaciones
    html_parts.append("<h2>Observaciones</h2>")
    observaciones = [f for f in collected.findings if f.confianza == "observacion"]
    if observaciones:
        html_parts.append("<ul>")
        for f in observaciones:
            html_parts.append(f"<li><strong>{html.escape(f.titulo)}</strong> ({html.escape(f.severidad)}): {html.escape(f.descripcion)}</li>")
        html_parts.append("</ul>")
    else:
        html_parts.append("<p>No hay observaciones.</p>")

    # Descartados
    html_parts.append("<h2>Descartados</h2>")
    if collected.descartados:
        motivos: dict[str, int] = {}
        for d in collected.descartados:
            motivo = d.get("motivo", "desconocido")
            motivos[motivo] = motivos.get(motivo, 0) + 1
        html_parts.append("<ul>")
        for motivo, count in sorted(motivos.items()):
            html_parts.append(f"<li>{html.escape(motivo)}: {count}</li>")
        html_parts.append("</ul>")
    else:
        html_parts.append("<p>No se descartaron hallazgos.</p>")

    # Incidencias
    html_parts.append("<h2>Incidencias de ejecución</h2>")
    if collected.incidencias:
        html_parts.append("<ul>")
        for inc in collected.incidencias:
            fuente = html.escape(str(inc.get("fuente", "desconocido")))
            motivo = html.escape(str(inc.get("motivo", "desconocido")))
            html_parts.append(f"<li>{fuente}: {motivo}</li>")
        html_parts.append("</ul>")
    else:
        html_parts.append("<p>No hubo incidencias de ejecución.</p>")

    # No evaluable
    html_parts.append("<h2>No evaluable</h2>")
    if collected.no_evaluable:
        html_parts.append("<ul>")
        for ne in collected.no_evaluable:
            fuente = html.escape(str(ne.get("fuente", "desconocido")))
            motivo = html.escape(str(ne.get("motivo", "desconocido")))
            html_parts.append(f"<li>{fuente}: {motivo}</li>")
        html_parts.append("</ul>")
    else:
        html_parts.append("<p>Todos los hallazgos pudieron evaluarse.</p>")

    # Metodología
    html_parts.append("<h2>Metodología</h2>")
    html_parts.append("<p>Se aplicaron técnicas de reconocimiento activo y pasivo, escaneo de puertos,")
    html_parts.append("análisis de vulnerabilidades con herramientas automatizadas y revisión manual")
    html_parts.append("de hallazgos. Los resultados se clasificaron por severidad y confianza.</p>")

    html_parts.extend(["</body>", "</html>"])
    return "\n".join(html_parts)


# ---------------------------------------------------------------------------
# Informe cliente
# ---------------------------------------------------------------------------

def _render_cliente_md(collected: Collected, meta: dict) -> str:
    """Genera el informe cliente en Markdown."""
    lines: list[str] = []

    # Portada
    lines.append("# Informe ejecutivo")
    lines.append("")
    cliente = meta.get("cliente", "No especificado")
    auditor = meta.get("auditor", "No especificado")
    fecha = meta.get("fecha", "No especificada")
    alcance = meta.get("alcance", "No especificado")
    lines.append(f"**Cliente:** {cliente}")
    lines.append(f"**Auditor:** {auditor}")
    lines.append(f"**Fecha:** {fecha}")
    lines.append(f"**Alcance:** {alcance}")
    lines.append("")

    # Resumen ejecutivo
    lines.append("## Resumen ejecutivo")
    lines.append("")
    confirmados = [f for f in collected.findings if f.confianza == "confirmado"]
    lineas_resumen: list[str] = []
    if confirmados:
        criticos = len([f for f in confirmados if f.severidad == "critica"])
        altos = len([f for f in confirmados if f.severidad == "alta"])
        medios = len([f for f in confirmados if f.severidad == "media"])
        bajos = len([f for f in confirmados if f.severidad == "baja"])
        if criticos or altos:
            lineas_resumen.append(f"Se identificaron {criticos + altos} hallazgos de severidad alta o crítica que requieren atención inmediata.")
        if medios:
            lineas_resumen.append(f"Se encontraron {medios} hallazgos de severidad media que deberían abordarse en el corto plazo.")
        if bajos:
            lineas_resumen.append(f"Se detectaron {bajos} hallazgos de severidad baja que pueden incluirse en el plan de endurecimiento.")
    else:
        lineas_resumen.append("No se identificaron hallazgos confirmados durante la evaluación.")
    lines.append(" ".join(lineas_resumen))
    lines.append("")

    # Tabla de riesgo por severidad
    lines.append("## Riesgo por severidad")
    lines.append("")
    lines.append("| Severidad | Cantidad |")
    lines.append("|-----------|----------|")
    for sev in ["critica", "alta", "media", "baja", "info"]:
        count = len([f for f in confirmados if f.severidad == sev])
        lines.append(f"| {sev.capitalize()} | {count} |")
    lines.append("")

    # Hallazgos principales
    lines.append("## Hallazgos principales")
    lines.append("")
    if confirmados:
        for f in confirmados:
            lines.append(f"### {f.titulo}")
            lines.append("")
            lines.append(f"**Qué significa:** {f.impacto_cliente}")
            lines.append(f"**Recomendación:** {f.recomendacion}")
            lines.append(f"**Esfuerzo:** {f.esfuerzo}")
            lines.append("")
    else:
        lines.append("No se identificaron hallazgos confirmados.")
        lines.append("")

    # Plan de acción 30/60/90
    lines.append("## Plan de acción 30/60/90 días")
    lines.append("")
    dias_30 = [f for f in confirmados if f.severidad in ("critica", "alta")]
    dias_60 = [f for f in confirmados if f.severidad == "media"]
    dias_90 = [f for f in confirmados if f.severidad in ("baja", "info")]

    lines.append("### 30 días")
    if dias_30:
        for f in dias_30:
            lines.append(f"- {f.titulo}: {f.recomendacion}")
    else:
        lines.append("- No hay hallazgos críticos o altos que abordar en este plazo.")
    lines.append("")

    lines.append("### 60 días")
    if dias_60:
        for f in dias_60:
            lines.append(f"- {f.titulo}: {f.recomendacion}")
    else:
        lines.append("- No hay hallazgos medios que abordar en este plazo.")
    lines.append("")

    lines.append("### 90 días")
    if dias_90:
        for f in dias_90:
            lines.append(f"- {f.titulo}: {f.recomendacion}")
    else:
        lines.append("- No hay hallazgos bajos o informativos que abordar en este plazo.")
    lines.append("")

    # Endurecimiento (observaciones)
    lines.append("## Endurecimiento")
    lines.append("")
    observaciones = [f for f in collected.findings if f.confianza == "observacion"]
    if observaciones:
        for f in observaciones:
            lines.append(f"- {f.titulo}: {f.recomendacion}")
    else:
        lines.append("No se identificaron oportunidades adicionales de endurecimiento.")
    lines.append("")

    # Límites
    lines.append("## Límites")
    lines.append("")
    candidatos = [f for f in collected.findings if f.confianza == "candidato"]
    if candidatos:
        n = len(candidatos)
        if n == 1:
            lines.append("1 prueba requiere revisión manual para confirmar su impacto real.")
        else:
            lines.append(f"{n} pruebas requieren revisión manual para confirmar su impacto real.")
    else:
        lines.append("Todas las pruebas se completaron y se presentan en este informe.")
    lines.append("")

    # Glosario
    lines.append("## Glosario")
    lines.append("")
    lines.append("- **Crítica:** Vulnerabilidad que permite compromiso inmediato del sistema.")
    lines.append("- **Alta:** Vulnerabilidad que puede ser explotada con esfuerzo moderado.")
    lines.append("- **Media:** Problema de seguridad que debería corregirse en el corto plazo.")
    lines.append("- **Baja:** Problema menor que no representa un riesgo inmediato.")
    lines.append("- **Info:** Observación informativa, no representa un riesgo directo.")
    lines.append("")

    return "\n".join(lines)


def _render_cliente_html(collected: Collected, meta: dict) -> str:
    """Genera el informe cliente en HTML con CSS embebido."""
    cliente = html.escape(str(meta.get("cliente", "No especificado")))
    auditor = html.escape(str(meta.get("auditor", "No especificado")))
    fecha = html.escape(str(meta.get("fecha", "No especificada")))
    alcance = html.escape(str(meta.get("alcance", "No especificado")))

    confirmados = [f for f in collected.findings if f.confianza == "confirmado"]
    candidatos = [f for f in collected.findings if f.confianza == "candidato"]
    observaciones = [f for f in collected.findings if f.confianza == "observacion"]

    html_parts: list[str] = [
        "<!DOCTYPE html>",
        "<html lang='es'>",
        "<head>",
        "<meta charset='UTF-8'>",
        "<title>Informe ejecutivo</title>",
        "<style>",
        "body { font-family: sans-serif; margin: 2em; }",
        "h1 { color: #333; }",
        "h2 { color: #555; border-bottom: 1px solid #ccc; }",
        "table { border-collapse: collapse; margin: 1em 0; }",
        "th, td { border: 1px solid #ccc; padding: 0.5em; text-align: left; }",
        ".critica { color: #d32f2f; font-weight: bold; }",
        ".alta { color: #f57c00; font-weight: bold; }",
        ".media { color: #fbc02d; }",
        ".baja { color: #388e3c; }",
        ".info { color: #1976d2; }",
        "</style>",
        "</head>",
        "<body>",
        "<h1>Informe ejecutivo</h1>",
        f"<p><strong>Cliente:</strong> {cliente}</p>",
        f"<p><strong>Auditor:</strong> {auditor}</p>",
        f"<p><strong>Fecha:</strong> {fecha}</p>",
        f"<p><strong>Alcance:</strong> {alcance}</p>",
    ]

    # Resumen ejecutivo
    html_parts.append("<h2>Resumen ejecutivo</h2>")
    if confirmados:
        criticos = len([f for f in confirmados if f.severidad == "critica"])
        altos = len([f for f in confirmados if f.severidad == "alta"])
        medios = len([f for f in confirmados if f.severidad == "media"])
        bajos = len([f for f in confirmados if f.severidad == "baja"])
        resumen = []
        if criticos or altos:
            resumen.append(f"Se identificaron {criticos + altos} hallazgos de severidad alta o crítica que requieren atención inmediata.")
        if medios:
            resumen.append(f"Se encontraron {medios} hallazgos de severidad media que deberían abordarse en el corto plazo.")
        if bajos:
            resumen.append(f"Se detectaron {bajos} hallazgos de severidad baja que pueden incluirse en el plan de endurecimiento.")
        html_parts.append(f"<p>{html.escape(' '.join(resumen))}</p>")
    else:
        html_parts.append("<p>No se identificaron hallazgos confirmados durante la evaluación.</p>")

    # Tabla de riesgo
    html_parts.append("<h2>Riesgo por severidad</h2>")
    html_parts.append("<table>")
    html_parts.append("<tr><th>Severidad</th><th>Cantidad</th></tr>")
    for sev in ["critica", "alta", "media", "baja", "info"]:
        count = len([f for f in confirmados if f.severidad == sev])
        html_parts.append(f"<tr><td class='{sev}'>{sev.capitalize()}</td><td>{count}</td></tr>")
    html_parts.append("</table>")

    # Hallazgos principales
    html_parts.append("<h2>Hallazgos principales</h2>")
    if confirmados:
        for f in confirmados:
            html_parts.append(f"<h3>{html.escape(f.titulo)}</h3>")
            html_parts.append(f"<p><strong>Qué significa:</strong> {html.escape(f.impacto_cliente)}</p>")
            html_parts.append(f"<p><strong>Recomendación:</strong> {html.escape(f.recomendacion)}</p>")
            html_parts.append(f"<p><strong>Esfuerzo:</strong> {html.escape(f.esfuerzo)}</p>")
    else:
        html_parts.append("<p>No se identificaron hallazgos confirmados.</p>")

    # Plan 30/60/90
    html_parts.append("<h2>Plan de acción 30/60/90 días</h2>")
    dias_30 = [f for f in confirmados if f.severidad in ("critica", "alta")]
    dias_60 = [f for f in confirmados if f.severidad == "media"]
    dias_90 = [f for f in confirmados if f.severidad in ("baja", "info")]

    html_parts.append("<h3>30 días</h3>")
    if dias_30:
        html_parts.append("<ul>")
        for f in dias_30:
            html_parts.append(f"<li>{html.escape(f.titulo)}: {html.escape(f.recomendacion)}</li>")
        html_parts.append("</ul>")
    else:
        html_parts.append("<p>No hay hallazgos críticos o altos que abordar en este plazo.</p>")

    html_parts.append("<h3>60 días</h3>")
    if dias_60:
        html_parts.append("<ul>")
        for f in dias_60:
            html_parts.append(f"<li>{html.escape(f.titulo)}: {html.escape(f.recomendacion)}</li>")
        html_parts.append("</ul>")
    else:
        html_parts.append("<p>No hay hallazgos medios que abordar en este plazo.</p>")

    html_parts.append("<h3>90 días</h3>")
    if dias_90:
        html_parts.append("<ul>")
        for f in dias_90:
            html_parts.append(f"<li>{html.escape(f.titulo)}: {html.escape(f.recomendacion)}</li>")
        html_parts.append("</ul>")
    else:
        html_parts.append("<p>No hay hallazgos bajos o informativos que abordar en este plazo.</p>")

    # Endurecimiento
    html_parts.append("<h2>Endurecimiento</h2>")
    if observaciones:
        html_parts.append("<ul>")
        for f in observaciones:
            html_parts.append(f"<li>{html.escape(f.titulo)}: {html.escape(f.recomendacion)}</li>")
        html_parts.append("</ul>")
    else:
        html_parts.append("<p>No se identificaron oportunidades adicionales de endurecimiento.</p>")

    # Límites
    html_parts.append("<h2>Límites</h2>")
    if candidatos:
        n = len(candidatos)
        if n == 1:
            html_parts.append("<p>1 prueba requiere revisión manual para confirmar su impacto real.</p>")
        else:
            html_parts.append(f"<p>{n} pruebas requieren revisión manual para confirmar su impacto real.</p>")
    else:
        html_parts.append("<p>Todas las pruebas se completaron y se presentan en este informe.</p>")

    # Glosario
    html_parts.append("<h2>Glosario</h2>")
    html_parts.append("<ul>")
    html_parts.append("<li><strong>Crítica:</strong> Vulnerabilidad que permite compromiso inmediato del sistema.</li>")
    html_parts.append("<li><strong>Alta:</strong> Vulnerabilidad que puede ser explotada con esfuerzo moderado.</li>")
    html_parts.append("<li><strong>Media:</strong> Problema de seguridad que debería corregirse en el corto plazo.</li>")
    html_parts.append("<li><strong>Baja:</strong> Problema menor que no representa un riesgo inmediato.</li>")
    html_parts.append("<li><strong>Info:</strong> Observación informativa, no representa un riesgo directo.</li>")
    html_parts.append("</ul>")

    html_parts.extend(["</body>", "</html>"])
    return "\n".join(html_parts)
