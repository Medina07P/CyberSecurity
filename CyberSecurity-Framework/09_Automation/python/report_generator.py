#!/usr/bin/env python3
# ============================================================
#  REPORT GENERATOR - Genera reportes profesionales
#  Uso: python report_generator.py --input <DIR> --output <FILE>
#  Ejemplo: python report_generator.py --input ../../11_Reports/ --output report.html
# ============================================================

import os
import sys
import json
import re
import argparse
from datetime import datetime
from pathlib import Path

class ReportGenerator:
    def __init__(self, input_dir, output_file):
        self.input_dir = Path(input_dir)
        self.output_file = output_file
        self.data = {
            "title": "Informe de Auditoría de Seguridad",
            "date": datetime.now().isoformat(),
            "findings": [],
            "summary": {
                "total_files": 0,
                "cves_found": 0,
                "credentials_found": 0,
                "vulnerabilities_found": 0,
                "services_found": []
            },
            "scan_results": {
                "open_ports": [],
                "services": [],
                "os_detected": []
            }
        }

    def collect_findings(self):
        """Recopila hallazgos de los directorios"""
        print("📁 Recopilando hallazgos...")
        print(f"   Directorio: {self.input_dir}")
        
        if not self.input_dir.exists():
            print(f"   ⚠️ Directorio no encontrado: {self.input_dir}")
            return
        
        # Buscar archivos con resultados de escaneo
        for file in self.input_dir.rglob("*.txt"):
            self.data["summary"]["total_files"] += 1
            self.parse_file(file)
        
        # Buscar archivos JSON de escaneos
        for file in self.input_dir.rglob("*.json"):
            self.parse_json(file)
        
        # Buscar directorios de escaneo en todo el framework
        self.collect_scan_results()

    def collect_scan_results(self):
        """Recopila resultados de escaneos de otras fases"""
        framework_root = self.input_dir.parent
        
        # Buscar puertos abiertos
        for file in framework_root.rglob("open_ports.txt"):
            if file.exists():
                with open(file) as f:
                    content = f.read()
                    ports = content.strip().split(',')
                    for port in ports:
                        if port and port not in self.data["scan_results"]["open_ports"]:
                            self.data["scan_results"]["open_ports"].append(port)
        
        # Buscar servicios
        for file in framework_root.rglob("servicios.txt"):
            if file.exists():
                with open(file) as f:
                    for line in f:
                        if line.strip():
                            self.data["scan_results"]["services"].append(line.strip())
        
        # Buscar SO detectado
        for file in framework_root.rglob("os_*.txt"):
            if file.exists():
                with open(file) as f:
                    content = f.read()
                    if "OS" in content or "Linux" in content or "Windows" in content:
                        self.data["scan_results"]["os_detected"].append(content[:100])

    def parse_file(self, file):
        """Parsea un archivo en busca de hallazgos"""
        try:
            with open(file, 'r', errors='ignore') as f:
                content = f.read()
                file_findings = []
                
                # 1. Buscar CVEs
                cves = re.findall(r'CVE-\d{4}-\d{4,}', content, re.IGNORECASE)
                if cves:
                    for cve in cves:
                        file_findings.append({
                            "type": "CVE",
                            "value": cve,
                            "file": str(file)
                        })
                        self.data["summary"]["cves_found"] += 1
                
                # 2. Buscar vulnerabilidades
                vuln_patterns = ['vulnerable', 'exploit', 'injection', 'XSS', 'SQLi', 'RCE']
                for pattern in vuln_patterns:
                    if re.search(pattern, content, re.IGNORECASE):
                        file_findings.append({
                            "type": "VULNERABILITY",
                            "value": pattern,
                            "file": str(file)
                        })
                        self.data["summary"]["vulnerabilities_found"] += 1
                
                # 3. Buscar credenciales
                cred_patterns = ['password', 'pass:', 'user:', 'login:', 'admin:', 'secret', 'key:']
                for pattern in cred_patterns:
                    if re.search(pattern, content, re.IGNORECASE):
                        # Extraer líneas con credenciales
                        for line in content.split('\n'):
                            if re.search(pattern, line, re.IGNORECASE):
                                if len(line.strip()) > 5:
                                    file_findings.append({
                                        "type": "CREDENTIALS",
                                        "value": line.strip()[:100],
                                        "file": str(file)
                                    })
                                    self.data["summary"]["credentials_found"] += 1
                
                # 4. Servicios encontrados
                service_patterns = ['open', 'tcp', 'udp']
                for pattern in service_patterns:
                    if re.search(pattern, content, re.IGNORECASE):
                        for line in content.split('\n'):
                            if 'open' in line.lower() or 'closed' in line.lower():
                                if any(p in line for p in ['tcp', 'udp']):
                                    self.data["scan_results"]["services"].append(line.strip())
                
                self.data["findings"].extend(file_findings)
                
        except Exception as e:
            print(f"  ⚠️ Error al parsear {file}: {e}")

    def parse_json(self, file):
        """Parsea archivos JSON de escaneos"""
        try:
            with open(file, 'r') as f:
                data = json.load(f)
                # Buscar CVEs en JSON
                if isinstance(data, dict):
                    self.search_json(data, str(file))
                elif isinstance(data, list):
                    for item in data:
                        if isinstance(item, dict):
                            self.search_json(item, str(file))
        except:
            pass

    def search_json(self, data, file_path):
        """Busca en un diccionario JSON"""
        for key, value in data.items():
            if isinstance(value, str):
                if 'CVE' in value:
                    cves = re.findall(r'CVE-\d{4}-\d{4,}', value)
                    if cves:
                        for cve in cves:
                            self.data["findings"].append({
                                "type": "CVE",
                                "value": cve,
                                "file": file_path
                            })
                            self.data["summary"]["cves_found"] += 1
            elif isinstance(value, dict):
                self.search_json(value, file_path)
            elif isinstance(value, list):
                for item in value:
                    if isinstance(item, dict):
                        self.search_json(item, file_path)

    def generate_html(self):
        """Genera reporte HTML"""
        html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>{self.data['title']}</title>
    <style>
        body {{ font-family: 'Segoe UI', Arial, sans-serif; margin: 40px; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        h1 {{ color: #2c3e50; border-bottom: 3px solid #3498db; padding-bottom: 10px; }}
        h2 {{ color: #34495e; margin-top: 30px; margin-bottom: 15px; }}
        .meta {{ background: #ecf0f1; padding: 15px; border-radius: 5px; margin: 20px 0; }}
        .meta p {{ margin: 5px 0; }}
        .summary-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin: 20px 0; }}
        .summary-card {{ background: #f8f9fa; padding: 15px; border-radius: 8px; text-align: center; }}
        .summary-card .number {{ font-size: 28px; font-weight: bold; color: #2c3e50; }}
        .summary-card .label {{ color: #7f8c8d; font-size: 14px; }}
        table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
        th, td {{ padding: 12px 15px; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background: #2c3e50; color: white; font-weight: bold; }}
        tr:hover {{ background: #f8f9fa; }}
        .badge {{ display: inline-block; padding: 3px 10px; border-radius: 4px; font-size: 12px; font-weight: bold; }}
        .badge-cve {{ background: #e74c3c; color: white; }}
        .badge-credential {{ background: #f39c12; color: white; }}
        .badge-vuln {{ background: #e67e22; color: white; }}
        .badge-info {{ background: #3498db; color: white; }}
        .footer {{ margin-top: 30px; padding-top: 20px; border-top: 1px solid #ddd; color: #7f8c8d; text-align: center; font-size: 0.9em; }}
    </style>
</head>
<body>
<div class="container">
    <h1>🔒 {self.data['title']}</h1>
    <div class="meta">
        <p><strong>Fecha:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M')}</p>
        <p><strong>Directorio analizado:</strong> {self.input_dir}</p>
    </div>
    
    <h2>📊 Resumen</h2>
    <div class="summary-grid">
        <div class="summary-card">
            <div class="number">{self.data['summary']['cves_found']}</div>
            <div class="label">CVEs Encontrados</div>
        </div>
        <div class="summary-card">
            <div class="number">{self.data['summary']['vulnerabilities_found']}</div>
            <div class="label">Vulnerabilidades</div>
        </div>
        <div class="summary-card">
            <div class="number">{self.data['summary']['credentials_found']}</div>
            <div class="label">Credenciales</div>
        </div>
        <div class="summary-card">
            <div class="number">{self.data['summary']['total_files']}</div>
            <div class="label">Archivos Analizados</div>
        </div>
    </div>
    
    <h2>📋 Hallazgos Detallados</h2>
"""
        if self.data['findings']:
            html += """
    <table>
        <thead><tr><th>Tipo</th><th>Valor</th><th>Archivo</th></tr></thead>
        <tbody>
"""
            for finding in self.data['findings'][:50]:  # Limitar a 50 resultados
                badge_class = "badge-info"
                if finding['type'] == "CVE":
                    badge_class = "badge-cve"
                elif finding['type'] == "CREDENTIALS":
                    badge_class = "badge-credential"
                elif finding['type'] == "VULNERABILITY":
                    badge_class = "badge-vuln"
                
                html += f"""
            <tr>
                <td><span class="badge {badge_class}">{finding['type']}</span></td>
                <td>{finding['value'][:100]}</td>
                <td><small>{Path(finding['file']).name}</small></td>
            </tr>
"""
            html += """
        </tbody>
    </table>
"""
        else:
            html += """
    <p style="text-align:center;color:#7f8c8d;padding:20px;">
        ℹ️ No se encontraron hallazgos en los archivos analizados.<br>
        <small>Esto puede deberse a que el objetivo no tiene vulnerabilidades conocidas</small>
    </p>
"""
        
        # Agregar servicios encontrados
        if self.data['scan_results']['services']:
            html += """
    <h2>🔌 Servicios Detectados</h2>
    <ul>
"""
            for service in self.data['scan_results']['services'][:20]:
                html += f"<li>{service}</li>"
            html += """
    </ul>
"""
        
        html += f"""
    <div class="footer">
        <p>Reporte generado automáticamente por CTF Toolkit Pro</p>
        <p>Total de hallazgos: {len(self.data['findings'])}</p>
    </div>
</div>
</body>
</html>
"""
        
        with open(self.output_file, 'w', encoding='utf-8') as f:
            f.write(html)
        print(f"✅ Reporte HTML generado: {self.output_file}")

    def generate_json(self):
        """Genera reporte JSON"""
        json_file = os.path.splitext(self.output_file)[0] + ".json"
        with open(json_file, 'w') as f:
            json.dump(self.data, f, indent=2, default=str)
        print(f"✅ Reporte JSON generado: {json_file}")

def main():
    parser = argparse.ArgumentParser(description="Generador de Reportes")
    parser.add_argument("--input", required=True, help="Directorio de entrada")
    parser.add_argument("--output", default="report.html", help="Archivo de salida")
    args = parser.parse_args()
    
    generator = ReportGenerator(args.input, args.output)
    generator.collect_findings()
    generator.generate_html()
    generator.generate_json()

if __name__ == "__main__":
    main()
