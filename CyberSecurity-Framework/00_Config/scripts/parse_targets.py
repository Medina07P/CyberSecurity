#!/usr/bin/env python3
# ============================================================
#  PARSE_TARGETS.py
#  Parsea targets.txt y genera archivos JSON/CSV
# ============================================================

import os
import json
import csv
import argparse
from pathlib import Path

class TargetParser:
    def __init__(self, targets_file):
        self.targets_file = targets_file
        self.targets = []
        self.parse()
    
    def parse(self):
        """Parsea el archivo targets.txt"""
        with open(self.targets_file) as f:
            for line in f:
                line = line.strip()
                # Saltar comentarios y líneas vacías
                if not line or line.startswith('#'):
                    continue
                
                # Formato: IP|PUERTO|PROTOCOLO|DESCRIPCIÓN|PRIORIDAD
                parts = line.split('|')
                if len(parts) >= 3:
                    target = {
                        "ip": parts[0],
                        "port": parts[1] if parts[1] != '—' else None,
                        "protocol": parts[2] if parts[2] != '—' else None,
                        "description": parts[3] if len(parts) > 3 else "",
                        "priority": parts[4] if len(parts) > 4 else "B"
                    }
                    self.targets.append(target)
    
    def to_json(self, output_file):
        """Exporta a JSON"""
        with open(output_file, 'w') as f:
            json.dump(self.targets, f, indent=2)
        print(f"✅ JSON guardado en: {output_file}")
    
    def to_csv(self, output_file):
        """Exporta a CSV"""
        with open(output_file, 'w', newline='') as f:
            if self.targets:
                writer = csv.DictWriter(f, fieldnames=self.targets[0].keys())
                writer.writeheader()
                writer.writerows(self.targets)
        print(f"✅ CSV guardado en: {output_file}")
    
    def get_ips(self):
        """Obtiene lista de IPs únicas"""
        return sorted(set(t['ip'] for t in self.targets))
    
    def get_services(self):
        """Obtiene resumen de servicios"""
        services = {}
        for t in self.targets:
            key = f"{t['protocol']}:{t['port']}" if t['port'] else t['protocol']
            services[key] = services.get(key, 0) + 1
        return services
    
    def print_summary(self):
        """Muestra resumen en consola"""
        print("\n📊 RESUMEN DE OBJETIVOS")
        print("=" * 50)
        print(f"  Total objetivos: {len(self.targets)}")
        print(f"  IPs únicas: {len(self.get_ips())}")
        print("\n  Servicios encontrados:")
        for service, count in self.get_services().items():
            print(f"    • {service}: {count}")

def main():
    parser = argparse.ArgumentParser(description="Parsea targets.txt")
    parser.add_argument("--input", default="../targets.txt", help="Archivo targets.txt")
    parser.add_argument("--json", help="Exportar a JSON")
    parser.add_argument("--csv", help="Exportar a CSV")
    parser.add_argument("--summary", action="store_true", help="Mostrar resumen")
    
    args = parser.parse_args()
    
    # Buscar archivo
    script_dir = Path(__file__).parent
    input_file = script_dir / args.input
    
    if not input_file.exists():
        print(f"❌ Archivo no encontrado: {input_file}")
        return
    
    tp = TargetParser(input_file)
    
    if args.json:
        tp.to_json(args.json)
    
    if args.csv:
        tp.to_csv(args.csv)
    
    if args.summary or (not args.json and not args.csv):
        tp.print_summary()

if __name__ == "__main__":
    main()
