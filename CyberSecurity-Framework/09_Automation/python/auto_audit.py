#!/usr/bin/env python3
# ============================================================
#  AUTO AUDIT - Automatización completa de auditoría
# ============================================================

import os
import sys
import subprocess
import json
import yaml
from datetime import datetime
from pathlib import Path

class AutoAudit:
    def __init__(self, target):
        self.target = target
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        # Resultados en <repo>/scans/audits/, sin depender del cwd
        self.root = Path(__file__).resolve().parents[3]
        self.output_dir = str(
            self.root / "scans" / "audits" /
            f"audit_{self.target}_{self.timestamp}"
        )
        os.makedirs(self.output_dir, exist_ok=True)
        self.phases = {
            "recon": self.run_recon,
            "scan": self.run_scan,
            "enum": self.run_enum,
            "web": self.run_web
        }
        
    def run_phase(self, phase):
        """Ejecuta una fase específica"""
        if phase in self.phases:
            print(f"🚀 Ejecutando fase: {phase}")
            self.phases[phase]()
        else:
            print(f"❌ Fase no encontrada: {phase}")
            
    def run_recon(self):
        """Reconocimiento básico"""
        print("  📡 Reconociendo...")
        os.system(f"nmap -sT -p- -T4 {self.target} -oA {self.output_dir}/recon_ports")
        
    def run_scan(self):
        """Escaneo de vulnerabilidades"""
        print("  🔍 Escaneando vulnerabilidades...")
        os.system(f"nmap --script vuln -sV -p $(grep open {self.output_dir}/recon_ports.nmap | cut -d'/' -f1 | tr '\n' ',' | sed 's/,$//') {self.target} -oA {self.output_dir}/scan_vuln")
        
    def run_enum(self):
        """Enumeración de servicios"""
        print("  📋 Enumerando servicios...")
        os.system(f"enum4linux -a {self.target} > {self.output_dir}/enum4linux.txt")
        
    def run_web(self):
        """Análisis web"""
        print("  🌐 Analizando web...")
        os.system(f"whatweb http://{self.target} > {self.output_dir}/web_tech.txt")
        os.system(f"nikto -h http://{self.target} -output {self.output_dir}/nikto.txt")
        
    def run_full(self):
        """Ejecuta todas las fases"""
        print("🔄 Ejecutando auditoría completa...")
        os.makedirs(self.output_dir, exist_ok=True)
        for phase in self.phases:
            self.run_phase(phase)
        print(f"✅ Auditoría completada en: {self.output_dir}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Uso: python3 auto_audit.py <IP> [--fase]")
        sys.exit(1)
        
    target = sys.argv[1]
    audit = AutoAudit(target)
    
    if len(sys.argv) > 2 and sys.argv[2] in audit.phases:
        audit.run_phase(sys.argv[2])
    else:
        audit.run_full()
