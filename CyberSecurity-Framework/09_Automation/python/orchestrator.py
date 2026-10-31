#!/usr/bin/env python3
# ============================================================
#  ORCHESTRATOR - Orquestador de flujo de trabajo
#  Uso: python orchestrator.py --target <IP> [--phase <fase>]
#  Ejemplo: python orchestrator.py --target 192.168.1.10 --full
# ============================================================

import os
import sys
import json
import argparse
import subprocess
from datetime import datetime
from pathlib import Path

class Orchestrator:
    def __init__(self, target, phase=None):
        self.target = target
        self.phase = phase
        # Ruta base del framework: <root>/09_Automation/python/orchestrator.py
        self.root = Path(__file__).resolve().parents[2]
        self.phases = {
            "recon": self.run_recon,
            "scan": self.run_scan,
            "enum": self.run_enum,
            "exploit": self.run_exploit,
            "post": self.run_post,
            "report": self.run_report
        }
        self.phase_order = ["recon", "scan", "enum", "exploit", "post", "report"]

    def execute(self, cmd, cwd=None):
        """Ejecuta un comando en el directorio especificado"""
        try:
            if cwd:
                result = subprocess.run(cmd, shell=True, cwd=str(cwd), capture_output=True, text=True)
            else:
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            
            if result.returncode == 0:
                print(f"  ✅ Comando ejecutado: {cmd}")
                return True
            else:
                print(f"  ❌ Error: {result.stderr[:200] if result.stderr else 'Comando falló'}")
                return False
        except Exception as e:
            print(f"  ❌ Excepción: {e}")
            return False

    def run_recon(self):
        """Ejecuta reconocimiento"""
        print("🔍 EJECUTANDO RECON...")
        script = self.root / "02_Recon" / "scripts" / "auto_recon.sh"
        if script.exists():
            return self.execute(f"./auto_recon.sh {self.target}", cwd=script.parent)
        else:
            print(f"  ❌ Script no encontrado: {script}")
            return False

    def run_scan(self):
        """Ejecuta escaneo"""
        print("📡 EJECUTANDO SCAN...")
        script = self.root / "03_Scanners" / "run_all_scanners.sh"
        if script.exists():
            return self.execute(f"./run_all_scanners.sh {self.target}", cwd=script.parent)
        else:
            print(f"  ❌ Script no encontrado: {script}")
            return False

    def run_enum(self):
        """Ejecuta enumeración"""
        print("📋 EJECUTANDO ENUM...")
        script = self.root / "04_Enumeration" / "run_all_enum.sh"
        if script.exists():
            return self.execute(f"./run_all_enum.sh {self.target}", cwd=script.parent)
        else:
            print(f"  ❌ Script no encontrado: {script}")
            return False

    def run_exploit(self):
        """Ejecuta explotación"""
        print("💥 EJECUTANDO EXPLOIT...")
        script = self.root / "05_Exploitation" / "run_all_exploits.sh"
        if script.exists():
            return self.execute(f"./run_all_exploits.sh {self.target}", cwd=script.parent)
        else:
            print(f"  ❌ Script no encontrado: {script}")
            return False

    def run_post(self):
        """Ejecuta post-explotación"""
        print("🕵️ EJECUTANDO POST-EXPLOTACIÓN...")
        script = self.root / "06_PostExploitation" / "run_all_post.sh"
        if script.exists():
            return self.execute(f"./run_all_post.sh", cwd=script.parent)
        else:
            print(f"  ❌ Script no encontrado: {script}")
            return False

    def run_report(self):
        """Genera reporte"""
        print("📊 GENERANDO REPORTE...")
        report_dir = self.root / "11_Reports"
        report_dir.mkdir(exist_ok=True)
        
        # Generar reporte simple
        report = {
            "target": self.target,
            "date": datetime.now().isoformat(),
            "phases": ["recon", "scan", "enum", "exploit", "post"],
            "status": "completed"
        }
        
        report_file = report_dir / f"report_{self.target}.json"
        with open(report_file, "w") as f:
            json.dump(report, f, indent=2)
        print(f"  ✅ Reporte generado: {report_file}")
        return True

    def run_full(self):
        """Ejecuta todas las fases"""
        print("🔄 EJECUTANDO FLUJO COMPLETO...")
        print("════════════════════════════════════════════════════════")
        for phase in self.phase_order:
            print(f"\n📌 FASE: {phase.upper()}")
            if not self.phases[phase]():
                print(f"  ⚠️ Falló la fase {phase}. Continuando...")
        print("\n✅ FLUJO COMPLETADO")

    def run_phase(self):
        """Ejecuta una fase específica"""
        if self.phase in self.phases:
            self.phases[self.phase]()
        else:
            print(f"❌ Fase no válida: {self.phase}")
            print(f"   Fases disponibles: {', '.join(self.phases.keys())}")

def main():
    parser = argparse.ArgumentParser(description="Orquestador de Red Team")
    parser.add_argument("--target", required=True, help="IP o dominio objetivo")
    parser.add_argument("--phase", help="Fase a ejecutar")
    parser.add_argument("--full", action="store_true", help="Ejecutar flujo completo")
    
    args = parser.parse_args()
    
    orchestrator = Orchestrator(args.target, args.phase)
    
    if args.full:
        orchestrator.run_full()
    elif args.phase:
        orchestrator.run_phase()
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
