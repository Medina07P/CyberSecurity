#!/usr/bin/env python3
"""Generador de informes (obsoleto).

Este script mantiene la CLI --input/--output por compatibilidad con
automatizaciones antiguas, pero delega todo el trabajo al motor de
informes (11_Reports/report_engine.py). No analiza palabras ni
ficheros por su cuenta; cualquier hallazgo debe pasar por el motor.

Uso: python3 report_generator.py --input <DIR> --output <FILE>
"""

import argparse
import os
import subprocess
import sys
from pathlib import Path


def main() -> None:
    print("⚠️  Este script es obsoleto. Use 11_Reports/report_generator.sh "
          "o 11_Reports/report_engine.py directamente.")

    parser = argparse.ArgumentParser(
        description="Compatibilidad: delega en report_engine.py")
    parser.add_argument("--input", required=True,
                        help="Directorio de entrada (→ --scans)")
    parser.add_argument("--output", default="report.html",
                        help="Archivo de salida (el directorio → --salida)")
    args = parser.parse_args()

    # Resolver rutas relativas al framework
    _this = Path(__file__).resolve()
    _framework = _this.parents[2]           # 09_Automation/python/.. -> CyberSecurity-Framework/
    engine = _framework / "11_Reports" / "report_engine.py"

    scans_dir = str(Path(args.input).resolve())
    out_dir = str(Path(args.output).resolve().parent)

    cmd = [
        sys.executable, str(engine),
        "--scans", scans_dir,
        "--salida", out_dir,
        "--tipo", "ambos",
    ]

    result = subprocess.run(cmd)
    sys.exit(result.returncode)


if __name__ == "__main__":
    main()
