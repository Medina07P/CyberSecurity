#!/usr/bin/env python3
"""Uso: python3 orchestrator.py [--target HOST] [--phase FASE] [opciones]."""
from pathlib import Path
import sys

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / '00_Config/lib'))
from automation.cli import main

if __name__ == '__main__':
    sys.exit(main())
