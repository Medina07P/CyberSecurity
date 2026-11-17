#!/usr/bin/env python3
"""Driver ZAP: spider + pasivo contra una API ya levantada, informe de texto.

Uso: zap_driver.py --host HOST --port PUERTO --url URL --salida FICHERO
     [--max-seg SEGUNDOS]

No levanta ni apaga el daemon (eso lo hace zap_scan.sh). Solo habla con la
API ya lista vía python3-zapv2: rastreo (spider), espera del pasivo
(pscan) y alertas (core.alerts). Nunca Active Scan ni AJAX Spider.
"""

import argparse
import sys
import time

import requests
import zapv2


def conectar(host, port):
    proxies = {'http': f'http://{host}:{port}', 'https': f'http://{host}:{port}'}
    return zapv2.ZAPv2(proxies=proxies)


def correr_spider(zap, url, limite):
    scanid = zap.spider.scan(url=url)
    estado = '0'
    while True:
        estado = zap.spider.status(scanid)
        if estado == '100':
            return True, estado
        if time.monotonic() >= limite:
            zap.spider.stop(scanid)
            return False, estado
        time.sleep(0.5)


def esperar_pasivo(zap, limite):
    while True:
        restantes = zap.pscan.records_to_scan
        if str(restantes) == '0':
            return True
        if time.monotonic() >= limite:
            return False
        time.sleep(0.5)


def escribir_informe(path, url, spider_completo, spider_pct, pasivo_completo, alerts):
    lineas = [f'Objetivo: {url}']
    if spider_completo:
        lineas.append('Spider: completo')
        lineas.append('Pasivo: completo' if pasivo_completo else 'Pasivo: parcial')
    else:
        lineas.append(f'Spider: parcial ({spider_pct}%)')
    lineas.append('')
    n = len(alerts)
    if n == 0:
        lineas.append('SIN HALLAZGOS')
    elif n == 1:
        lineas.append('1 hallazgo')
    else:
        lineas.append(f'{n} hallazgos')
    for alerta in alerts:
        lineas.append('{} | {} | {} | {}'.format(
            alerta.get('risk', '?'), alerta.get('confidence', '?'),
            alerta.get('name', '?'), alerta.get('url', '?')))
    with open(path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(lineas) + '\n')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--host', required=True)
    parser.add_argument('--port', required=True, type=int)
    parser.add_argument('--url', required=True)
    parser.add_argument('--salida', required=True)
    parser.add_argument('--max-seg', type=int, default=300)
    args = parser.parse_args()

    limite = time.monotonic() + args.max_seg
    try:
        zap = conectar(args.host, args.port)
        spider_completo, spider_pct = correr_spider(zap, args.url, limite)
        pasivo_completo = False
        alerts = []
        if spider_completo:
            pasivo_completo = esperar_pasivo(zap, limite)
            alerts = zap.core.alerts(baseurl=args.url)
    except requests.exceptions.RequestException:
        with open(args.salida, 'w', encoding='utf-8') as f:
            f.write(f'Objetivo: {args.url}\n'
                    'Error de conexión con la API de ZAP; no se completó nada.\n')
        return 1

    escribir_informe(args.salida, args.url, spider_completo, spider_pct,
                      pasivo_completo, alerts)
    return 0 if (spider_completo and pasivo_completo) else 1


if __name__ == '__main__':
    sys.exit(main())
