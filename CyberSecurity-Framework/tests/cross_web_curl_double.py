#!/usr/bin/python3
"""Mandatory transport double: literal argv/body receipts, no socket imports.

Only new per-case scratch destinations supplied by the real leaf are written.
Programmed times are emitted, never slept. Unknown curl option shapes fail shut.
"""
import json
import os
from pathlib import Path
import sys


def main():
    args = sys.argv[1:]
    record_path = Path(os.environ['CROSS_CURL_RECORDS'])
    program = os.environ['CROSS_CURL_PROGRAM']
    rows = [json.loads(line) for line in record_path.read_text().splitlines()] if record_path.exists() else []
    index = sum(row['program'] == program for row in rows)
    responses = json.loads(Path(program).read_text())
    response = responses[min(index, len(responses) - 1)]
    values = {}
    headers = []
    urls = []
    error = None
    i = 0
    while i < len(args):
        arg = args[i]
        if arg in ('-o', '--output', '-D', '--dump-header', '-w', '--write-out',
                   '-X', '--request', '-H', '--header', '--data-binary', '--max-time'):
            if i + 1 == len(args):
                error = 'Missing option value'
                break
            value = args[i + 1]
            if arg in ('-H', '--header'):
                headers.append(value)
            else:
                values[arg] = value
            i += 2
        elif arg in ('-skS', '-sk', '-skL', '-s', '-S', '-k', '--disable', '--'):
            i += 1
        elif '://' in arg:
            urls.append(arg)
            i += 1
        else:
            error = 'Unreviewed curl option: ' + arg
            break
    body = values.get('--data-binary', '')
    if body.startswith('@'):
        body = Path(body[1:]).read_text()  # capture actual bytes passed by file transport
    row = {'program': program, 'argv': args, 'body': body, 'headers': headers,
           'method': values.get('-X', values.get('--request', 'GET')), 'urls': urls,
           'response': response, 'error': error}
    with record_path.open('a', encoding='utf-8') as stream:
        stream.write(json.dumps(row, ensure_ascii=False) + '\n')
    if error:
        print(error, file=sys.stderr)
        return 2  # even malformed/preconsent invocations remain observable
    code = response['code']
    payload = response.get('body', 'denied')
    output = values.get('-o', values.get('--output'))
    if output and output != '/dev/null':
        Path(output).write_text(payload)
    header_path = values.get('-D', values.get('--dump-header'))
    if header_path:
        Path(header_path).write_text('HTTP/1.1 ' + code + ' Synthetic\r\n' + ''.join(
            key + ': ' + value + '\r\n' for key, value in response.get('headers', {}).items()) + '\r\n')
    fmt = values.get('-w', values.get('--write-out', ''))
    print(fmt.replace('%{http_code}', code).replace('%{size_download}', str(len(payload.encode())))
          .replace('%{time_total}', response.get('time', '0.010')), end='')
    return response.get('rc', 0)


if __name__ == '__main__':
    sys.exit(main())
