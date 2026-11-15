#!/usr/bin/python3
"""Mandatory transport double: literal argv/body receipts, no socket imports.

Only new per-case scratch destinations supplied by the real leaf are written.
Programmed times are emitted, never slept. Unknown curl option shapes fail shut.
"""
import base64
import json
import os
from pathlib import Path
import sys
import uuid


def decode_options(args):
    values = {}
    headers = []
    urls = []
    i = 0
    while i < len(args):
        arg = args[i]
        if arg in ('-o', '--output', '-D', '--dump-header', '-w', '--write-out',
                   '-X', '--request', '-H', '--header', '--data-binary', '--max-time'):
            if i + 1 == len(args):
                raise ValueError('Missing option value')
            value = args[i + 1]
            if arg in ('-H', '--header'):
                headers.append(value)
            else:
                values[arg] = value
            i += 2
        elif arg in ('-skS', '-sk', '-skL', '-s', '-S', '-k', '--disable', '--', '--globoff'):
            i += 1
        elif '://' in arg:
            urls.append(arg)
            i += 1
        else:
            raise ValueError('Unreviewed curl option: ' + arg)
    return values, headers, urls


def main():
    args = sys.argv[1:]
    record_path = Path(os.environ['CROSS_CURL_RECORDS'])
    invocation_id = uuid.uuid4().hex
    program = os.environ.get('CROSS_CURL_PROGRAM')
    raw = {'invocation_id': invocation_id, 'argv': args, 'program': program, 'state': 'INVOKED'}
    # The raw invocation is durable BEFORE prior-log/program parsing, option
    # decoding or file-body reads. No decoded-result failure can erase this call.
    with record_path.open('a', encoding='utf-8') as stream:
        stream.write(json.dumps(raw, ensure_ascii=True) + '\n')
        stream.flush()
        os.fsync(stream.fileno())
    detail = {'state': 'ERROR', 'invocation_id': invocation_id}
    stage = 'program'
    try:
        rows = [json.loads(line) for line in record_path.read_text().splitlines()]
        index = sum(row['program'] == program for row in rows) - 1
        responses = json.loads(Path(program).read_text())
        response = responses[min(index, len(responses) - 1)]
        detail['response'] = response
        stage = 'options'
        values, headers, urls = decode_options(args)
        detail.update(headers=headers, urls=urls,
                      method=values.get('-X', values.get('--request', 'GET')))
        stage = 'body'
        body = values.get('--data-binary', '')
        body_bytes = Path(body[1:]).read_bytes() if body.startswith('@') else os.fsencode(body)
        detail['body_base64'] = base64.b64encode(body_bytes).decode('ascii')
        try:
            detail['body'] = body_bytes.decode('utf-8')  # no newline translation
        except UnicodeDecodeError:
            detail['body'] = None  # bytes are still retained exactly, not replaced
        stage = 'response'
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
        rc = response.get('rc', 0)
        detail.update(state='DONE', returncode=rc)
    except Exception as exc:
        rc = 2
        detail.update(returncode=rc, failure={'stage': stage, 'type': type(exc).__name__,
                                            'message': str(exc), 'errno': getattr(exc, 'errno', None)})
        print('Synthetic curl failure: ' + stage + ': ' + type(exc).__name__, file=sys.stderr)
    # Separate exclusive terminal receipt; never rewrite/adopt the raw invocation.
    result = record_path.parent / ('curl-result-' + invocation_id + '.json')
    fd = os.open(result, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    with os.fdopen(fd, 'w', encoding='utf-8') as stream:
        json.dump(detail, stream, ensure_ascii=True)
        stream.write('\n')
        stream.flush()
        os.fsync(stream.fileno())
    return rc


if __name__ == '__main__':
    sys.exit(main())
