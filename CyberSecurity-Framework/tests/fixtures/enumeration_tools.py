#!/usr/bin/python3
"""Dobles de binarios: nunca ejecuta herramientas ni accede a red."""
import json
import os
from pathlib import Path
import sys

tool = Path(sys.argv[0]).name
args = sys.argv[1:]
stdin = sys.stdin.read() if tool in ('nc', 'ftp') else ''
with open(os.environ['ENUM_CALLS'], 'a') as f:
    f.write(json.dumps({'tool': tool, 'args': args, 'stdin': stdin,
                       'env': {k: os.environ.get(k) for k in ('HOME', 'MYSQL_PWD', 'PGPASSWORD', 'PGPASSFILE', 'PGSERVICE', 'PGHOSTADDR')}})+'\n')
if os.environ.get('FAKE_FAIL') in (tool, 'all'):
    print('fallo de conexión simulado', file=sys.stderr); sys.exit(7)
deny = os.environ.get('FAKE_DENY') == tool
def option(flag, default=''):
    return args[args.index(flag)+1] if flag in args else default

if tool == 'nmap':
    if '--script-help' in args:
        if os.environ.get('FAKE_NSE_MISSING'):
            sys.exit(1)
        print(option('--script-help')); sys.exit(0)
    target = args[-1]
    ports = option('-p', '22')
    state = os.environ.get('FAKE_PORT_STATE', 'open')
    if '-oG' in args:
        Path(option('-oG')).write_text('Host: '+target+' ()\tPorts: '+', '.join(p+'/'+state+'/tcp//service///' for p in ports.split(','))+'\n')
    body = 'Nmap scan report for '+target+'\n'+ '\n'.join(p+'/tcp '+state+' service' for p in ports.split(','))+'\n'
    script = option('--script')
    if 'ssh-auth-methods' in script: body += '| ssh-auth-methods: Supported authentication methods:\n|_ password,publickey\n'
    if 'ssh-enum-users' in script: body += '| ssh-enum-users: Valid user fixture\n'
    if '-oN' in args and option('-oN') != '-': Path(option('-oN')).write_text(body)
    print(body)
elif tool == 'nc':
    if '-zv' in args or '-z' in args: sys.exit(0)
    if 'INFO' in stdin: print('-NOAUTH Authentication required.' if deny else '# Server\r\nredis_version:7.0\r\ntcp_port:6379')
    elif 'KEYS' in stdin: print('-NOAUTH Authentication required.' if deny else '*1\r\n$7\r\nfixture')
    else: print('220 Fixture FTP ready')
elif tool == 'ftp':
    print('530 Login incorrect.' if deny else '220 Fixture\n230 Login successful.\n150 Listing\nfixture.txt\n226 Transfer complete.')
elif tool == 'ldapsearch':
    if deny: print('ldap_bind: Insufficient access (50)', file=sys.stderr); sys.exit(50)
    if '(objectClass=user)' in args: print('dn: cn=fixture,dc=example,dc=invalid\ncn: fixture\nresult: 0 Success')
    else: print('dn:\nnamingContexts: dc=example,dc=invalid\nresult: 0 Success')
elif tool == 'rpcclient':
    if deny: print('NT_STATUS_ACCESS_DENIED'); sys.exit(1)
    print('user:[fixture] rid:[0x3e9]')
elif tool == 'smbclient':
    if deny: print('session setup failed: NT_STATUS_LOGON_FAILURE'); sys.exit(1)
    print('Sharename       Type      Comment\n---------       ----      -------\npublic          Disk      Fixture')
elif tool == 'enum4linux': print('Domain Name: FIXTURE\nuser:[fixture]')
elif tool == 'mysql':
    if deny: print('ERROR 1045 (28000): Access denied for user', file=sys.stderr); sys.exit(1)
    print('version()\n8.0.30')
elif tool == 'psql':
    if deny: print('FATAL: password authentication failed for user postgres', file=sys.stderr); sys.exit(2)
    print('List of databases\npostgres | postgres' if '\\l' in args else 'version\nPostgreSQL 15.0 on fixture')
elif tool == 'whatweb': print(args[-1]+' [200 OK] HTTPServer[Fixture]')
elif tool == 'curl':
    url = option('--url', args[-1] if args else '')
    method = option('-X', 'GET')
    if method == 'HEAD' and '--head' not in args:
        print('HEAD sin modo no-body: timeout simulado',file=sys.stderr); sys.exit(28)
    mode = os.environ.get('CURL_MODE', 'normal')
    code, body = 200, 'fixture page'
    if mode == 'down': print('fallo conexión', file=sys.stderr); sys.exit(7)
    if mode == 'catchall': body = 'same SPA page'
    elif 'enum_probe_' in url: code, body = 404, 'not found'
    elif 'swagger' in url or 'openapi' in url: body = '{"openapi":"3.0.0","paths":{}}'
    elif 'robots.txt' in url: body = 'User-agent: *\nDisallow: /private'
    elif 'sitemap.xml' in url: body = '<urlset></urlset>'
    elif method == 'OPTIONS': code, body = 204, ''
    elif method in ('PUT', 'DELETE', 'PATCH'): code, body = 405, 'method not allowed'
    if mode == 'block' and method == os.environ.get('CURL_BLOCK_METHOD', 'GET'):
        code, body = 429, 'rate limited'
    headers = 'HTTP/1.1 '+str(code)+' Fixture\r\nContent-Type: text/plain\r\nRetry-After: '+os.environ.get('CURL_RETRY_AFTER', '0')+'\r\n\r\n'
    if '-D' in args: Path(option('-D')).write_text(headers)
    if '-o' in args and option('-o') != '/dev/null': Path(option('-o')).write_text('' if method == 'HEAD' else body)
    if '-w' in args: print(str(code), end='')
    elif '-I' in args or '-sI' in args or '-skI' in args: print(headers)
    else: print(body)
elif tool == 'ffuf':
    status = 429 if os.environ.get('FAKE_FFUF_BLOCK') else 200
    result = {'url': 'http://example.invalid/found', 'status': status, 'length': 12, 'input': {'FUZZ': 'found'}, 'position': 1}
    if '-o' in args: Path(option('-o')).write_text(json.dumps({'results': [result]}))
    if '-json' in args: print(json.dumps(result), flush=True)
