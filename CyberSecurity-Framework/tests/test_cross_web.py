"""Seven closed web contracts, STATIC NOT RUN. No servers or real transports.

Future helper import is inside each pure method, never discovery. Business tests
call the real Bash leaves with mandatory recording curl; no business no-ops.
"""
import json
from pathlib import Path
import unittest
from urllib.parse import parse_qsl, urlsplit

LOGIN = '05_Exploitation/web/web_login_bruteforce.sh'
RATE = '05_Exploitation/web/rate_limit_probe.sh'
FORM = 'application/x-www-form-urlencoded'


class WebTests(unittest.TestCase):
    def fixture(self):
        from cross_module_fixture import CrossModuleFixture
        return CrossModuleFixture('--cross-web')

    def helper(self, fixture):
        import importlib.util
        import sys
        path = fixture.framework / '00_Config/lib/http_fields.py'
        spec = importlib.util.spec_from_file_location('http_fields', path)
        module = importlib.util.module_from_spec(spec)
        sys.modules['http_fields'] = module
        spec.loader.exec_module(module)  # fixture-local only; no host/module fallback
        return module

    def new_text(self, path, text):
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        with path.open('x', encoding='utf-8') as stream:
            stream.write(text)
        return path

    def capture(self, f, target='/login', body='username=alice%40example.test&password=captured&nonce=%2f+',
                content_type=FORM, host='example.test:8443', method='PATCH', name='login.req'):
        return self.new_text(f.repo / name, method + ' ' + target + ' HTTP/1.1\r\nHost: ' + host +
                             '\r\nContent-Type: ' + content_type +
                             '\r\nCookie: synthetic=session\r\nX-Synthetic: keep\r\n\r\n' + body)

    def dictionary(self, f):
        return self.new_text(f.repo / 'synthetic-words.txt', 'a&b=+%\nquote" /ñ\n')

    def login(self, f, request, words, override=None, consent=True):
        f.env.update(BRUTE_ESQUEMA='https', BRUTE_MAX='2', BRUTE_DELAY='0')
        if consent:
            f.env['BRUTE_SI'] = '1'
        args = (str(request), str(words)) + (() if override is None else (override,))
        return f.run_leaf(LOGIN, args)

    def rate(self, f, request, count='2', consent=True):
        f.env.update(RATE_LIMIT_ESQUEMA='https', RATE_LIMIT_RETARDO='0')
        if consent:
            f.env['RATE_LIMIT_SI'] = '1'
        return f.run_leaf(RATE, (str(request), count))

    def logical(self, row, location, name):
        if location == 'query':
            pairs = parse_qsl(urlsplit(row['urls'][0]).query, keep_blank_values=True)
        elif location == 'form':
            pairs = parse_qsl(row['body'], keep_blank_values=True)
        else:
            return json.loads(row['body'])[name]
        matches = [value for key, value in pairs if key == name]
        self.assertEqual(len(matches), 1, row)
        return matches[0]

    def test_pair_composes_locations_and_literals(self):
        f = self.fixture()
        core = self.helper(f)
        from dataclasses import FrozenInstanceError
        Change = core.FieldChange
        change = Change('form', 'password', 'literal')
        with self.assertRaises(FrozenInstanceError):
            change.value = 'mutated'
        literal = 'a&b=+% "\\ / ñ雪\n|$(not-a-command)'
        cases = (
            ('/login?nonce=%2f+', 'username=old&password=old&keep=%2f+', FORM,
             ('form', 'username'), ('form', 'password')),
            ('/login?username=old&password=old&keep=%2f+', 'opaque-body', 'text/plain',
             ('query', 'username'), ('query', 'password')),
            ('/login?username=old&keep=%2f+', 'password=old&keep=%2f+', FORM,
             ('query', 'username'), ('form', 'password')),
            ('/login?password=old&keep=%2f+', 'username=old&keep=%2f+', FORM,
             ('form', 'username'), ('query', 'password')),
            ('/login?username=old&keep=%2f+', '{"password":"old","keep":[1,true,null]}', 'application/json',
             ('query', 'username'), ('json', 'password')),
        )
        for target, body, ct, user, password in cases:
            original = (target, body)
            for candidate in (literal, 'second+literal%20&='):
                with self.subTest(user=user, password=password, candidate=candidate):
                    changed = core.compose_request(target, body, ct, (
                        Change(*user, literal), Change(*password, candidate)))
                    row = {'urls': ['https://example.test' + changed[0]], 'body': changed[1]}
                    self.assertEqual(self.logical(row, *user), literal)
                    self.assertEqual(self.logical(row, *password), candidate)
                    if 'keep=%2f+' in target:
                        self.assertIn('keep=%2f+', changed[0])
                    if 'keep=%2f+' in body:
                        self.assertIn('keep=%2f+', changed[1])
                    if ct == 'text/plain':
                        self.assertEqual(changed[1], body)
                    if ct == 'application/json':
                        self.assertEqual(json.loads(changed[1])['keep'], [1, True, None])
                    self.assertEqual((target, body), original)
        nested = '{"account":{"users":[{"password":"old","active":true}]},"count":3}'
        target, body = core.compose_request('/login?username=old', nested, 'application/json', (
            Change('json', 'account.users.0.password', literal), Change('query', 'username', 'new')))
        self.assertEqual(json.loads(body), {'account': {'users': [{'password': literal, 'active': True}]}, 'count': 3})
        self.assertEqual(parse_qsl(urlsplit(target).query), [('username', 'new')])
        # Literal numeric-token oracle: decoding both sides as default floats
        # would hide underflow/rounding. Token preservation also covers integers
        # beyond Python's normal conversion digit cap and huge finite exponents.
        numeric_body = ('{"password":"old","tiny":1e-400,'
                        '"precise":0.12345678901234567890123456789,'
                        '"huge":1e400,"signed":-0,"nested":[1.2300e-400],'
                        '"text":"1e-400 0.12345678901234567890123456789"}')
        _, exact_body = core.compose_request('/login', numeric_body, 'application/json',
                                             (Change('json', 'password', 'new'),))
        tokens = json.loads(exact_body, parse_float=lambda token: ('number', token),
                            parse_int=lambda token: ('number', token))
        self.assertEqual(tokens, {
            'password': 'new', 'tiny': ('number', '1e-400'),
            'precise': ('number', '0.12345678901234567890123456789'),
            'huge': ('number', '1e400'), 'signed': ('number', '-0'),
            'nested': [('number', '1.2300e-400')],
            'text': '1e-400 0.12345678901234567890123456789',
        })
        long_integer = '7' * 5000
        _, exact_body = core.compose_request('/login', '{"password":"old","keep":' + long_integer + '}',
                                             'application/json', (Change('json', 'password', 'new'),))
        self.assertEqual(json.loads(exact_body, parse_int=lambda token: token)['keep'], long_integer)
        # Literal expected wire bytes, not an expectation generated by the composer.
        self.assertEqual(core.compose_request('/login?%75sername=old&keep=%2f+',
                                              '%70assword=old&keep=%2f+', FORM, (
                                                  Change('query', '%75sername', 'a&b=+%'),
                                                  Change('form', '%70assword', 'a&b=+%'))),
                         ('/login?%75sername=a%26b%3D%2B%25&keep=%2f+',
                          '%70assword=a%26b%3D%2B%25&keep=%2f+'))
        # Total input bound, not an arbitrary small per-field truncation.
        _, body = core.compose_request('/login', 'password=old', FORM,
                                       (Change('form', 'password', 'x' * (1024 * 1024 - 256)),))
        self.assertEqual(len(dict(parse_qsl(body))['password']), 1024 * 1024 - 256)
        # Actual Bash adapter plus existing single-field consumers: real functions,
        # no shell eval, all values supplied by literal driver source in scratch.
        driver = self.new_text(f.output / 'pair.sh', '''source "$1/00_Config/lib/http_request.bash"
HR_METHOD=PATCH; HR_TARGET='/login?username=old&keep=%2f+'; HR_CT=application/x-www-form-urlencoded
HR_BODY='password=old&keep=%2f+'
pair=$(hr_request_pair query username 'a&b=+%' form password $'quote" /ñ\\n|tail') || exit $?
printf '%s\n' "$pair"
printf '%s' "$pair" | hr_pair_part target || exit $?
printf '\n'
printf '%s' "$pair" | hr_pair_part body || exit $?
printf '\n%s\n%s\n%s\n' "$HR_METHOD" "$HR_TARGET" "$HR_BODY"
hr_target_with query username 'legacy%20raw'
printf '\n'
hr_body_with form password 'legacy%20raw'
printf '\n'
hr_params
HR_CT=application/json; HR_BODY='{"users":[{"password":"old","active":true}]}'
hr_params || exit $?
hr_body_with json users.0.password 'legacy"literal' || exit $?
''')
        result = f._run(['/bin/bash', '--noprofile', '--norc', str(driver), str(f.framework)], '')
        self.assertEqual(result.returncode, 0, result.stderr)
        lines = result.stdout.splitlines()
        pair = json.loads(lines[0])
        self.assertEqual(set(pair), {'target', 'body'})
        self.assertEqual(lines[1:3], [pair['target'], pair['body']])
        self.assertEqual(dict(parse_qsl(pair['target'].split('?', 1)[1]))['username'], 'a&b=+%')
        self.assertEqual(dict(parse_qsl(pair['body']))['password'], 'quote" /ñ\n|tail')
        self.assertEqual(lines[3:6], ['PATCH', '/login?username=old&keep=%2f+', 'password=old&keep=%2f+'])
        self.assertIn('/login?username=legacy%20raw&keep=%2f+', result.stdout)
        self.assertIn('password=legacy%20raw&keep=%2f+', result.stdout)
        self.assertIn('form|password|old', result.stdout)
        self.assertIn('query|username|old', result.stdout)
        self.assertIn('json|users.0.password|old', result.stdout)
        self.assertIn('json|users.0.active|true', result.stdout)
        self.assertEqual(json.loads(result.stdout.splitlines()[-1]),
                         {'users': [{'password': 'legacy"literal', 'active': True}]})
        # The fixed CLI consumes the actual NUL frame, not newline/pipe/argv
        # copies of request values. Independently inspect its logical result.
        value = 'literal\n|a&b=+% ñ'
        frame = '\0'.join(('/login?username=old', 'password=old', FORM,
                           'query', 'username', value, 'form', 'password', value, ''))
        result = f._run(['/usr/bin/python3', '-I', '-B',
                         str(f.framework / '00_Config/lib/http_fields.py'), 'compose'], frame)
        self.assertEqual(result.returncode, 0, result.stderr)
        wire_pair = json.loads(result.stdout)
        self.assertEqual(dict(parse_qsl(urlsplit(wire_pair['target']).query)), {'username': value})
        self.assertEqual(dict(parse_qsl(wire_pair['body'])), {'password': value})
        self.assertEqual(f.curl_records(), [])

    def test_pair_rejects_ambiguity(self):
        f = self.fixture()
        core = self.helper(f)
        Change = core.FieldChange
        cases = (
            ('/login', 'password=a&password=b', FORM, (Change('form', 'password', 'x'),)),
            ('/login?password=a&%70assword=b', '', FORM, (Change('query', 'password', 'x'),)),
            ('/login', 'password=a&%70assword=b', FORM, (Change('form', '%70assword', 'x'),)),
            ('/login', 'password=old', FORM, (Change('form', 'password', 'user'), Change('form', 'password', 'pass'))),
            ('/login', '{"password":"a","password":"b"}', 'application/json', (Change('json', 'password', 'x'),)),
            ('/login', '{"a.b":"x","a":{"b":"y"}}', 'application/json', (Change('json', 'a.b', 'x'),)),
            ('/login', '{"users":[]}', 'application/json', (Change('json', 'users.0.password', 'x'),)),
            ('/login', '{"password":"old","keep":"\\ud800"}', 'application/json', (Change('json', 'password', 'x'),)),
            ('/login', '{"password":"old","\\udfff":"keep"}', 'application/json', (Change('json', 'password', 'x'),)),
            ('/login', 'password=old', FORM, (Change('cookie', 'password', 'x'),)),
            ('/login', 'password=old', FORM, (Change('form', 'absent', 'x'),)),
            ('/login?a=1&b=2&c=3', '', FORM, tuple(Change('query', name, 'x') for name in ('a', 'b', 'c'))),
            ('/login', 'password=old', FORM, (Change('form', 'password', '雪' * (1024 * 1024 // 3 + 1)),)),
            ('/login?' + 'q' * (1024 * 1024), 'password=old', FORM, (Change('form', 'password', 'x'),)),
        )
        for target, body, ct, changes in cases:
            before = (target, body, changes)
            with self.subTest(ct=ct, changes=tuple((c.location, c.name) for c in changes)):
                with self.assertRaises(ValueError):
                    core.compose_request(target, body, ct, changes)
                self.assertEqual((target, body, changes), before)
        driver = self.new_text(f.output / 'reject.sh', '''source "$1/00_Config/lib/http_request.bash"
HR_TARGET=/login; HR_BODY='password=a&password=b'; HR_CT=application/x-www-form-urlencoded
hr_request_pair form password literal
''')
        result = f._run(['/bin/bash', '--noprofile', '--norc', str(driver), str(f.framework)], '')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, '')  # no partial request JSON on error
        self.assertTrue(result.stderr)
        # Extraction failures cannot masquerade as an empty successful value.
        for value, part in (('not-json', 'target'), ('{"target":"x"}', 'body'),
                            ('{"target":"x","body":"y"}', 'unknown')):
            driver = self.new_text(f.output / ('extract-' + part + '-' + str(len(value)) + '.sh'),
                                   'source "$1/00_Config/lib/http_request.bash"\n'
                                   'hr_pair_part "$2"\n')
            result = f._run(['/bin/bash', '--noprofile', '--norc', str(driver), str(f.framework), part], value)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(result.stdout, '')
        for frame in ('/login\0password=old\0' + FORM + '\0form\0password\0literal',
                      '\0'.join(('/login', 'password=old', FORM, 'form', 'password', 'x', 'extra', '')),
                      '\0'.join(('/login', 'password=old', FORM, 'form', 'password', 'x' * (1024 * 1024), ''))):
            result = f._run(['/usr/bin/python3', '-I', '-B',
                             str(f.framework / '00_Config/lib/http_fields.py'), 'compose'], frame)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(result.stdout, '')
            self.assertTrue(result.stderr)
        frame = '\0'.join(('/login', '{"password":"old","keep":"\\ud800"}', 'application/json',
                           'json', 'password', 'synthetic-secret-not-in-diagnostic', ''))
        result = f._run(['/usr/bin/python3', '-I', '-B',
                         str(f.framework / '00_Config/lib/http_fields.py'), 'compose'], frame)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, '')
        self.assertEqual(result.stderr, 'No se pudo componer/extraer la petición: entrada inválida o ambigua.\n')
        self.assertNotIn('synthetic-secret-not-in-diagnostic', result.stderr)
        # An unavailable existing interpreter override must not become a partial
        # request or a successful empty result; this is a negative, not a backend.
        driver = self.new_text(f.output / 'interpreter-error.sh', '''source "$1/00_Config/lib/http_request.bash"
HR_TARGET=/login; HR_BODY=password=old; HR_CT=application/x-www-form-urlencoded
HTTP_REQUEST_PYTHON=/unavailable-synthetic-interpreter
hr_request_pair form password literal
''')
        result = f._run(['/bin/bash', '--noprofile', '--norc', str(driver), str(f.framework)], '')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, '')
        self.assertTrue(result.stderr)
        self.assertEqual(f.curl_records(), [])

    def test_login_req_transmits_each_candidate(self):
        cases = (
            ('/login?nonce=%2f+', 'username=alice%40example.test&password=captured&nonce=%2f+', FORM, 'form', 'form'),
            ('/login?username=alice%40example.test&password=captured&nonce=%2f+', '', FORM, 'query', 'query'),
            ('/login?nonce=%2f+', '{"username":"alice@example.test","password":"captured","keep":[1,true,null]}', 'application/json', 'json', 'json'),
            ('/login?username=alice%40example.test&nonce=%2f+', 'password=captured&nonce=%2f+', FORM, 'query', 'form'),
            ('/login?password=captured&nonce=%2f+', 'username=alice%40example.test&nonce=%2f+', FORM, 'form', 'query'),
            ('/login?username=alice%40example.test&nonce=%2f+', '{"password":"captured","keep":false}', 'application/json', 'query', 'json'),
        )
        for target, body, ct, user_loc, pass_loc in cases:
            for override_mode in ('captured', 'argument', 'environment'):
                with self.subTest(user=user_loc, password=pass_loc, override=override_mode):
                    f = self.fixture()
                    request = self.capture(f, target, body, ct)
                    words = self.dictionary(f)
                    f.configure_curl([
                        {'code': '401', 'time': '0.010', 'headers': {}, 'body': 'denied'},
                        {'code': '200', 'time': '0.020', 'headers': {}, 'body': 'accepted-synthetic'},
                    ])
                    override = 'new&user=+% ñ'
                    if override_mode == 'environment':
                        f.env['BRUTE_USUARIO'] = override
                    result = self.login(f, request, words, override if override_mode == 'argument' else None)
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    calls = f.curl_records()
                    self.assertEqual(len(calls), 2, result.stdout + result.stderr)
                    for row, candidate in zip(calls, ('a&b=+%', 'quote" /ñ')):
                        self.assertEqual(row['method'], 'PATCH')
                        self.assertEqual(self.logical(row, pass_loc, 'password'), candidate)
                        self.assertEqual(self.logical(row, user_loc, 'username'),
                                         'alice@example.test' if override_mode == 'captured' else override)
                        self.assertIn('Cookie: synthetic=session', row['headers'])
                        self.assertIn('X-Synthetic: keep', row['headers'])
                        self.assertEqual(urlsplit(row['urls'][0]).scheme, 'https')
                        if 'nonce=%2f+' in target:
                            self.assertIn('nonce=%2f+', row['urls'][0])
                        if 'nonce=%2f+' in body:
                            self.assertIn('nonce=%2f+', row['body'])
                        if ct == 'application/json':
                            self.assertEqual(json.loads(row['body'])['keep'], json.loads(body)['keep'])
                    self.assertNotEqual(self.logical(calls[0], pass_loc, 'password'),
                                        self.logical(calls[1], pass_loc, 'password'))
                    self.assertEqual([row['response']['code'] for row in calls], ['401', '200'])
                    table, = (f.repo / 'scans/web').glob('bruteforce_*.tsv')
                    self.assertEqual([line.split('\t')[2:4] for line in table.read_text().splitlines()[1:]],
                                     [['401', '10'], ['200', '20']])
        # Absolute capture supplies its own scheme; override still wins without
        # a probe, including HTTP on a port commonly assumed to mean TLS.
        for override, expected in ((None, 'https://example.test:8443/login'),
                                   ('http', 'http://example.test:8443/login')):
            f = self.fixture()
            request = self.capture(f, target='https://example.test:8443/login')
            words = self.dictionary(f)
            f.env.update(BRUTE_SI='1', BRUTE_MAX='2')
            if override is not None:
                f.env['BRUTE_ESQUEMA'] = override
            result = f.run_leaf(LOGIN, (str(request), str(words)))
            self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
            calls = f.curl_records()
            self.assertEqual(len(calls), 2)
            self.assertEqual([row['urls'] for row in calls], [[expected], [expected]])
            self.assertEqual([self.logical(row, 'form', 'password') for row in calls],
                             ['a&b=+%', 'quote" /ñ'])
        # Inspect exact numeric lexemes on the wire, not rounded float equality.
        f = self.fixture()
        request = self.capture(f, body='{"username":"alice","password":"old","tiny":1e-400,"precise":0.12345678901234567890123456789}',
                               content_type='application/json')
        words = self.dictionary(f)
        f.env['BRUTE_USUARIO'] = 'environment'
        result = self.login(f, request, words, 'argument')
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        calls = f.curl_records()
        self.assertEqual(len(calls), 2)
        for row in calls:
            parsed = json.loads(row['body'], parse_float=lambda token: token)
            self.assertEqual(parsed['username'], 'environment')
            self.assertEqual(parsed['tiny'], '1e-400')
            self.assertEqual(parsed['precise'], '0.12345678901234567890123456789')

    def test_login_has_no_preconsent_transport(self):
        # Verify the zero-call oracle itself without touching product business:
        # all failures must leave a raw receipt before any fallible input access.
        for failure, stage, error_type in (
                ('unreadable-body', 'body', 'PermissionError'),
                ('missing-body', 'body', 'FileNotFoundError'),
                ('missing-program', 'program', 'FileNotFoundError'),
                ('invalid-program', 'program', 'JSONDecodeError')):
            with self.subTest(double_failure=failure):
                f = self.fixture()
                body = f.repo / 'synthetic-file-body.bin'
                if failure == 'unreadable-body':
                    with body.open('xb') as stream:
                        stream.write(b'private synthetic body\r\n')
                    body.chmod(0o000)  # current new scratch only; cap-drop ALL is mandatory
                if failure == 'missing-program':
                    f.env['CROSS_CURL_PROGRAM'] = str(f.output / 'absent-program.json')
                elif failure == 'invalid-program':
                    program = self.new_text(f.output / 'invalid-program.json', 'not-json')
                    f.env['CROSS_CURL_PROGRAM'] = str(program)
                argv = [str(f.bin / 'curl'), '--data-binary', '@' + str(body),
                        'https://example.test/synthetic-transport-only']
                result = f._run(argv, '')
                self.assertNotEqual(result.returncode, 0)
                raw, = f.curl_invocations()
                self.assertEqual(raw['argv'], argv[1:])
                self.assertEqual(raw['program'], f.env['CROSS_CURL_PROGRAM'])
                self.assertEqual(raw['state'], 'INVOKED')
                self.assertTrue(raw['invocation_id'])
                record, = f.curl_records()
                self.assertEqual(record['invocation_id'], raw['invocation_id'])
                self.assertEqual(record['state'], 'ERROR')
                self.assertEqual(record['failure']['stage'], stage)
                self.assertEqual(record['failure']['type'], error_type)
                self.assertEqual(result.stdout, '')
                self.assertIn('Synthetic curl failure:', result.stderr)
                terminal = f.output / ('curl-result-' + raw['invocation_id'] + '.json')
                self.assertEqual(json.loads(terminal.read_text())['failure'], record['failure'])
        # File data are never executed or decoded with newline replacement. The
        # literal byte oracle is independent of the double's base64 producer.
        import base64
        for payload, text in ((b'first\r\nsecond\r\n', 'first\r\nsecond\r\n'),
                              (b'first\r\n\xff\x00\x80last', None)):
            with self.subTest(file_body=payload):
                f = self.fixture()
                body = f.repo / 'synthetic-file-body.bin'
                with body.open('xb') as stream:
                    stream.write(payload)
                argv = [str(f.bin / 'curl'), '--data-binary', '@' + str(body),
                        'https://example.test/synthetic-transport-only']
                result = f._run(argv, '')
                self.assertEqual(result.returncode, 0, result.stderr)
                raw, = f.curl_invocations()
                self.assertEqual(raw['argv'], argv[1:])
                record, = f.curl_records()
                self.assertEqual(record['state'], 'DONE')
                self.assertEqual(base64.b64decode(record['body_base64'], validate=True), payload)
                self.assertEqual(record['body'], text)
                self.assertEqual(body.read_bytes(), payload)
        scenarios = (
            ({'BRUTE_SI': '1'}, 'example.test', 'username=a&password=b', 'local'),
            ({'BRUTE_SI': '1'}, 'example.test:443', 'username=a&password=b', 'local'),
            ({'BRUTE_SI': '1', 'BRUTE_ESQUEMA': 'ftp'}, 'example.test', 'username=a&password=b', 'remote'),
            ({'BRUTE_ESQUEMA': 'https'}, 'example.test', 'username=a&password=b', 'remote'),
            ({}, 'example.test', 'username=a&password=b', 'remote'),  # EOF + missing consent
            ({'BRUTE_SI': '1', 'BRUTE_ESQUEMA': 'https'}, 'example.test', 'username=a&password=b&%70assword=c', 'local'),
            ({'BRUTE_SI': '1', 'BRUTE_ESQUEMA': 'https', 'BRUTE_USUARIO_CAMPO': 'password'}, 'example.test', 'username=a&password=b', 'local'),
            ({'BRUTE_SI': '1', 'BRUTE_ESQUEMA': 'https', 'BRUTE_MAX': '1001'}, 'example.test', 'username=a&password=b', 'remote'),
            ({'BRUTE_SI': '1', 'BRUTE_ESQUEMA': ''}, 'example.test', 'username=a&password=b', 'remote'),
            ({'BRUTE_SI': '1', 'BRUTE_ESQUEMA': 'https'}, 'example.test', 'username=a&password=b&%70assword=c', 'remote'),
            ({'BRUTE_SI': '1', 'BRUTE_ESQUEMA': 'https', 'BRUTE_USUARIO_CAMPO': 'absent'}, 'example.test', 'username=a&password=b', 'remote'),
        )
        for env, host, body, dictionary in scenarios:
            with self.subTest(env=env, host=host, dictionary=dictionary):
                f = self.fixture()
                request = self.capture(f, body=body, host=host)
                words = self.dictionary(f) if dictionary == 'local' else 'https://example.test/synthetic-words'
                f.env.update(env)
                result = f.run_leaf(LOGIN, (str(request), str(words)), stdin='')
                self.assertEqual(f.curl_invocations(), [], result.stdout + result.stderr)
        f = self.fixture()
        request = self.new_text(f.repo / 'invalid.req', 'not an HTTP request')
        words = self.dictionary(f)
        f.env.update(BRUTE_SI='1', BRUTE_ESQUEMA='https')
        result = f.run_leaf(LOGIN, (str(request), str(words)))
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(f.curl_records(), [])
        # Per-candidate composition can fail after local preflight. No partial
        # request, response attribution or subsequent candidate may escape.
        f = self.fixture()
        request = self.capture(f)
        words = self.new_text(f.repo / 'oversized-words.txt', 'x' * (1024 * 1024) + '\nnext\n')
        result = self.login(f, request, words)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(f.curl_invocations(), [], result.stdout + result.stderr)
        table, = (f.repo / 'scans/web').glob('bruteforce_*.tsv')
        self.assertEqual(len(table.read_text().splitlines()), 1)
        # Even a success-looking response is not evaluated when curl fails.
        f = self.fixture()
        request = self.capture(f)
        words = self.dictionary(f)
        f.configure_curl([{'code': '200', 'time': '0.010', 'headers': {},
                           'body': 'accepted-synthetic', 'rc': 7}])
        f.env['BRUTE_EXITO_PATRON'] = 'accepted-synthetic'
        result = self.login(f, request, words)
        self.assertNotEqual(result.returncode, 0)
        calls = f.curl_records()
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0]['returncode'], 7)
        table, = (f.repo / 'scans/web').glob('bruteforce_*.tsv')
        self.assertEqual(len(table.read_text().splitlines()), 1)
        f = self.fixture()
        words = self.dictionary(f)
        f.env.update(BRUTE_URL='https://example.test/login', BRUTE_CUERPO='password={password}')
        result = f.run_leaf(LOGIN, ('manual', str(words)), stdin='')
        self.assertEqual(f.curl_records(), [], result.stdout + result.stderr)
        # An explicit manual URL remains a supported mode, not guessed .req TLS.
        f = self.fixture()
        words = self.dictionary(f)
        f.env.update(BRUTE_URL='http://example.test:8080/login', BRUTE_METODO='POST',
                     BRUTE_CUERPO='password={password}', BRUTE_SI='1', BRUTE_MAX='2')
        result = f.run_leaf(LOGIN, ('manual', str(words)))
        self.assertEqual(len(f.curl_records()), 2, result.stdout + result.stderr)
        self.assertTrue(all(row['urls'] == ['http://example.test:8080/login'] for row in f.curl_records()))

    def test_rate_has_no_scheme_probe(self):
        # Literal URLs, not generated by hr_url/rl_url/the tested port policy.
        # HTTP on443/8443 and HTTPS on8080 explicitly contradict port inference.
        for scheme, host, expected_url in (
                ('http', 'example.test:443', 'http://example.test:443/login?nonce=%2f+'),
                ('http', 'example.test:8443', 'http://example.test:8443/login?nonce=%2f+'),
                ('http', 'example.test:8080', 'http://example.test:8080/login?nonce=%2f+'),
                ('http', 'example.test', 'http://example.test/login?nonce=%2f+'),
                ('https', 'example.test:443', 'https://example.test/login?nonce=%2f+'),
                ('https', 'example.test:8443', 'https://example.test:8443/login?nonce=%2f+'),
                ('https', 'example.test:8080', 'https://example.test:8080/login?nonce=%2f+'),
                ('https', 'example.test', 'https://example.test/login?nonce=%2f+')):
            with self.subTest(scheme=scheme, host=host):
                f = self.fixture()
                request = self.capture(f, target='/login?nonce=%2f+', host=host)
                f.env.update(RATE_LIMIT_SI='1', RATE_LIMIT_ESQUEMA=scheme, RATE_LIMIT_RETARDO='0')
                result = f.run_leaf(RATE, (str(request), '2'))
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                calls = f.curl_records()
                self.assertEqual(len(calls), 2)
                for n, row in enumerate(calls, 1):
                    self.assertEqual(row['urls'], [expected_url])
                    self.assertEqual(row['method'], 'PATCH')
                    self.assertEqual(self.logical(row, 'form', 'password'), 'wrong-' + str(n))
                    self.assertEqual(self.logical(row, 'form', 'username'), 'alice@example.test')
        for host in ('example.test:443', 'example.test:8443', 'example.test:8080', 'example.test'):
            for env, count, must_error in (
                    ({'RATE_LIMIT_SI': '1'}, '2', True),
                    ({'RATE_LIMIT_SI': '1', 'RATE_LIMIT_ESQUEMA': 'ftp'}, '2', True),
                    ({'RATE_LIMIT_ESQUEMA': 'https'}, '2', False),  # cancellation/EOF, not invalid input
                    ({}, '2', None),  # missing scheme + EOF: require only zero transport
                    ({'RATE_LIMIT_SI': '1', 'RATE_LIMIT_ESQUEMA': 'https'}, '201', True),
                    ({'RATE_LIMIT_SI': '1', 'RATE_LIMIT_ESQUEMA': 'https'}, '0', True),
                    ({'RATE_LIMIT_SI': '1', 'RATE_LIMIT_ESQUEMA': 'https'}, 'bad', True)):
                with self.subTest(host=host, env=env, count=count):
                    f = self.fixture()
                    request = self.capture(f, host=host)
                    f.env.update(env)
                    result = f.run_leaf(RATE, (str(request), count), stdin='')
                    if must_error is True:
                        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                    elif must_error is False:
                        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    self.assertEqual(f.curl_invocations(), [], result.stdout + result.stderr)
        f = self.fixture()
        request = self.new_text(f.repo / 'invalid.req', 'not an HTTP request')
        result = self.rate(f, request)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(f.curl_records(), [])

    def test_rate_403_and_existing_verdicts(self):
        def response(code, time='0.010', headers=None):
            return {'code': code, 'time': time, 'headers': headers or {}, 'body': 'denied'}
        scenarios = (
            ([response('401')], 2, 'SIN FRENO', 0, 2),
            ([response('403')], 12, 'NO DETERMINADO', 1, 1),
            ([response('403', '2.000')], 12, 'NO DETERMINADO', 1, 1),
            ([response('403', headers={'Retry-After': 'Wed, 21 Oct 2037 07:28:00 GMT'})], 2, 'FRENADO', 0, 1),
            ([response('403', headers={'X-RateLimit-Remaining': '0'})], 2, 'FRENADO', 0, 1),
            ([response('429')], 2, 'FRENADO', 0, 1),
            ([response('503')], 2, 'FRENADO', 0, 1),
            ([response('000')], 2, 'NO DETERMINADO', 1, 1),
            ([response('200')], 2, 'NO DETERMINADO', 1, 1),
            ([response('302')], 2, 'NO DETERMINADO', 1, 1),
            ([response('401'), response('403')], 3, 'NO DETERMINADO', 1, 2),
            ([response('401')] * 5 + [response('401', '0.500')] * 5, 10, 'FRENADO (por retardo)', 0, 10),
            ([response('401')] * 4 + [response('401', '0.500')] * 5, 9, 'SIN FRENO', 0, 9),
        )
        for responses, count, verdict, rc, sends in scenarios:
            with self.subTest(responses=responses, count=count):
                f = self.fixture()
                request = self.capture(f)
                f.configure_curl(responses)
                result = self.rate(f, request, str(count))
                self.assertEqual(result.returncode, rc, result.stdout + result.stderr)
                self.assertIn('Veredicto: ' + verdict, result.stdout)
                calls = f.curl_records()
                self.assertEqual(len(calls), sends)
                for n, row in enumerate(calls, 1):
                    self.assertEqual(self.logical(row, 'form', 'password'), 'wrong-' + str(n))
                    self.assertEqual(self.logical(row, 'form', 'username'), 'alice@example.test')
                tables = list((f.repo / 'scans/web').glob('rate_limit_*.tsv'))
                self.assertEqual(len(tables), 1)
                lines = tables[0].read_text().splitlines()[1:]
                self.assertEqual(len(lines), sends)
                for n, line in enumerate(lines):
                    expected = responses[min(n, len(responses) - 1)]
                    self.assertEqual(line.split('\t')[1], expected['code'])
                    if 'Retry-After' in expected['headers']:
                        self.assertEqual(line.split('\t')[4], expected['headers']['Retry-After'])

    def test_web_inputs_and_previous_runs_are_preserved(self):
        for leaf in (LOGIN, RATE):
            f = self.fixture()
            request = self.capture(f)
            words = self.dictionary(f)
            sources = [f.framework / relative for relative in f.source_files] + [request, words]
            def identity(path):
                info = path.stat()
                return (path.read_bytes(), info.st_mode, info.st_dev, info.st_ino,
                        info.st_size, info.st_mtime_ns, info.st_ctime_ns, info.st_nlink)
            before = {path: identity(path) for path in sources}
            kind = 'bruteforce' if leaf == LOGIN else 'rate_limit'
            base = f.repo / ('scans/web/' + kind + '_example.test_8443')
            sentinel = self.new_text(base / 'run_previous_synthetic/keep.txt', 'prior synthetic result\n')
            previous = {sentinel: identity(sentinel)}
            runs = []
            for _ in range(2):
                result = self.login(f, request, words) if leaf == LOGIN else self.rate(f, request)
                self.assertEqual(result.returncode, 1 if leaf == LOGIN else 0, result.stdout + result.stderr)
                self.assertEqual({path: identity(path) for path in before}, before)
                self.assertEqual({path: identity(path) for path in previous}, previous)
                created = sorted(p for p in base.iterdir() if p.is_dir() and p.name != 'run_previous_synthetic')
                self.assertEqual(len(created), len(runs) + 1)
                self.assertTrue(set(runs) < set(created))
                runs = created
                previous.update({p: identity(p) for directory in runs for p in directory.rglob('*') if p.is_file()})
            self.assertEqual(len(f.curl_records()), 4)
