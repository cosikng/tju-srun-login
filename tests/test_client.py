import json
import os
import socket
import unittest
from unittest.mock import Mock, patch
from urllib.parse import parse_qs, urlsplit

import requests
from requests.adapters import BaseAdapter

from srun.client import Config, SRunClient
from srun.protocol import AuthenticationError, ProtocolError, TransportError

IP = '192.0.2.10'
PROBE_IP = '192.0.2.20'
CONNECTED = (301, '<html>Powered by MiWeb</html>', {'Location': 'https://www.mi.com/'})
SUCCESS = {'error': 'ok', 'res': 'ok', 'ecode': 0, 'suc_msg': 'login_ok'}
ONLINE = {'error': 'ok', 'user_name': 'testuser', 'online_ip': IP}


def blocked(ac='28', ip=IP):
    suffix = '?tjusip=' + ip if ip else ''
    return (200, '<html><script>location.href="http://202.113.9.18/index_' + ac + '.html' + suffix + '"</script></html>', {})


def challenge(token='a' * 64):
    return {'error': 'ok', 'client_ip': IP, 'challenge': token, 'expire': '60'}


class OfflineAdapter(BaseAdapter):
    """保留真实 Session、URL 编码、代理合并与重定向逻辑，只替换网络传输。"""
    def __init__(self, steps):
        self.steps = list(steps)
        self.calls = []

    def send(self, request, **kwargs):
        query = {k: v[0] for k, v in parse_qs(urlsplit(request.url).query, keep_blank_values=True).items()}
        endpoint = 'probe' if request.headers.get('Host') == 'mi.com' else urlsplit(request.url).path.rsplit('/', 1)[1]
        self.calls.append({'endpoint': endpoint, 'query': query, 'url': request.url,
                           'headers': dict(request.headers), **kwargs})
        if not self.steps:
            raise AssertionError('发送了计划外请求')
        expected, result = self.steps.pop(0)
        if endpoint != expected:
            raise AssertionError('访问了计划外接口：' + endpoint)
        if isinstance(result, Exception):
            raise result
        response = requests.Response()
        response.request = request
        response.url = request.url
        response.status_code = 200
        if isinstance(result, dict):
            body = query['callback'] + '(' + json.dumps(result) + ')'
        elif isinstance(result, tuple):
            response.status_code, body, response.headers = result
        else:
            body = result
        response._content = body.encode('utf-8')
        response._content_consumed = True
        return response

    def close(self):
        pass


class ClientTests(unittest.TestCase):
    def setUp(self):
        self.resolver = patch('srun.client.socket.getaddrinfo', return_value=[
            (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, '', (PROBE_IP, 80))]).start()
        self.addCleanup(patch.stopall)

    def client(self, steps, **kwargs):
        session = requests.Session()
        session.proxies = {'http': 'http://127.0.0.1:9', 'https': 'http://127.0.0.1:9', 'all': 'socks5://127.0.0.1:9'}
        session.headers.update({'Proxy-Authorization': 'synthetic-proxy-secret',
                                'Authorization': 'synthetic-auth-secret', 'Cookie': 'pass=synthetic-cookie-secret'})
        waits = []
        client = SRunClient(Config(**kwargs), session=session, sleep=waits.append)
        adapter = OfflineAdapter(steps)
        session.mount('http://', adapter)
        session.mount('https://', adapter)
        self.addCleanup(session.close)
        return client, session, adapter, waits

    def test_blocked_flow_three_requests_without_status(self):
        c, s, a, _ = self.client([('probe', blocked()), ('get_challenge', challenge()), ('srun_portal', SUCCESS)])
        s.cookies.set('pass', 'synthetic-secret')
        self.assertEqual(c.login('testuser', 'dummy'), 'login_ok')
        self.assertEqual([r['endpoint'] for r in a.calls], ['probe', 'get_challenge', 'srun_portal'])
        self.assertEqual(c.request_count, 3)
        self.assertEqual(a.calls[1]['query']['ip'], IP)
        self.assertEqual(a.calls[2]['query']['ac_id'], '28')
        self.assertFalse(any('Cookie' in r['headers'] for r in a.calls))
        self.assertFalse(any('Authorization' in r['headers'] or 'Proxy-Authorization' in r['headers'] for r in a.calls))
        self.assertEqual([r['timeout'] for r in a.calls], [(5, 3), (5, 15), (5, 35)])

    def test_connected_skips_credentials_and_auth(self):
        c, _, a, _ = self.client([('probe', CONNECTED)])
        credentials = Mock(side_effect=AssertionError('不应索取凭据'))
        self.assertEqual(c.login(credentials=credentials), 'already_connected')
        self.assertEqual(len(a.calls), 1)
        credentials.assert_not_called()

    def test_lazy_credentials_only_after_blocked_probe(self):
        c, _, a, _ = self.client([('probe', blocked()), ('get_challenge', challenge()), ('srun_portal', SUCCESS)])
        def credentials():
            self.assertEqual(len(a.calls), 1)
            return 'testuser', 'dummy'
        self.assertEqual(c.login(credentials=credentials), 'login_ok')

    def test_dns_and_http_are_ipv4_only_with_host_header(self):
        c, _, a, _ = self.client([('probe', CONNECTED)])
        c.login()
        self.resolver.assert_called_once_with('mi.com', 80, socket.AF_INET, socket.SOCK_STREAM)
        self.assertEqual(a.calls[0]['url'], 'http://' + PROBE_IP + '/')
        self.assertEqual(a.calls[0]['headers']['Host'], 'mi.com')

    def test_ipv4_dns_failure_does_not_fall_back_to_ipv6(self):
        self.resolver.side_effect = socket.gaierror('test failure')
        c, _, a, waits = self.client([], probe_attempts=2)
        with self.assertRaisesRegex(TransportError, 'IPv4 DNS'):
            c.login()
        self.assertEqual(a.calls, [])
        self.assertEqual(waits, [1])
        self.assertTrue(all(call.args[2] == socket.AF_INET for call in self.resolver.call_args_list))

    def test_injected_ipv6_address_cannot_be_used(self):
        self.resolver.return_value = [(socket.AF_INET6, socket.SOCK_STREAM, socket.IPPROTO_TCP, '', ('2001:db8::1', 80, 0, 0))]
        c, _, a, _ = self.client([], probe_attempts=1)
        with self.assertRaises(TransportError):
            c.login()
        self.assertEqual(a.calls, [])

    def test_environment_system_and_session_proxy_bypassed(self):
        with patch.dict(os.environ, {'HTTP_PROXY': 'http://127.0.0.1:9', 'HTTPS_PROXY': 'http://127.0.0.1:9',
                                     'ALL_PROXY': 'socks5://127.0.0.1:9', 'SRUN_AC_ID': '999'}), \
                patch('requests.sessions.get_environ_proxies', side_effect=AssertionError('不应发现系统代理')):
            c, s, a, _ = self.client([('probe', blocked()), ('get_challenge', challenge()), ('srun_portal', SUCCESS)])
            self.assertFalse(s.trust_env)
            self.assertEqual(s.proxies, {})
            s.proxies.update({'http': 'http://127.0.0.1:9', 'all': 'socks5://127.0.0.1:9'})
            c.login('testuser', 'dummy')
            self.assertTrue(all(not r['proxies'] for r in a.calls))
            self.assertEqual(a.calls[-1]['query']['ac_id'], '28')

    def test_normal_redirect_is_not_followed(self):
        c, _, a, _ = self.client([('probe', CONNECTED)])
        c.login()
        self.assertEqual(len(a.calls), 1)
        self.assertEqual(urlsplit(a.calls[0]['url']).scheme, 'http')

    def test_unknown_response_does_not_authenticate(self):
        for response in [(200, '<html>Unknown</html>', {}), (503, 'unavailable', {}),
                         (302, '', {'Location': 'http://202.113.9.18/index_28.html'})]:
            c, _, a, _ = self.client([('probe', response)])
            with self.assertRaises(ProtocolError):
                c.login('testuser', 'dummy')
            self.assertEqual(len(a.calls), 1)

    def test_no_probe_ip_uses_challenge_server_ip(self):
        c, _, a, _ = self.client([('probe', blocked(ip='')), ('get_challenge', challenge()), ('srun_portal', SUCCESS)])
        c.login('testuser', 'dummy')
        self.assertEqual(a.calls[1]['query']['ip'], '')
        self.assertEqual(a.calls[2]['query']['ip'], IP)

    def test_manual_ip_conflict_stops_after_probe(self):
        c, _, a, _ = self.client([('probe', blocked())])
        with self.assertRaisesRegex(ProtocolError, 'IP 不一致'):
            c.login('testuser', 'dummy', ip='192.0.2.11')
        self.assertEqual(len(a.calls), 1)

    def test_verify_uses_external_probe_not_status(self):
        c, _, a, _ = self.client([('probe', blocked()), ('get_challenge', challenge()), ('srun_portal', SUCCESS), ('probe', CONNECTED)])
        c.login('testuser', 'dummy', verify=True)
        self.assertEqual([r['endpoint'] for r in a.calls], ['probe', 'get_challenge', 'srun_portal', 'probe'])

    def test_verify_rejects_portal_success_without_network_release(self):
        c, _, _, _ = self.client([('probe', blocked()), ('get_challenge', challenge()), ('srun_portal', SUCCESS), ('probe', blocked())])
        with self.assertRaisesRegex(AuthenticationError, '网络仍返回认证入口'):
            c.login('testuser', 'dummy', verify=True)

    def test_login_timeout_reprobes_without_status(self):
        c, _, a, _ = self.client([('probe', blocked()), ('get_challenge', challenge()),
                                 ('srun_portal', requests.ReadTimeout('URL contains secret')), ('probe', CONNECTED)])
        self.assertEqual(c.login('testuser', 'dummy'), 'recovered')
        self.assertEqual([r['endpoint'] for r in a.calls], ['probe', 'get_challenge', 'srun_portal', 'probe'])

    def test_retry_uses_new_probe_ac_and_new_challenge(self):
        c, _, a, waits = self.client([('probe', blocked('16')), ('get_challenge', challenge('a' * 64)),
                                      ('srun_portal', requests.ConnectionError()), ('probe', blocked('28')),
                                      ('get_challenge', challenge('b' * 64)), ('srun_portal', SUCCESS)])
        self.assertEqual(c.login('testuser', 'dummy'), 'login_ok')
        self.assertEqual(waits, [1])
        self.assertEqual([a.calls[i]['query']['ac_id'] for i in (2, 5)], ['16', '28'])
        for key in ('password', 'info', 'chksum'):
            self.assertNotEqual(a.calls[2]['query'][key], a.calls[5]['query'][key])

    def test_uncertain_probe_failure_stops_relogin(self):
        c, _, a, _ = self.client([('probe', blocked()), ('get_challenge', challenge()),
                                 ('srun_portal', requests.ReadTimeout()), ('probe', requests.ReadTimeout())], probe_attempts=1)
        with self.assertRaisesRegex(TransportError, '登录结果不确定'):
            c.login('testuser', 'dummy')
        self.assertEqual(len(a.calls), 4)

    def test_explicit_rejection_not_retried(self):
        c, _, a, _ = self.client([('probe', blocked()), ('get_challenge', challenge()),
                                 ('srun_portal', {'error': 'password_error', 'res': 'fail'})])
        with self.assertRaises(AuthenticationError):
            c.login('testuser', 'dummy')
        self.assertEqual(len(a.calls), 3)

    def test_bas_timeout_reports_discovered_ac(self):
        c, _, _, _ = self.client([('probe', blocked()), ('get_challenge', challenge()),
                                 ('srun_portal', {'error': 'login_error', 'error_msg': 'INFO failed, BAS respond timeout.'})])
        with self.assertRaisesRegex(AuthenticationError, 'ac_id=28'):
            c.login('testuser', 'dummy')

    def test_probe_and_challenge_connect_retries_bounded(self):
        c, _, a, waits = self.client([('probe', requests.ConnectTimeout())] * 2)
        with self.assertRaises(TransportError):
            c.login()
        self.assertEqual(len(a.calls), 2)
        self.assertEqual(waits, [1])
        c, _, a, waits = self.client([('probe', blocked())] + [('get_challenge', requests.ConnectTimeout('secret'))] * 3)
        with self.assertRaises(TransportError) as caught:
            c.login('testuser', 'dummy')
        self.assertNotIn('secret', str(caught.exception))
        self.assertEqual(len(a.calls), 4)
        self.assertEqual(waits, [1, 2])

    def test_malformed_login_recovers_by_probe(self):
        c, _, _, _ = self.client([('probe', blocked()), ('get_challenge', challenge()),
                                 ('srun_portal', '<html>failure</html>'), ('probe', CONNECTED)])
        self.assertEqual(c.login('testuser', 'dummy'), 'recovered')

    def test_login_attempts_bounded(self):
        c, _, a, _ = self.client([('probe', blocked()), ('get_challenge', challenge()),
                                 ('srun_portal', requests.ReadTimeout()), ('probe', blocked()),
                                 ('get_challenge', challenge()), ('srun_portal', requests.ReadTimeout()), ('probe', blocked())])
        with self.assertRaisesRegex(TransportError, '重试上限'):
            c.login('testuser', 'dummy')
        self.assertEqual(len(a.calls), 7)

    def test_log_does_not_contain_auth_secrets(self):
        c, _, a, _ = self.client([('probe', blocked()), ('get_challenge', challenge()), ('srun_portal', SUCCESS)])
        with self.assertLogs('srun', 'DEBUG') as logs:
            c.login('testuser', 'dummy-secret')
        text = '\n'.join(logs.output)
        for secret in ('dummy-secret', 'a' * 64, a.calls[-1]['query']['password'], a.calls[-1]['query']['info'], a.calls[-1]['query']['chksum']):
            self.assertNotIn(secret, text)

    def test_status_is_still_explicitly_available(self):
        c, _, a, _ = self.client([('rad_user_info', ONLINE)])
        self.assertEqual(c.get_status(), ONLINE)
        self.assertEqual(len(a.calls), 1)
        self.resolver.assert_not_called()

    def test_invalid_config_and_no_manual_ac(self):
        for kwargs in ({'portal': 'http://u:p@example.com'}, {'portal': 'file:///tmp'},
                       {'portal': 'http://example.com/path'}, {'portal': 'http://example.com:bad'},
                       {'connect_timeout': 0}, {'probe_read_timeout': float('nan')},
                       {'login_attempts': 0}, {'probe_attempts': 11}, {'backoff': -1}):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                Config(**kwargs)
        with self.assertRaises(TypeError):
            Config(ac_id='28')


if __name__ == '__main__':
    unittest.main()
