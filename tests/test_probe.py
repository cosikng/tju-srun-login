import unittest

from srun.protocol import ProtocolError, parse_probe

PORTAL = 'http://202.113.9.18'


def page(target):
    return '<html><script type="text/javascript">location.href="' + target + '"</script><body><a href="' + target + '">here</a></body></html>'


class ProbeTests(unittest.TestCase):
    def test_index_js_redirect_and_ip(self):
        result = parse_probe(200, {}, page(PORTAL + '/index_28.html?tjusip=192.0.2.10'), PORTAL)
        self.assertFalse(result.connected)
        self.assertEqual(result.ac_id, '28')
        self.assertEqual(result.ip, '192.0.2.10')

    def test_supported_literal_assignment_forms(self):
        for assignment in ["window.location = 'http://202.113.9.18/index_16.html';",
                           "document.location.href = 'http://202.113.9.18:80/index_21.html';",
                           'location.href="http:\\/\\/202.113.9.18/index_28.html"']:
            result = parse_probe(200, {}, '<script>' + assignment + '</script>', PORTAL)
            self.assertFalse(result.connected)
            self.assertEqual(result.ip, '')

    def test_portal_path_and_html_entities(self):
        result = parse_probe(200, {}, page(PORTAL + '/srun_portal_pc?ac_id=28&amp;sip=192.0.2.10'), PORTAL)
        self.assertEqual(result.ac_id, '28')
        self.assertEqual(result.ip, '192.0.2.10')

    def test_actual_normal_site_redirect(self):
        self.assertTrue(parse_probe(301, {'Location': 'https://www.mi.com/'}, '<html>MiWeb</html>', PORTAL).connected)
        self.assertTrue(parse_probe(301, {'location': 'https://www.mi.com:443/'}, '', PORTAL).connected)

    def test_http_200_or_unrelated_redirect_not_connected(self):
        for status, headers, body in [(200, {}, '<html>Success</html>'), (200, {}, '<![bad]>'), (500, {}, 'error'),
                                      (302, {'Location': PORTAL + '/index_28.html'}, ''),
                                      (301, {'Location': 'https://www.mi.com.evil.example/'}, ''),
                                      (301, {'Location': 'https://www.mi.com@evil.example/'}, ''),
                                      (301, {'Location': 'https://www.mi.com/account/login'}, '')]:
            with self.subTest(status=status, headers=headers), self.assertRaises(ProtocolError):
                parse_probe(status, headers, body, PORTAL)

    def test_only_js_redirect_triggers_auth(self):
        for body in ['<a href="' + PORTAL + '/index_28.html">here</a>',
                     '<!-- <script>location.href="' + PORTAL + '/index_28.html"</script> -->',
                     '<script>// location.href="' + PORTAL + '/index_28.html"</script>',
                     '<script src="/anything.js"></script>',
                     '<script>runArbitraryCode()</script>']:
            with self.assertRaises(ProtocolError):
                parse_probe(200, {}, body, PORTAL)

    def test_untrusted_or_malformed_portal_target(self):
        for target in ['http://evil.example/index_28.html', 'http://202.113.9.18.evil.example/index_28.html',
                       'http://202.113.9.18@evil.example/index_28.html', 'http://user:pass@202.113.9.18/index_28.html',
                       'http://202.113.9.18:8080/index_28.html', 'https://202.113.9.18/index_28.html',
                       PORTAL + '/index_0.html', PORTAL + '/index_bad.html', PORTAL + '/index_28.html#ac=1',
                       PORTAL + '/srun_portal_pc?ac_id=28&ac_id=16', PORTAL + '/index_28.html?ac_id=16']:
            with self.subTest(target=target), self.assertRaises(ProtocolError):
                parse_probe(200, {}, page(target), PORTAL)

    def test_conflicting_targets_and_ip(self):
        with self.assertRaises(ProtocolError):
            parse_probe(200, {}, page(PORTAL + '/index_16.html') + page(PORTAL + '/index_28.html'), PORTAL)
        for query in ['tjusip=192.0.2.10&ip=192.0.2.11', 'tjusip=host.example',
                      'tjusip=2001:db8::1', 'tjusip=192.0.2.10&tjusip=192.0.2.10']:
            with self.assertRaises(ProtocolError):
                parse_probe(200, {}, page(PORTAL + '/index_28.html?' + query), PORTAL)



if __name__ == '__main__':
    unittest.main()
