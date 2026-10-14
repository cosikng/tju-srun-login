import unittest

from srun.protocol import ProtocolError, login_succeeded, online_identity, parse_jsonp, valid_ip


class ProtocolTests(unittest.TestCase):
    def test_json_and_jsonp(self):
        for text in ('{"error":"ok"}', '\ufeff  callback({"error":"ok"}); ',
                     'callback({"text":"a(b)c", "error":"ok"})'):
            self.assertEqual(parse_jsonp(text, "callback")["error"], "ok")

    def test_malformed_responses_and_callback(self):
        for text in ('<html>error</html>', 'callback([])', 'other({})', 'callback({bad})',
                     'callback({}); alert(1)', 'callback({})garbage'):
            with self.subTest(text=text), self.assertRaises(ProtocolError):
                parse_jsonp(text, "callback")

    def test_success_requires_business_result(self):
        self.assertFalse(login_succeeded({"error": "ok"}))
        self.assertFalse(login_succeeded({"error": "fail", "res": "ok"}))
        self.assertFalse(login_succeeded({"error": "ok", "res": "ok", "ecode": 1}))
        self.assertTrue(login_succeeded({"error": "ok", "res": "ok"}))
        self.assertTrue(login_succeeded({"error": "ok", "suc_msg": "login_ok"}))

    def test_unknown_status_is_not_offline(self):
        self.assertIsNone(online_identity({"error": "not_online_error"}))
        for data in ({"error": "server_error"}, {"error": "ok"},
                     {"error": "not_online_error", "res": "server_error"}):
            with self.assertRaises(ProtocolError):
                online_identity(data)

    def test_invalid_client_ip(self):
        for ip in (None, True, 1, "", "host.example", "0.0.0.0", "127.0.0.1", "224.0.0.1", "::"):
            with self.assertRaises(ProtocolError):
                valid_ip(ip)


if __name__ == "__main__":
    unittest.main()
