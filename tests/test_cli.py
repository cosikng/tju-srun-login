import os
import unittest
from unittest.mock import patch

from srun.cli import main
from tests import test_client as fixtures


class CliTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.ClientTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        patch('srun.cli.logging.basicConfig').start()

    def test_online_requires_no_username_or_password(self):
        client, _, _, _ = self.fixture.client([('probe', fixtures.CONNECTED)])
        with patch('srun.cli.SRunClient', return_value=client), \
                patch('srun.cli.input', side_effect=AssertionError('不应询问账号')), \
                patch('srun.cli.getpass.getpass', side_effect=AssertionError('不应询问密码')):
            self.assertEqual(main(['login']), 0)

    def test_env_credentials_and_ac_env_ignored(self):
        client, _, adapter, _ = self.fixture.client([('probe', fixtures.blocked()), ('get_challenge', fixtures.challenge()), ('srun_portal', fixtures.SUCCESS)])
        with patch('srun.cli.SRunClient', return_value=client), \
                patch.dict(os.environ, {'SRUN_USERNAME': 'testuser', 'SRUN_PASSWORD': 'dummy', 'SRUN_AC_ID': '999'}):
            self.assertEqual(main(['login', '--minimal']), 0)
        self.assertEqual(adapter.calls[-1]['query']['ac_id'], '28')

    def test_manual_ac_argument_removed(self):
        with patch('srun.cli.SRunClient') as factory, patch('sys.stderr'), self.assertRaises(SystemExit) as caught:
            main(['login', '--ac-id', '28'])
        self.assertEqual(caught.exception.code, 2)
        factory.assert_not_called()


if __name__ == '__main__':
    unittest.main()
