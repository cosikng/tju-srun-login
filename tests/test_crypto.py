"""公开人工参考向量；不需要抓包、Node.js 或原始前端资源。"""

import json
from pathlib import Path
import unittest

from srun.crypto import make_login_params

FIXTURE = Path(__file__).parent / "fixtures" / "auth_vectors.json"


class CryptoTests(unittest.TestCase):
    def test_reference_vectors(self):
        vectors = json.loads(FIXTURE.read_text(encoding="utf-8"))
        self.assertEqual(len(vectors), 70)
        for index, vector in enumerate(vectors):
            args = vector["inputs"]
            actual = make_login_params(args["username"], args["password"], args["ip"],
                                       args["ac_id"], args["token"])
            with self.subTest(vector=index):
                for field in ("password", "info", "chksum"):
                    self.assertEqual(actual[field], vector["expected"][field])

    def test_ac_is_part_of_info_and_checksum(self):
        args = json.loads(FIXTURE.read_text(encoding="utf-8"))[0]["inputs"]
        first = make_login_params(args["username"], args["password"], args["ip"], "1", args["token"])
        second = make_login_params(args["username"], args["password"], args["ip"], "2", args["token"])
        self.assertEqual(first["password"], second["password"])
        self.assertNotEqual(first["info"], second["info"])
        self.assertNotEqual(first["chksum"], second["chksum"])


if __name__ == "__main__":
    unittest.main()
