import unittest
import requests
from app import app

server_address = "http://127.0.0.1:5000"
SERVICE_ADDR = server_address

class FeatureTest(unittest.TestCase):

    def setUp(self):
        self.app = app.test_client()
        app.testing = True

    def test_server_is_alive(self):
        req = requests.get(server_address + "/register")
        self.assetrEqual(req.status_code, 200)
        print("OK")

    def test_login(self):
        req = requests.get(server_address + "/login")
        self.assertEqual(req.status_code, 200)
        print("OK")

    def test_page_exits(self):
        PAGES = ["/register", "/login", "/spell_check"]
        for page in PAGES:
            req = requests.get(server_address + page)
            self.assertEqual(req.status_code, 200)
            print("OK")

    def test_no_login(self):
        req = requests.get(server_address + "/spell_check")
        self.assertEqual(req.status_code, 400)
        print("OK")

    def test_spell_check(self):
        req = requests.get(server_address + "/register")
        self.assertEqual(req.status_code, 200)
        uname = 'alfredo'
        pword = "root"
        mfa = "1234567899"
        req = requests.get(server_address + "/login")
        self.assertEqual(req.status_code, 200)
        print("OK")

        req = requests.get(server_address + "/spell_check")
        self.assertEqual(req.status_code, 200)

    def tearDown(self):
        pass

if __name__ == '__main__':
    unittest.main()