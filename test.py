import unittest
import requests
from app import app
from bs4 import BeautifulSoup
import pytest

server_address="http://127.0.0.1:5000"
SERVICE_ADDR=server_address


class FeatureTest(unittest.TestCase):

    def setUp(self):
        self.app = app.test_client()
        app.testing = True

    def test_register(self):
        req = requests.get(server_address + "/register")
        self.assertEqual(req.status_code, 200)
        print("OK")

    def test_login(self):
        req = requests.get(server_address + "/login")
        self.assertEqual(req.status_code, 200)
        print("OK")

    def test_no_login(self):
        req = requests.get(server_address + "/spell_check")
        self.assertEqual(req.status_code, 401)
        print("OK")

    def test_spell_check(self):
        
        headers = {'User-Agent': 'My User Agent'}
        s = requests.Session()
        req = s.get(server_address + "/register")     
        headers['cookie'] = '; '.join([x.name + '=' + x.value for x in req.cookies])
        headers['content-type'] = 'application/x-www-form-urlencoded'
        #print(req.content)
        self.assertEqual(req.status_code, 200)
        uname = 'tjramlogan'
        pword = "blahblah"
        mfa = "1234567891"
        req = s.post(server_address + "/register", data=dict(
            uname=uname, pword=pword, mfa=mfa), headers=headers
        )
        #print(req.content)
        #assert b'success' in req.data
        #self.assertEqual(req.status_code, 200)
        req = s.get(server_address + "/login")
        headers['cookie'] = '; '.join([x.name + '=' + x.value for x in req.cookies])
        headers['content-type'] = 'application/x-www-form-urlencoded'
        req = s.post(server_address + "/login", data=dict(
            uname=uname, pword=pword, mfa=mfa), headers=headers
        )                  
        #print(req.content)
        self.assertEqual(req.status_code, 200)
        req = s.get(server_address + "/spell_check")
        self.assertEqual(req.status_code, 200)
        inputtext = "one two chalfdae three four blakc-da"
        req = s.post(server_address + "/spell_check", data=dict(
            inputtext=inputtext)
        )               
        soup = BeautifulSoup(req.content, 'html.parser')
        values = soup.find("p", {"id":"misspelled"})
        text = 'chalfdae, blakc-da'
        print(values.text)
        self.assertEqual(text, values.text)



    def tearDown(self):
        pass

if __name__ == '__main__':
    
    unittest.main()


