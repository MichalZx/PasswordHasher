import unittest
from password_hasher import PasswordHasher

class TestPasswordHasher(unittest.TestCase):
    def setUp(self):
        self.db_name = 'test_passwords.db'
        self.password_hasher = PasswordHasher(self.db_name)

    def test_insert_password(self):
        self.password_hasher.insert_password("test_password")
        assert self.password_hasher.verify_password(1, "test_password") == True

    def test_verify_password_correct(self):
        self.password_hasher.insert_password("test_password")
        assert self.password_hasher.verify_password(1, "test_password") == True

    def test_verify_password_incorrect(self):
        self.password_hasher.insert_password("test_password")
        assert self.password_hasher.verify_password(1, "incorrect_password") == False

if __name__ == '__main__':
    unittest.main()
