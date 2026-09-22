import os
import unittest
import json

TEST_DB_FILE = "test_secure_share.db"

# Force SQLite test mode with a persistent test DB file
os.environ["USE_SQLITE"] = "true"
os.environ["SQLITE_DB_PATH"] = TEST_DB_FILE

from app import create_app
from app.models.user import hash_password, verify_password, find_by_email

class Phase1AutomatedTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Remove any leftover test DB file before starting
        if os.path.exists(TEST_DB_FILE):
            try:
                os.remove(TEST_DB_FILE)
            except OSError:
                pass

    @classmethod
    def tearDownClass(cls):
        # Clean up test DB file after tests finish
        if os.path.exists(TEST_DB_FILE):
            try:
                os.remove(TEST_DB_FILE)
            except OSError:
                pass

    def setUp(self):
        self.app = create_app()
        self.app.config['TESTING'] = True
        self.client = self.app.test_client()

    def test_01_health_check(self):
        """TEST 1 — GET /api/health returns success status."""
        response = self.client.get('/api/health')
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertEqual(data.get("status"), "success")
        self.assertIn("Secure File Sharing API is running", data.get("message", ""))
        print("\n[PASS] TEST 1: Backend Health Check")

    def test_02_password_hashing(self):
        """TEST 4 (Unit) — Password hashing is secure and uses bcrypt."""
        plain_pwd = "Password123"
        hashed = hash_password(plain_pwd)
        
        # Must not store plain text
        self.assertNotEqual(plain_pwd, hashed)
        self.assertTrue(hashed.startswith("$2b$"))
        
        # Verification checks
        self.assertTrue(verify_password("Password123", hashed))
        self.assertFalse(verify_password("WrongPassword", hashed))
        print("[PASS] TEST 4 (Unit): Password Security & Bcrypt Hashing")

    def test_03_registration(self):
        """TEST 3 — POST /api/auth/register creates user account."""
        payload = {
            "username": "alice",
            "email": "alice@example.com",
            "password": "Password123"
        }
        response = self.client.post('/api/auth/register', json=payload)
        self.assertEqual(response.status_code, 201)
        data = response.get_json()
        self.assertTrue(data.get("success"))
        self.assertEqual(data["user"]["username"], "alice")
        self.assertEqual(data["user"]["email"], "alice@example.com")
        self.assertNotIn("password", data["user"])
        self.assertNotIn("password_hash", data["user"])
        print("[PASS] TEST 3: User Registration")

    def test_04_check_database_hash(self):
        """TEST 4 (DB) — User in DB contains bcrypt hash, not plain text."""
        user = find_by_email("alice@example.com")
        self.assertIsNotNone(user, "User alice should exist in database")
        self.assertEqual(user["username"], "alice")
        self.assertNotEqual(user["password_hash"], "Password123")
        self.assertTrue(user["password_hash"].startswith("$2b$"))
        print("[PASS] TEST 4 (DB): Database Hashed Password Verification")

    def test_05_duplicate_registration(self):
        """TEST 5 — Duplicate registration attempt returns 409 Conflict."""
        payload = {
            "username": "alice",
            "email": "alice@example.com",
            "password": "Password123"
        }
        response = self.client.post('/api/auth/register', json=payload)
        self.assertEqual(response.status_code, 409)
        data = response.get_json()
        self.assertFalse(data.get("success"))
        print("[PASS] TEST 5: Duplicate Registration Prevention")

    def test_06_login_success(self):
        """TEST 6 — Successful login returns token & user details."""
        payload = {
            "email": "alice@example.com",
            "password": "Password123"
        }
        response = self.client.post('/api/auth/login', json=payload)
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertTrue(data.get("success"))
        self.assertIn("token", data)
        self.assertEqual(data["user"]["username"], "alice")
        self.assertNotIn("password_hash", data["user"])
        print("[PASS] TEST 6: Successful Login & JWT Token Generation")

    def test_07_wrong_password(self):
        """TEST 7 — Wrong password returns 401 Unauthorized."""
        payload = {
            "email": "alice@example.com",
            "password": "WrongPassword"
        }
        response = self.client.post('/api/auth/login', json=payload)
        self.assertEqual(response.status_code, 401)
        data = response.get_json()
        self.assertFalse(data.get("success"))
        self.assertEqual(data.get("message"), "Invalid email or password.")
        print("[PASS] TEST 7: Wrong Password Rejection")

    def test_08_get_current_user(self):
        """TEST 8 (API) — GET /api/auth/me returns profile with valid Bearer token."""
        # 1. Login to get token
        login_res = self.client.post('/api/auth/login', json={
            "email": "alice@example.com",
            "password": "Password123"
        })
        self.assertEqual(login_res.status_code, 200)
        token = login_res.get_json()["token"]

        # 2. Get current user profile
        headers = {"Authorization": f"Bearer {token}"}
        me_res = self.client.get('/api/auth/me', headers=headers)
        self.assertEqual(me_res.status_code, 200)
        data = me_res.get_json()
        self.assertTrue(data.get("success"))
        self.assertEqual(data["user"]["username"], "alice")
        self.assertEqual(data["user"]["email"], "alice@example.com")
        self.assertIsNone(data["user"]["wallet_address"])
        print("[PASS] TEST 8 (API): Get Current Authenticated User")

    def test_09_unauthorized_access(self):
        """TEST 9 (API) — /api/auth/me fails without valid token."""
        response = self.client.get('/api/auth/me')
        self.assertEqual(response.status_code, 401)
        
        bad_response = self.client.get('/api/auth/me', headers={"Authorization": "Bearer invalid_token_123"})
        self.assertEqual(bad_response.status_code, 401)
        print("[PASS] TEST 9 (API): Unauthorized Access Protection")

if __name__ == "__main__":
    unittest.main()
