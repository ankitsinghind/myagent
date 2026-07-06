import unittest
import os
import sys
from fastapi.testclient import TestClient

# Ensure root directory is in sys.path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.web_server import app

class TestWebEndpoints(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(app)

    def test_status_endpoint(self):
        response = self.client.get("/api/status")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn("actions", data)
        self.assertIn("blocked_ips", data)
        self.assertIn("blocked_domains", data)

    def test_index_serves(self):
        response = self.client.get("/")
        # If static index.html doesn't exist, it returns a 200 dict warning, or serves file
        self.assertEqual(response.status_code, 200)

if __name__ == "__main__":
    unittest.main()
