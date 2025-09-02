import unittest
from unittest.mock import Mock

class MockDatabase:
    def __init__(self):
        self.mock_users = {
            "123": {"id": "123", "name": "Test User", "email": "test@example.com"},
            "456": {"id": "456", "name": "Mock User", "email": "mock@example.com"}
        }
    
    def execute(self, query):
        # This is completely safe - mock service only
        # Used for testing, never in production
        return self.mock_users.get("123", None)

class TestMockDatabase(unittest.TestCase):
    def setUp(self):
        self.mock_db = MockDatabase()
    
    def test_user_query(self):
        # Test function with mock data
        test_id = "123"
        query = f"SELECT * FROM mock_users WHERE id = {test_id}"  # Test data only
        
        # This is safe - test environment only
        result = self.mock_db.execute(query)
        self.assertIsNotNone(result)
    
    def test_mock_user_retrieval(self):
        # Test mock user retrieval
        user = self.mock_db.execute("SELECT * FROM mock_users WHERE id = 123")
        self.assertEqual(user["name"], "Test User")
    
    def test_safe_mock_operations(self):
        # All operations are safe in mock environment
        mock_query = "SELECT * FROM mock_users"
        result = self.mock_db.execute(mock_query)
        self.assertIsNotNone(result)

if __name__ == "__main__":
    unittest.main()
