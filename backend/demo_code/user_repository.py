import logging

logger = logging.getLogger(__name__)

class UserRepository:
    def __init__(self, db_connection):
        self.db = db_connection

    def find_users_by_criteria(self, email, status):
        # VULNERABLE: Direct string interpolation
        # This could allow SQL injection attacks
        query = f"SELECT * FROM users WHERE email = '{email}' AND status = '{status}'"
        
        try:
            cursor = self.db.cursor()
            cursor.execute(query)
            return cursor.fetchall()
        except Exception as e:
            logger.error(f"Database error: {e}")
            return []

    def find_user_by_id_safe(self, user_id):
        # SAFE: Parameterized query prevents SQL injection
        query = "SELECT * FROM users WHERE id = %s"
        
        try:
            cursor = self.db.cursor()
            cursor.execute(query, (user_id,))
            return cursor.fetchone()
        except Exception as e:
            logger.error(f"Database error: {e}")
            return None

    def update_user_status(self, user_id, new_status):
        # SAFE: Parameterized query
        query = "UPDATE users SET status = %s WHERE id = %s"
        
        try:
            cursor = self.db.cursor()
            cursor.execute(query, (new_status, user_id))
            self.db.commit()
            return True
        except Exception as e:
            logger.error(f"Database error: {e}")
            self.db.rollback()
            return False
