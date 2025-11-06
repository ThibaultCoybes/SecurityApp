import bcrypt
from datetime import datetime, timedelta
from typing import Optional

class AuthenticationEnforcer:
    def __init__(self):
        self.sessions = {}
        self.failed_attempts = {}

    def hash_password(self, plain_password: str) -> str:
        salt = bcrypt.gensalt()
        hashed = bcrypt.hashpw(plain_password.encode('utf-8'), salt)
        return hashed.decode('utf-8')

    def authenticate(self, username: str, password: str, mysql=None) -> bool:
        cur = mysql.connection.cursor()
        try:
            cur.execute("SELECT password FROM users WHERE username = %s", (username,))
            user = cur.fetchone()
            if not user:
                self.failed_attempts[username] = self.failed_attempts.get(username, 0) + 1
                return False

            if self.failed_attempts.get(username, 0) >= 5:
                return False 

            if bcrypt.checkpw(password.encode('utf-8'), user['password'].encode('utf-8')):
                self.sessions[username] = datetime.now() + timedelta(minutes=30)
                self.failed_attempts[username] = 0  # reset après succès
                return True
            else:
                self.failed_attempts[username] = self.failed_attempts.get(username, 0) + 1
                return False
        finally:
            cur.close()

    def is_session_valid(self, username: str) -> bool:
        if username not in self.sessions:
            return False
        return datetime.now() < self.sessions[username]
