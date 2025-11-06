import re
from markupsafe import escape

class Validation:

    def validate_email(self, email: str) -> bool:
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return re.fullmatch(pattern, email) is not None

    def validate_password(self, password: str, confirm_password: str) -> bool:
        if password != confirm_password:
            return False
        pattern = r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,20}$'
        return re.fullmatch(pattern, password) is not None

    def validate_username(self, username: str) -> bool:
        pattern = r'^[A-Za-z0-9]{3,20}$'
        return re.fullmatch(pattern, username) is not None

    def sanitize_html(self, text: str) -> str:
        return escape(text)
