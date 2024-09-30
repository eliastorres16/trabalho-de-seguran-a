import re

class PasswordValidator:
    def __init__(self):
        # Definindo as regras para a senha
        self.rules = {
            "min_length": 8,
            "uppercase": r"[A-Z]",
            "lowercase": r"[a-z]",
            "digit": r"\d",
            "special": r"[!@#$%^&*(),.?\":{}|<>]",
        }

    def validate(self, password):
        if len(password) < self.rules["min_length"]:
            return False
        if not re.search(self.rules["uppercase"], password):
            return False
        if not re.search(self.rules["lowercase"], password):
            return False
        if not re.search(self.rules["digit"], password):
            return False
        if not re.search(self.rules["special"], password):
            return False
        return True
