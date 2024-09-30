import bcrypt

class UserManager:
    @staticmethod
    def hash_password(password):
        salt = bcrypt.gensalt()
        hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
        return hashed

    @staticmethod
    def check_password(hashed_password, user_password):
        return bcrypt.checkpw(user_password.encode('utf-8'), hashed_password)
