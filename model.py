import sqlite3
import hashlib
import secrets


class User:
    def __init__(self, username, password):
        self.username = username
        self.password = password

    def login(self):
        authenticator = Authenticator()
        if authenticator.authenticate(self.username, self.password):
            session_manager = SessionManager()
            session = session_manager.create_session(self.username)
            return session.token
        else:
            raise AuthenticationError("Invalid username or password")

    def logout(self, token):
        session_manager = SessionManager()
        session_manager.invalidate_session(token)


class Authenticator:
    def __init__(self):
        self.user_manager = UserManager()
        self.password_encryptor = PasswordEncryptor()
        self.error_manager = ErrorManager()

    def authenticate(self, username, password):
        try:
            user = self.user_manager.get_user(username)
        except UserNotFoundError:
            self.error_manager.handle_error("User not found")
            return False

        encrypted_password = self.password_encryptor.encrypt(password)
        if encrypted_password != user.password:
            self.error_manager.handle_error("Invalid password")
            return False

        return True


class UserManager:
    def __init__(self):
        self.users = {
            "john": User("john", "password"),
            "jane": User("jane", "letmein"),
        }

    def get_user(self, username):
        try:
            return self.users[username]
        except KeyError:
            raise UserNotFoundError


class UserNotFoundError(Exception):
    pass


class SessionManager:
    def __init__(self):
        self.sessions = {}

    def create_session(self, username):
        token = secrets.token_hex(16)
        session = Session(token, username)
        self.sessions[token] = session
        return session

    def get_session(self, token):
        try:
            return self.sessions[token]
        except KeyError:
            raise InvalidTokenError

    def invalidate_session(self, token):
        try:
            del self.sessions[token]
        except KeyError:
            raise InvalidTokenError


class Session:
    def __init__(self, token, username):
        self.token = token
        self.user = User(username, "")

    def get_user(self):
        return self.user


class PasswordEncryptor:
    def encrypt(self, password):
        return hashlib.sha256(password.encode()).hexdigest()


class SecurityManager:
    def __init__(self, authenticator):
        self.authenticator = authenticator

    def authorize(self, token):
        session_manager = SessionManager()
        try:
            session = session_manager.get_session(token)
            user = session.get_user()
        except InvalidTokenError:
            return False

        return self.authenticator.authenticate(user.username, user.password)


class ErrorManager:
    def handle_error(self, error_message):
        print(f"Error: {error_message}")


class LogManager:
    def __init__(self):
        self.connection = sqlite3.connect("log.sqlite")
        self.cursor = self.connection.cursor()
        self.create_table()

    def create_table(self):
        self.cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                message TEXT
            )
            """
        )
        self.connection.commit()

    def log(self, message):
        self.cursor.execute("INSERT INTO log (message) VALUES (?)", (message,))
        self.connection.commit()


class AuthenticationError(Exception):
    pass


class InvalidTokenError(Exception):
    pass
