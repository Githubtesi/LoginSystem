from model import SecurityManager, SessionManager
from model import LogManager
from model import Authenticator

# ユーザーの認証
username = input("Username: ")
password = input("Password: ")
authenticator = Authenticator()
if authenticator.authenticate(username, password):
    print("Authentication successful.")
else:
    print("Authentication failed.")

# ログの書き込み
log_manager = LogManager()
log_manager.log("User {} logged in".format(username))

# ログアウト
session_manager = SessionManager()
token = session_manager.create_session(username)
print("Session created with token: {}".format(token))
# session_manager.invalidate_session(token)
log_manager.log("User {} logged out".format(username))
