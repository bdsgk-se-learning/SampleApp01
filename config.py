"""
アプリケーションの設定情報を管理するモジュール
"""

# アプリケーション情報
APP_VERSION = '1.1.0'
APP_NAME = 'SampleApp'

# データベース設定
DATABASE_NAME = 'app.db'

# セッション設定
SECRET_KEY = 'your_secret_key'

# 2FA設定
TOTP_DIGITS = 6
TOTP_INTERVAL = 30  # seconds