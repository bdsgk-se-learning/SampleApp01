#!/usr/bin/env python3
import os
import sys
import sqlite3
from app import DATABASE

# データベースのマイグレーションバージョンを管理するテーブル
SCHEMA_VERSION_SQL = '''
CREATE TABLE IF NOT EXISTS schema_version (
    version INTEGER PRIMARY KEY,
    applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
'''

# 各バージョンのマイグレーションSQL
MIGRATIONS = {
    1: '''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL
    );
    ''',
    2: '''
    ALTER TABLE users ADD COLUMN totp_secret TEXT;
    ALTER TABLE users ADD COLUMN is_2fa_enabled BOOLEAN DEFAULT 0;
    ''',
    3: '''
    ALTER TABLE users ADD COLUMN is_admin BOOLEAN DEFAULT 0;
    ALTER TABLE users ADD COLUMN is_protected BOOLEAN DEFAULT 0;
    '''
}

def init_schema_version():
    """スキーマバージョン管理テーブルを初期化"""
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute(SCHEMA_VERSION_SQL)
    conn.commit()
    conn.close()

def get_current_version():
    """現在のスキーマバージョンを取得"""
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    
    try:
        cursor.execute('SELECT MAX(version) FROM schema_version')
        version = cursor.fetchone()[0]
        return version or 0
    except sqlite3.OperationalError:
        return 0
    finally:
        conn.close()

def apply_migration(version, sql):
    """指定されたバージョンのマイグレーションを適用"""
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    
    try:
        # マイグレーションSQLの実行
        for statement in sql.split(';'):
            if statement.strip():
                cursor.execute(statement)
        
        # バージョン情報の更新
        cursor.execute('INSERT INTO schema_version (version) VALUES (?)', (version,))
        conn.commit()
        print(f'マイグレーション {version} を適用しました')
        
    except sqlite3.Error as e:
        conn.rollback()
        print(f'エラー: マイグレーション {version} の適用に失敗しました')
        print(e)
        sys.exit(1)
    finally:
        conn.close()

def create_admin_user():
    """管理者ユーザーの作成"""
    from werkzeug.security import generate_password_hash
    
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    
    try:
        # 管理者ユーザーの存在確認
        cursor.execute('SELECT id FROM users WHERE username = ?', ('admin',))
        if not cursor.fetchone():
            # 管理者ユーザーの作成
            cursor.execute(
                'INSERT INTO users (username, password, is_admin, is_protected) VALUES (?, ?, ?, ?)',
                ('admin', generate_password_hash('admin'), True, True)
            )
            conn.commit()
            print('管理者ユーザーを作成しました (username: admin, password: admin)')
    except sqlite3.Error as e:
        conn.rollback()
        print('エラー: 管理者ユーザーの作成に失敗しました')
        print(e)
    finally:
        conn.close()

def upgrade_database():
    """データベースを最新バージョンにアップグレード"""
    if not os.path.exists(DATABASE):
        print(f'新しいデータベースを作成します: {DATABASE}')
    
    init_schema_version()
    current_version = get_current_version()
    
    for version in sorted(MIGRATIONS.keys()):
        if version > current_version:
            print(f'バージョン {version} に更新しています...')
            apply_migration(version, MIGRATIONS[version])
    
    # 最新バージョンで管理者ユーザーを作成
    if get_current_version() >= 3:
        create_admin_user()

def main():
    """メイン処理"""
    print('データベースのアップグレードを開始します...')
    upgrade_database()
    print('データベースのアップグレードが完了しました')

if __name__ == '__main__':
    main()