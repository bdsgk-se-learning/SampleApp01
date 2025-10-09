from flask import Flask, render_template, request, redirect, url_for, session, flash, g, abort
from flask_restful import Api, Resource
from flasgger import Swagger
from functools import wraps
import secrets
import config
import pyotp
import qrcode
import io
import base64
import os
import subprocess
from werkzeug.security import generate_password_hash, check_password_hash
app = Flask(__name__)
api = Api(app)
swagger = Swagger(app)

app = Flask(__name__)
api = Api(app)
swagger = Swagger(app)

app.secret_key = config.SECRET_KEY
app.config.from_object(config)

# セッションの設定
app.config.update(
    SESSION_COOKIE_SECURE=False,  # 開発環境ではFalse
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    PERMANENT_SESSION_LIFETIME=1800  # 30分
)

def generate_csrf_token():
    if '_csrf_token' not in session:
        session['_csrf_token'] = secrets.token_hex(16)
    return session['_csrf_token']

def check_csrf_token():
    token = session.get('_csrf_token')
    submitted_token = request.form.get('_csrf_token')
    if not token or not submitted_token or token != submitted_token:
        flash('セッションが無効です。もう一度お試しください。')
        return False
    return True

app.jinja_env.globals['csrf_token'] = generate_csrf_token

def requires_csrf(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if request.method == "POST":
            if not check_csrf_token():
                return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

DATABASE = os.path.join(os.path.dirname(__file__), 'app.db')

def run_sql(sql, params=(), fetchone=False, fetchall=False, commit=False):
    # SQL文とパラメータを組み立ててsqlite3コマンドで実行
    # パラメータは?で置換し、SQL文を安全に組み立てる
    # 文字列はシングルクォートでエスケープ
    def escape(val):
        if isinstance(val, str):
            return "'" + val.replace("'", "''") + "'"
        return str(val)
    for p in params:
        sql = sql.replace('?', escape(p), 1)
    args = ['sqlite3', DATABASE, '-cmd', '.timeout 5000', '-batch']
    if fetchone or fetchall:
        # 出力をCSV形式にしてパースしやすくする
        args += ['-header', '-csv']
    args.append(sql)
    result = subprocess.run(args, capture_output=True, text=True)
    if result.returncode != 0:
        raise Exception(result.stderr)
    if fetchone or fetchall:
        lines = result.stdout.strip().split('\n')
        if not lines or len(lines) < 2:
            return None if fetchone else []
        headers = lines[0].split(',')
        rows = [line.split(',') for line in lines[1:]]
        if fetchone:
            return rows[0]
        return rows
    return None

def init_db():
    with app.app_context():
        # スキーマの初期化
        schema_path = os.path.join(os.path.dirname(__file__), 'schema.sql')
        with open(schema_path, mode='r') as f:
            schema_sql = f.read()
        subprocess.run(['sqlite3', DATABASE], input=schema_sql, text=True)
        
        # 管理者ユーザーの存在確認
        admin = run_sql(
            'SELECT id FROM users WHERE username = ?',
            ('admin',),
            fetchone=True
        )
        
        # 管理者ユーザーが存在しない場合は作成
        if not admin:
            run_sql(
                'INSERT INTO users (username, password, is_admin, is_protected) VALUES (?, ?, ?, ?)',
                ('admin', generate_password_hash('admin'), True, True),
                commit=True
            )

def requires_admin(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not g.user:
            flash('ログインが必要です')
            return redirect(url_for('login'))
        
        # g.userからis_adminを直接チェック
        if not g.user.get('is_admin', False):
            flash('この操作には管理者権限が必要です')
            return redirect(url_for('index'))
        
        return f(*args, **kwargs)
    return decorated_function

@app.route('/register', methods=['GET', 'POST'])
@requires_csrf
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        enable_2fa = 'enable_2fa' in request.form
        
        try:
            if enable_2fa:
                # Generate TOTP secret
                totp_secret = pyotp.random_base32()
                # まずユーザーを作成
                run_sql(
                    'INSERT INTO users (username, password, totp_secret, is_2fa_enabled) VALUES (?, ?, ?, ?)',
                    (username, generate_password_hash(password), totp_secret, True),
                    commit=True
                )
                
                # 作成したユーザーの情報を取得
                user = run_sql(
                    'SELECT id FROM users WHERE username = ?',
                    (username,),
                    fetchone=True
                )
                
                # セッションを設定
                session['user_id'] = user[0]
                session['temp_totp_secret'] = totp_secret
                # 2FA設定ページにリダイレクト
                return redirect(url_for('setup_2fa'))
            else:
                run_sql(
                    'INSERT INTO users (username, password, is_2fa_enabled) VALUES (?, ?, ?)',
                    (username, generate_password_hash(password), False),
                    commit=True
                )
                return redirect(url_for('login'))
        except Exception as e:
            return 'ユーザー名が既に使われています'
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
@requires_csrf
def login():
    if request.method == 'POST':
        totp_code = request.form.get('totp_code', '')
        
        # 2FA認証コードが送信された場合
        if totp_code:
            temp_user_id = session.get('2fa_user_id')
            if not temp_user_id:
                flash('セッションが無効です。もう一度ログインしてください。')
                return redirect(url_for('login'))
            
            user = run_sql(
                'SELECT id, username, totp_secret FROM users WHERE id = ?',
                (temp_user_id,),
                fetchone=True
            )
            
            if not user or not user[2]:  # ユーザーが存在しないか、TOTPシークレットがない場合
                flash('セッションが無効です。もう一度ログインしてください。')
                session.pop('2fa_user_id', None)
                return redirect(url_for('login'))
            
            totp = pyotp.TOTP(user[2])
            if totp.verify(totp_code, valid_window=1):
                # ログイン成功時にフラッシュメッセージをクリア
                session.pop('_flashes', None)
                session.pop('2fa_user_id', None)
                session['user_id'] = user[0]
                return redirect(url_for('index'))
            else:
                flash('認証コードが正しくありません。')
                return render_template('verify_login.html', username=user[1])
        
        # 通常のログインフォームの処理
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        
        if not username or not password:
            flash('ユーザー名とパスワードを入力してください。')
            return redirect(url_for('login'))
        
        user = run_sql(
            'SELECT id, username, password, totp_secret, is_2fa_enabled FROM users WHERE username = ?',
            (username,),
            fetchone=True
        )
        
        if not user or not check_password_hash(user[2], password):
            flash('ユーザー名またはパスワードが違います。')
            return redirect(url_for('login'))
        
        # 2FAが有効かつTOTPシークレットが設定されている場合
        if bool(int(user[4])) and user[3]:
            session['2fa_user_id'] = user[0]
            return render_template('verify_login.html', username=user[1])
        
        # 2FAが無効な場合は直接ログイン
        session.pop('_flashes', None)  # フラッシュメッセージをクリア
        session['user_id'] = user[0]
        return redirect(url_for('index'))
        
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    return redirect(url_for('login'))

@app.before_request
def load_logged_in_user():
    user_id = session.get('user_id')
    g.user = None
    if user_id is not None:
        user = run_sql(
            'SELECT id, username, password, is_admin, is_protected FROM users WHERE id = ?',
            (user_id,),
            fetchone=True
        )
        if user:
            g.user = {
                'id': user[0],
                'username': user[1],
                'password': user[2],
                'is_admin': bool(int(user[3])) if user[3] is not None else False,
                'is_protected': bool(int(user[4])) if user[4] is not None else False
            }

@app.route('/')
def index():
    if not g.user:
        return redirect(url_for('login'))
    return render_template('welcome.html', username=g.user['username'])

@app.route('/users')
def users():
    if not g.user:
        return redirect(url_for('login'))
    users = run_sql('SELECT id, username FROM users', fetchall=True)
    user_list = [{'id': u[0], 'username': u[1]} for u in users]
    return render_template('users.html', users=user_list)

class UserListAPI(Resource):
    def get(self):
        """
        ユーザー一覧を取得するAPI
        ---
        responses:
          200:
            description: ユーザー一覧を返します
            schema:
              type: array
              items:
                type: object
                properties:
                  id:
                    type: integer
                    description: ユーザーID
                  username:
                    type: string
                    description: ユーザー名
        """
        users = run_sql(
            'SELECT id, username FROM users',
            fetchall=True
        )
        return [{'id': user[0], 'username': user[1]} for user in users]

# アカウント設定ページ
@app.route('/account')
def account():
    if not g.user:
        return redirect(url_for('login'))
    user_data = run_sql(
        'SELECT id, username, is_2fa_enabled FROM users WHERE id = ?',
        (g.user['id'],),
        fetchone=True
    )
    # SQLiteのBOOLEAN値（0/1）を適切にPythonのブール値に変換
    is_2fa_enabled = bool(int(user_data[2])) if user_data[2] is not None else False
    return render_template('account.html', user={
        'id': user_data[0], 
        'username': user_data[1], 
        'is_2fa_enabled': is_2fa_enabled
    })

# パスワード変更
@app.route('/change_password', methods=['POST'])
@requires_csrf
def change_password():
    if not g.user:
        return redirect(url_for('login'))
    
    current_password = request.form['current_password']
    new_password = request.form['new_password']
    
    # 現在のパスワードを確認
    user = run_sql(
        'SELECT password FROM users WHERE id = ?',
        (g.user['id'],),
        fetchone=True
    )
    
    if not check_password_hash(user[0], current_password):
        flash('現在のパスワードが正しくありません')
        return redirect(url_for('account'))
    
    # 新しいパスワードに更新
    run_sql(
        'UPDATE users SET password = ? WHERE id = ?',
        (generate_password_hash(new_password), g.user['id']),
        commit=True
    )
    
    flash('パスワードを更新しました')
    return redirect(url_for('account'))

# 2FA設定ページ
@app.route('/setup_2fa')
def setup_2fa():
    if not g.user:
        return redirect(url_for('login'))
    
    # セッションに保存されたシークレットを確認し、ない場合のみ新しく生成
    totp_secret = session.get('temp_totp_secret')
    if not totp_secret:
        totp_secret = pyotp.random_base32()
        session['temp_totp_secret'] = totp_secret
        session['setup_2fa_user_id'] = g.user['id']  # 2FA設定中のユーザーIDを保存
    
    # ユーザー情報を取得
    user = run_sql(
        'SELECT username FROM users WHERE id = ?',
        (g.user['id'],),
        fetchone=True
    )
    
    # QRコードを生成
    totp = pyotp.TOTP(totp_secret)
    provisioning_uri = totp.provisioning_uri(user[0], issuer_name="SampleApp")
    
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(provisioning_uri)
    qr.make(fit=True)
    
    img = qr.make_image(fill_color="black", back_color="white")
    img_buffer = io.BytesIO()
    img.save(img_buffer, format='PNG')
    qr_code = base64.b64encode(img_buffer.getvalue()).decode()
    
    return render_template('setup_2fa.html', secret=totp_secret, qr_code=qr_code)

# 2FA確認
@app.route('/verify_2fa', methods=['POST'])
@requires_csrf
def verify_2fa():
    if not g.user:
        return redirect(url_for('login'))
    
    code = request.form.get('code')
    secret = session.get('temp_totp_secret')
    setup_user_id = session.get('setup_2fa_user_id')
    
    if not secret or not setup_user_id or setup_user_id != g.user['id']:
        flash('セッションが無効です。もう一度最初から設定してください。')
        return redirect(url_for('account'))
    
    if not code:
        flash('認証コードを入力してください')
        return redirect(url_for('setup_2fa'))
    
    totp = pyotp.TOTP(secret)
    if totp.verify(code, valid_window=1):  # 前後1ステップ（30秒）を許容
        # 2FAを有効化
        run_sql(
            'UPDATE users SET totp_secret = ?, is_2fa_enabled = ? WHERE id = ?',
            (secret, True, g.user['id']),
            commit=True
        )
        # セッションからの一時データを削除
        session.pop('temp_totp_secret', None)
        session.pop('setup_2fa_user_id', None)
        flash('二段階認証を有効にしました')
        return redirect(url_for('account'))
    else:
        flash('認証コードが正しくありません。コードを再度確認してください。')
        # シークレットは保持したまま、設定ページに戻る
        return redirect(url_for('setup_2fa'))

# 2FA無効化
@app.route('/disable_2fa', methods=['POST'])
@requires_csrf
def disable_2fa():
    if not g.user:
        return redirect(url_for('login'))
    
    run_sql(
        'UPDATE users SET totp_secret = NULL, is_2fa_enabled = ? WHERE id = ?',
        (False, g.user['id']),
        commit=True
    )
    
    flash('二段階認証を無効にしました')
    return redirect(url_for('account'))

# 管理者用のユーザー管理機能
@app.route('/admin/users')
@requires_admin
def admin_users():
    users = run_sql(
        'SELECT id, username, is_2fa_enabled, is_admin, is_protected FROM users',
        fetchall=True
    )
    return render_template('admin_users.html', users=[{
        'id': u[0],
        'username': u[1],
        'is_2fa_enabled': bool(int(u[2])) if u[2] is not None else False,
        'is_admin': bool(int(u[3])) if u[3] is not None else False,
        'is_protected': bool(int(u[4])) if u[4] is not None else False
    } for u in users])

@app.route('/admin/reset_password/<int:user_id>', methods=['POST'])
@requires_admin
@requires_csrf
def admin_reset_password(user_id):
    # 保護されたユーザーの確認
    target_user = run_sql(
        'SELECT is_protected FROM users WHERE id = ?',
        (user_id,),
        fetchone=True
    )
    
    if not target_user or target_user[0]:
        flash('このユーザーのパスワードはリセットできません')
        return redirect(url_for('admin_users'))
    
    # パスワードをリセット（一時的なパスワード：'password123'）
    run_sql(
        'UPDATE users SET password = ? WHERE id = ?',
        (generate_password_hash('password123'), user_id),
        commit=True
    )
    
    flash('パスワードをリセットしました')
    return redirect(url_for('admin_users'))

@app.route('/admin/reset_2fa/<int:user_id>', methods=['POST'])
@requires_admin
@requires_csrf
def admin_reset_2fa(user_id):
    # 保護されたユーザーの確認
    target_user = run_sql(
        'SELECT is_protected FROM users WHERE id = ?',
        (user_id,),
        fetchone=True
    )
    
    if not target_user or target_user[0]:
        flash('この操作は許可されていません')
        return redirect(url_for('admin_users'))
    
    # 2FAをリセット
    run_sql(
        'UPDATE users SET totp_secret = NULL, is_2fa_enabled = ? WHERE id = ?',
        (False, user_id),
        commit=True
    )
    
    flash('2FA設定をリセットしました')
    return redirect(url_for('admin_users'))

# APIルートの登録
api.add_resource(UserListAPI, '/api/users')
