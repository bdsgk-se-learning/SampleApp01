from flask import Flask, render_template, request, redirect, url_for, session, g
import os
import subprocess
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # セッション用の秘密鍵

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
        schema_path = os.path.join(os.path.dirname(__file__), 'schema.sql')
        with open(schema_path, mode='r') as f:
            schema_sql = f.read()
        subprocess.run(['sqlite3', DATABASE], input=schema_sql, text=True)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        try:
            run_sql(
                'INSERT INTO users (username, password) VALUES (?, ?)',
                (username, generate_password_hash(password)),
                commit=True
            )
            return redirect(url_for('login'))
        except Exception as e:
            return 'ユーザー名が既に使われています'
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = run_sql(
            'SELECT id, username, password FROM users WHERE username = ?', (username,),
            fetchone=True
        )
        if user and check_password_hash(user[2], password):
            session['user_id'] = user[0]
            return redirect(url_for('index'))
        else:
            return 'ユーザー名またはパスワードが違います'
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
            'SELECT id, username, password FROM users WHERE id = ?', (user_id,),
            fetchone=True
        )
        g.user = user

@app.route('/')
def index():
    if not g.user:
        return redirect(url_for('login'))
    return render_template('welcome.html', username=g.user[1])
