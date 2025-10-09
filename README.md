# SampleApp01

Polaris の SAST/SCA/DAST の解析対象のサンプルです。
Python と Flask で作成されたWebアプリケーションです。
パッケージ管理にpipを使用しています。

演習１，２，３で使用します

## DAST 解析対象の構築

演習でDAST解析のターゲットが必要なときは、このアプリケーションを起動して使用してください。以下の事前準備が必要です。

### 必要なもの

* Python3
* pipenv

### インストール方法

依存関係のインストール

```bash
cd TargetApp01
pipenv shell
pipenv install
```

データベースの初期設定とアップグレード
```bash
python manage_db.py
```
このコマンドを実行すると、以下の処理が行われます：
- データベース（app.db）の作成（存在しない場合）
- スキーマの最新バージョンへのアップグレード
- 管理者ユーザー（admin）の作成（存在しない場合）

注: データベースを初期化するには、既存のapp.dbを削除してから上記コマンドを実行してください。

### 起動方法

```bash
python server.py
```

http://localhost:5000 でアクセスして、ログインページが表示されたら起動完了です。
「ユーザー登録」から任意のユーザーを登録してください。ユーザー情報は、app.db に保存されます。

停止時は、CTRL+C で停止してください。

### API

http://localhost:5000/apidocs/ から SwaggerのAPIドキュメントを表示することができます。
