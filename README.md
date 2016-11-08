# LISM
LISM(LDAP Identity Synchronization Manager)は、LDAP、リレーショナルデータベース、CSVファイルといった様々形式で管理されているID情報を、LDAPインターフェースを通して一元的に管理することができるオープンソースソフトウェアです。

## 動作環境
* OS：CentOS7、Redhat Enterprise Linux 7
* ミドルウェア：Apache、OpenLDAP、PHP、perl、Memcached

## インストール
### 事前準備
EPELのリポジトリを追加します。
* CentOS7の場合  
`# yum install epel-release`
* Redhat Enterprise Linux 7の場合  
`# rpm -ivh http://ftp.riken.jp/Linux/fedora/epel/epel-release-latest-7.noarch.rpm`

### LISMのインストール
githubのpackages/LISM-4.x.x-x.x86_64.tar.gzをダウンロード、展開して、インストールスクリプト(install.sh)を実行して下さい。  
`# ./isntall.sh install`

必要なパッケージが不足している場合、一覧表示され、自動的にインストールします。

    eventlogが必要です。
    httpdが必要です。
    ・・・・
    yumリポジトリから必須パッケージをインストールします。よろしいですか？ [yes]
    yes

### 初期設定
インストール完了後、セットアップツール(setup.pl)により初期設定を行います。

#### FQDNの設定
サーバのFQDNを設定します。

    FQDNの設定を行います。
    FQDNを入力してください。(default: …) 
    sime.secioss.com
    FQDNの設定が完了しました。

#### visudoの設定変更
LISMがsudoコマンドを実行するための設定を行います。

    sudoの設定変更を行います。
    requirettyを無効にします。よろしいですか？ [yes/no](default: yes)
    yes
    apacheユーザにコマンド実行時の昇格権限を付与します。よろしいですか？ [yes/no](default: yes)
    yes
    visudoの設定変更が完了しました。

#### パスワード辞書ファイルの作成
パスワードの強度チェックに使用する辞書ファイルを作成します。

    パスワード辞書ファイルを作成します。
    yumリポジトリから最新の辞書ファイルをインストールします。よろしいですか？[yes/no](default: yes)
    yes
    パスワード辞書ファイルの作成が完了しました。

#### LDAPサーバへの接続設定
LISMが接続するLDAPサーバの設定を行います。

    LDAPサーバの設定を行います。
    LDAP-pathを入力してください。(default: ldap://localhost)
    ldaps://sime.ldap.com
    BaseDNを入力してください。(default: dc=example,dc=com)
    dc=sime,dc=ldap,dc=com
    BindDNを入力してください。(default: cn=Manager,dc=example,dc=com)
    cn=Manager,dc=sime,dc=ldap,dc=com
    Passwordを入力してください。
    ******
    LDAPサーバへの接続設定が完了しました。

#### memcachedサーバへの接続確認
memcachedサーバへの接続確認を行います。接続確認前にmemcachedを起動しておいて下さい。
`# systemctl start memcached`

localhostでmemcachedを起動している場合は、「localhost:11211」を入力して下さい。

    memcachedサーバの設定をします。
    memcachedサーバを入力してください。カンマ区切りで複数指定できます。(default: localhost:11211)
    enter
    memcachedサーバへの接続設定が完了しました。

#### 管理者パスワードの設定
LISMのWeb管理コンソールにログインする管理アカウント「admin」のパスワードを設定します。

    LISM 管理者パスワードを設定します。
    管理者パスワードを入力してください。
    管理者パスワード(再入力)を入力してください。
    ******
    管理者パスワードの設定が完了しました。

#### サービスの再起動
LISMで利用するデーモンの再起動を行います。

    httpdを再起動しますか？ [yes/no](default: yes)
    yes
    openldap-lismを再起動しますか？ [yes/no](default: yes)
    yes

#### サービスの停止
LISMで利用するデーモンを停止します。
