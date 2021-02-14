# LISM
LISM(LDAP Identity Synchronization Manager)は、LDAP、リレーショナルデータベース、CSVファイルといった様々形式で管理されているID情報を、LDAPインターフェースを通して一元的に管理することができるオープンソースの統合ID管理ソフトウェアです。

## 概要
統合ID管理ソフトウェア「LISM」は、様々なシステムに分散したID情報や役割（ロール）情報を一元的に管理することができるソフトウェアです。  
LISMは、システムの情報を１つのLDAPディレクトリツリーとして管理し、連携先の各システムの情報はそれぞれサブツリーに分かれて管理されています。マスタデータとなるLDAPサーバの情報については、ou=LDAPとou=Masterの配下に表示され、ou=Master配下の情報がマスタデータとして扱われます。  
  
そのため、LISMのマスタデータ（OpenLDAP）に対して更新を行うことで、LISMと連携されている  
Active Directory、LDAP、RDBMSや、CSVファイル出力、RESTful API、SOAP APIを持ったWebサービスに対してID情報の更新内容をリアルタイムで同期することができます。  
ID情報の管理は、基本的にマスタデータに対して操作のみの一元管理を実現します。

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

SELinuxを無効にします。  
一時的に無効にするには以下を実行して下さい。

`# setenforce 0`

それから、/etc/selinux/configのSELINUXをpermissive、またはdisalbedに変更して下さい。

### LISM用OpenLDAPサーバの設定
LISMの管理用LDAPサーバとして利用するための設定を行います。パッケージファイル内にある「secioss_ldif」フォルダ以下をOpneLDAPをインストールしたサーバにコピー（ディレクトリは何処でも構いません）して下さい。  
「secioss_ldif」フォルダ内には5つのldifファイルがあります。このうち4つのファイルを編集し、LDAPの初期設定を行います。  

1.admin.ldif
2.schema.ldif
3.db.ldif
4.module.ldif

OpenLDAPの管理者パスワードをadmin.ldifの「olcRootPW」に記述して、以下のコマンドを実行して下さい。

`# ldapmodify -Y EXTERNAL -H ldapi:// -f admin.ldif`

スキーマを以下のコマンドを実行して、適用して下さい。

`# ldapmodify -Y EXTERNAL -H ldapi:// -f schema.ldif`

OpenLDAPに対する一部初期設定を行います。  
db.ldif内にあるsuffixのdc=example,dc=comは、構築したいベースDNに変更して下さい。

`# sed -i -e "s/dc=example,dc=com/dc=lism,dc=ldap/g" db.ldif`

以下のコマンドを実行して、適用して下さい。

`# ldapmodify -Y EXTERNAL -H ldapi:// -f db.ldif`

必要なモジュールの設定を以下のコマンドを実行して、適用して下さい。

`# ldapmodify -Y EXTERNAL -H ldapi:// -f module.ldif`

全ての設定が完了したら、OpenLDAPを再起動します。

`# systemctl restart slapd`

次に、LDAPサーバに以下のLDIFファイルを登録して下さい。  
suffixのdc=example,dc=comは、OpenLDAPの設定に合わせて変更して下さい。

    dn: dc=example,dc=com
    changetype: add
    objectClass: domain
    dc: example
    
    dn: o=System,dc=example,dc=com
    changetype: add
    objectClass: organization
    objectClass: seciossTenant
    objectClass: seciossPwdPolicy
    o: System
    pwdAttribute: 2.5.4.35
    
    dn: ou=People,dc=example,dc=com
    changetype: add
    objectClass: organizationalUnit
    ou: People
    
    dn: ou=Groups,dc=example,dc=com
    changetype: add
    objectClass: organizationalUnit
    ou: Groups
    
    dn: ou=Organizations,dc=example,dc=com
    changetype: add
    objectClass: organizationalUnit
    ou: Organizations
    businessCategory: invisible
    
    dn: ou=Metadata,dc=example,dc=com
    changetype: add
    objectClass: organizationalUnit
    ou: Metadata
    
    dn: ou=Profiles,dc=example,dc=com
    changetype: add
    objectClass: organizationalUnit
    ou: Profiles
    
    dn: ou=Config,dc=example,dc=com
    changetype: add
    objectClass: organizationalUnit
    ou: Config
    
    dn: ou=Autologin,ou=Config,dc=example,dc=com
    changetype: add
    objectClass: organizationalUnit
    ou: Autologin
    
    dn: ou=Gateway,ou=Config,dc=example,dc=com
    changetype: add
    objectClass: organizationalUnit
    ou: Gateway

### LISMのインストール
githubのpackages/LISM-4.x.x-x.x86_64.tar.gzを展開して、インストールスクリプト(install.sh)を実行して下さい。  

`# ./install.sh install`

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

## Web 管理コンソール
Web 管理コンソールの使い方については、docsの下の「LISM_管理者ガイド」をご覧ください。
