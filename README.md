# LISM
LISM(LDAP Identity Synchronization Manager)は、LDAP、リレーショナルデータベース、CSVファイルといった様々形式で管理されているID情報を、LDAPインターフェースを通して一元的に管理することができるオープンソースの統合ID管理ソフトウェアです。

## 概要
統合ID管理ソフトウェア「LISM」は、様々なシステムに分散したID情報や役割（ロール）情報を一元的に管理することができるソフトウェアです。  
LISMは、システムの情報を１つのLDAPディレクトリツリーとして管理し、連携先の各システムの情報はそれぞれサブツリーに分かれて管理されています。マスタデータとなるLDAPサーバの情報については、ou=LDAPとou=Masterの配下に表示され、ou=Master配下の情報がマスタデータとして扱われます。  
  
そのため、LISMのマスタデータ（OpenLDAP）に対して更新を行うことで、LISMと連携されている  
Active Directory、LDAP、RDBMSや、CSVファイル出力、RESTful API、SOAP APIを持ったWebサービスに対してID情報の更新内容をリアルタイムで同期することができます。  
ID情報の管理は、基本的にマスタデータに対して操作のみの一元管理を実現します。

## 動作環境
* OS：Rockey Linux8、Redhat Enterprise Linux 8

## インストール
#### selinux無効化
setenforce 0
*/etc/selinux/config でdisabledに変更も

#### EPEL有効化
`# dnf install dnf-plugins-core`

`# dnf install epel-release`

`# dnf config-manager --set-enabled powertools`

### LISM用LDAPサーバの設定
LISMの管理用LDAPとして利用するためのスキーマ設定とエントリーを追加します。

#### 389DSサーバーインストール
`# dnf module enable 389-ds -y`

`# dnf install -y 389-ds-base 389-ds-base-legacy-tools`

以下のコマンドで基本設定を行ってください。

`# setup-ds.pl`

###### schema拡張
以下Directory ServerのIDを389dsとした場合のコマンドを記載します。slapd-389dsの部分は設定したIDに適宜置き換えて実行してください。

`# cp /opt/secioss/ldap/389ds/schema/50secioss.ldif /etc/dirsrv/slapd-389ds/schema/`

`# systemctl restart dirsrv@389ds`

###### サーバー設定
`# cd /opt/secioss/ldap/389ds/ldif/`

`# ldapmodify -H ldap://localhost -D {RootDN} -w {パスワード} -f 389ds.ldif`

`# ldapmodify -H ldap://localhost -D {RootDN} -w {パスワード} -f 389ds_index.ldif`

`# systemctl restart dirsrv@389ds`


###### 基本データ登録
`# cd /opt/secioss/ldap/389ds/ldif/`

`# cp init.389ds.xxxx.ldif modify.ldif`

BaseDNを「dc=test,dc=ldap」に指定したときのコマンドです。設定したBaseDNに置き換えて実行してください。

`# sed -i -e "s/dc=example,dc=com/dc=test,dc=ldap/g" modify.ldif`

`# ldapmodify -x -H ldap://localhost -D {RootDN} -f modify.ldif`

### LISMインストール
githubのpackages/LISM-5.x.x-x.x86_64.tar.gzを展開して、インストールスクリプト(install.sh)を実行して下さい。  
`# tar -zxcf LISM-5.xxxx.tar.gz`

`# cd LISM-xxxxx`

`# ./install install`

#### lism-server
`# cp /opt/secioss/etc/openldap/slapd.conf.lism /opt/secioss/etc/openldap/slapd.conf`

`# chown ldap:ldap /opt/secioss/etc/openldap/slapd.conf`

`# cp /opt/secioss/etc/lism-server.service /etc/systemd/system`

lism-server起動

`# systemctl start lism-server`


## 動作確認

#### CSV同期ディレクトリ作成
`# mkdir /opt/secioss/var/lib/tenantcsv`

`# chown ldap:ldap /opt/secioss/var/lib/tenantcsv`

#### 同期用DB
`# dnf install mariadb mariadb-server`

`# systemctl start mariadb`

`# mysql`

`> CREATE DATABASE sample;`

`> CREATE TABLE user(user_id VARCHAR(64) PRIMARY KEY, emp_code VARCHAR(32), last_name VARCHAR(32), first_name VARCHAR(32), mail VARCHAR(64));`

`> CREATE TABLE password(id INT AUTO_INCREMENT PRIMARY KEY, user_id VARCHAR(64), password TINYTEXT, change_date DATETIME, delete_flag TINYINT);`

`> CREATE USER "admin"@"localhost" IDENTIFIED BY adminpass;`

#### 同期データ準備
`# vi /opt/secioss/var/lib/tenantcsv/organization.csv`

> 組織,

`# vi /opt/secioss/var/lib/tenantcsv/user.csv`

> yamada,1001,山田,太郎,ヤマダ,タロウ,yamada@example.com,active,Passwd01,組織

#### CSV => MASTER 差分確認
`# /opt/secioss/sbin/lismsync -f '(objectClass=organizationalUnit)' -d CSV read master`

`# /opt/secioss/sbin/lismsync -f '(objectClass=seciossIamAccount)' -d CSV read master`

#### CSV => MASTER 差分更新
`# /opt/secioss/sbin/lismsync -f '(objectClass=organizationalUnit)' -d CSV update master`

`# /opt/secioss/sbin/lismsync -f '(objectClass=seciossIamAccount)' -d CSV update master`

#### MASTER => DB 差分確認
`# /opt/secioss/sbin/lismsync -f '(objectClass=seciossIamAccount)' -d DB read cluster`

#### MASTER => DB 差分更新
`# /opt/secioss/sbin/lismsync -f '(objectClass=seciossIamAccount)' -d DB update cluster`

*CSV,DBの部分は/opt/secioss/etc/lism.confのDataのnameの値を指定しています。
