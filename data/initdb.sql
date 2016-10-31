GRANT ALL ON LISM.* TO 'admin'@'localhost' IDENTIFIED BY 'secret';

CREATE TABLE users (
  id int(10) NOT NULL auto_increment,
  user_id char(10) default '',
  user_name char(32) default '',
  passwd char(128) default '',
  email char(32) default '',
  fax varchar(256) default '',
  modifytime int(10) default 0,
  PRIMARY KEY (id)
);

CREATE TABLE phones (
  id int(10) NOT NULL auto_increment,
  users_id int(10),
  phone char(32) default '',
  modifytime int(10) default 0,
  PRIMARY KEY (id)
);

CREATE TABLE groups (
  id int(10) NOT NULL auto_increment,
  group_name char(32) default '',
  PRIMARY KEY (id)
);

CREATE TABLE users_groups_link (
  id int(10) NOT NULL auto_increment,
  uid int(10),
  gid int(10),
  PRIMARY KEY (id)
);

CREATE TABLE divisions (
  id int(10) NOT NULL auto_increment,
  division_name char(32) default '',
  division_longname char(32) default '',
  division_status char(32) default '',
  PRIMARY KEY (id)
);

CREATE TABLE departments (
  id int(10) NOT NULL auto_increment,
  department_name char(32) default '',
  department_longname char(32) default '',
  department_status char(32) default '',
  PRIMARY KEY (id)
);

CREATE TABLE divisions_departments_link (
  id int(10) NOT NULL auto_increment,
  dvid int(10),
  dpid int(10),
  PRIMARY KEY (id)
);

CREATE TABLE users_departments_link (
  id int(10) NOT NULL auto_increment,
  uid int(10),
  dpid int(10),
  modifytime int(10) default 0,
  PRIMARY KEY (id)
);

CREATE TABLE categories (
  id int(10) NOT NULL auto_increment,
  category_name char(32) default '',
  category_status char(32) default '',
  PRIMARY KEY (id)
);

CREATE TABLE groups_categories_link (
  id int(10) NOT NULL auto_increment,
  gid int(10),
  cid int(10),
  PRIMARY KEY (id)
);

CREATE TABLE cmplx_users (
  id int(10) NOT NULL auto_increment,
  user_id char(10) default '',
  user_name char(32) default '',
  passwd char(128) default '',
  email char(32) default '',
  PRIMARY KEY (id)
);

CREATE TABLE cmplx_groups (
  id int(10) NOT NULL auto_increment,
  group_name char(32) default '',
  description char(32) default '',
  parentid int(10) default NULL,
  PRIMARY KEY (id)
);

CREATE TABLE cmplx_users_groups_link (
  id int(10) NOT NULL auto_increment,
  uid int(10),
  gid int(10),
  PRIMARY KEY (id)
);

CREATE TABLE cmplx_divisions (
  id int(10) NOT NULL auto_increment,
  division_name char(32) default '',
  PRIMARY KEY (id)
);

CREATE TABLE cmplx_departments (
  id int(10) NOT NULL auto_increment,
  department_name char(32) default '',
  PRIMARY KEY (id)
);

CREATE TABLE cmplx_divisions_departments_link (
  id int(10) NOT NULL auto_increment,
  dvid int(10),
  dpid int(10),
  PRIMARY KEY (id)
);

CREATE TABLE cmplx_users_departments_link (
  id int(10) NOT NULL auto_increment,
  uid int(10),
  dpid int(10),
  PRIMARY KEY (id)
);

CREATE TABLE cmplx_groups_divisions_link (
  id int(10) NOT NULL auto_increment,
  gid int(10),
  dvid int(10),
  PRIMARY KEY (id)
);

CREATE TABLE rcsv_groups (
  id int(10) NOT NULL auto_increment,
  group_name char(32) default '',
  description char(32) default '',
  parentid int(10) default NULL,
  PRIMARY KEY (id)
);

CREATE TABLE rcsv_users_groups_link (
  id int(10) NOT NULL auto_increment,
  uid int(10),
  gid int(10),
  PRIMARY KEY (id)
);
