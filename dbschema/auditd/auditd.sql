-- Creator:       MySQL Workbench 5.2.43/ExportSQLite plugin 2009.12.02
-- Author:        Beng Heng Ng
-- Caption:       New Model
-- Project:       SecureFile
-- Changed:       2013-02-26 12:01
-- Created:       2012-09-25 21:47
PRAGMA foreign_keys = OFF;

-- Schema: mydb
BEGIN;
CREATE TABLE "type"(
  "tyid" INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
  "description" TEXT NOT NULL,
  CONSTRAINT "tyid_UNIQUE"
    UNIQUE("tyid")
);
CREATE TABLE "user"(
  "uid" INTEGER PRIMARY KEY NOT NULL,
  CONSTRAINT "uid_UNIQUE"
    UNIQUE("uid")
);
CREATE TABLE "group"(
  "gid" INTEGER PRIMARY KEY NOT NULL,
  CONSTRAINT "gid_UNIQUE"
    UNIQUE("gid")
);
CREATE TABLE "syscall_open"(
  "sc_open_id" INTEGER PRIMARY KEY NOT NULL,
  "flags" INTEGER
);
CREATE TABLE "syscall_execve"(
  "sc_execve_id" INTEGER PRIMARY KEY NOT NULL,
  "argc" INTEGER,
  "arg0" TEXT,
  "arg1" TEXT,
  "arg2" TEXT,
  "arg3" TEXT
);
CREATE TABLE "program"(
  "progid" INTEGER PRIMARY KEY NOT NULL,
  "comm" TEXT,
  "exe" TEXT
);
CREATE TABLE "group_name"(
  "gnid" INTEGER PRIMARY KEY NOT NULL,
  "gid" INTEGER,
  "name" TEXT,
  CONSTRAINT "gnid_UNIQUE"
    UNIQUE("gnid"),
  CONSTRAINT "fk_group_name_1"
    FOREIGN KEY("gid")
    REFERENCES "group"("gid")
);
CREATE INDEX "group_name.fk_group_name_1_idx" ON "group_name"("gid");
CREATE TABLE "user_name"(
  "unid" INTEGER PRIMARY KEY NOT NULL,
  "uid" INTEGER,
  "name" TEXT,
  "pri_gid" INTEGER,
  CONSTRAINT "unid_UNIQUE"
    UNIQUE("unid"),
  CONSTRAINT "fk_user_name_1"
    FOREIGN KEY("uid")
    REFERENCES "user"("uid"),
  CONSTRAINT "fk_user_name_2"
    FOREIGN KEY("pri_gid")
    REFERENCES "group"("gid")
);
CREATE INDEX "user_name.fk_user_name_1_idx" ON "user_name"("uid");
CREATE INDEX "user_name.fk_user_name_2_idx" ON "user_name"("pri_gid");
CREATE TABLE "Principal"(
  "aid" INTEGER PRIMARY KEY NOT NULL,
  "uid" INTEGER,
  "gid" INTEGER,
  CONSTRAINT "fk_Actor_1"
    FOREIGN KEY("uid")
    REFERENCES "user"("uid"),
  CONSTRAINT "fk_Actor_2"
    FOREIGN KEY("gid")
    REFERENCES "group"("gid")
);
CREATE INDEX "Principal.fk_Actor_1_idx" ON "Principal"("uid");
CREATE INDEX "Principal.fk_Actor_2_idx" ON "Principal"("gid");
CREATE TABLE "ConfigSpec"(
  "csid" INTEGER PRIMARY KEY NOT NULL,
  "key" TEXT,
  "type" TEXT,
  "param" TEXT,
  "default" TEXT
);
CREATE TABLE "Operation"(
  "opid" INTEGER PRIMARY KEY NOT NULL,
  "label" TEXT
);
CREATE TABLE "Resource"(
  "rid" INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
  "inode" INTEGER,
  "path" TEXT NOT NULL,
  "tyid" INTEGER,
  "extension" TEXT,
  "uid" INTEGER,
  "gid" INTEGER,
  "mode" INTEGER,
  CONSTRAINT "fileid_UNIQUE"
    UNIQUE("rid"),
  CONSTRAINT "fk_path_properties_1"
    FOREIGN KEY("tyid")
    REFERENCES "type"("tyid"),
  CONSTRAINT "fk_Resource_3"
    FOREIGN KEY("uid")
    REFERENCES "user"("uid"),
  CONSTRAINT "fk_Resource_4"
    FOREIGN KEY("gid")
    REFERENCES "group"("gid")
);
CREATE INDEX "Resource.fk_path_properties_1_idx" ON "Resource"("tyid");
CREATE INDEX "Resource.fk_Resource_3_idx" ON "Resource"("uid");
CREATE INDEX "Resource.fk_Resource_4_idx" ON "Resource"("gid");
CREATE INDEX "Resource.index6" ON "Resource"("inode");
CREATE TABLE "group_membership"(
  "unid" INTEGER,
  "gnid" INTEGER,
  CONSTRAINT "fk_group_membership_1"
    FOREIGN KEY("unid")
    REFERENCES "user_name"("unid"),
  CONSTRAINT "fk_group_membership_2"
    FOREIGN KEY("gnid")
    REFERENCES "group_name"("gnid")
);
CREATE INDEX "group_membership.fk_group_membership_1_idx" ON "group_membership"("unid");
CREATE INDEX "group_membership.fk_group_membership_2_idx" ON "group_membership"("gnid");
CREATE INDEX "group_membership.index3" ON "group_membership"("unid","gnid");
CREATE TABLE "ReqPerm"(
  "pid" INTEGER PRIMARY KEY NOT NULL,
  "rid" INTEGER NOT NULL,
  "opid" INTEGER NOT NULL,
  "aid" INTEGER NOT NULL,
  CONSTRAINT "index5"
    UNIQUE("rid","opid","aid"),
  CONSTRAINT "fk_ReqPerm_1"
    FOREIGN KEY("rid")
    REFERENCES "Resource"("rid"),
  CONSTRAINT "fk_ReqPerm_2"
    FOREIGN KEY("aid")
    REFERENCES "Principal"("aid"),
  CONSTRAINT "fk_ReqPerm_3"
    FOREIGN KEY("opid")
    REFERENCES "Operation"("opid")
);
CREATE INDEX "ReqPerm.fk_ReqPerm_1_idx" ON "ReqPerm"("rid");
CREATE INDEX "ReqPerm.fk_ReqPerm_2_idx" ON "ReqPerm"("aid");
CREATE INDEX "ReqPerm.fk_ReqPerm_3_idx" ON "ReqPerm"("opid");
CREATE TABLE "Process"(
  "procid" INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
  "progid" INTEGER NOT NULL,
  "pid" INTEGER NOT NULL,
  "ppid" INTEGER,
  CONSTRAINT "index4"
    UNIQUE("progid","pid","ppid"),
  CONSTRAINT "procid_UNIQUE"
    UNIQUE("procid"),
  CONSTRAINT "fk_process_1"
    FOREIGN KEY("progid")
    REFERENCES "program"("progid")
);
CREATE INDEX "Process.fk_process_1_idx" ON "Process"("progid");
CREATE TABLE "OpMeta"(
  "omid" INTEGER PRIMARY KEY NOT NULL,
  "rid" INTEGER,
  "procid" INTEGER,
  "sc_open_id" INTEGER,
  "sc_execve_id" INTEGER,
  "serial" INTEGER,
  "sec" INTEGER,
  "milli" INTEGER,
  "syscall" INTEGER,
  "success" INTEGER,
  "exit" INTEGER,
  "auid" INTEGER,
  "uid" INTEGER,
  "gid" INTEGER,
  "euid" INTEGER,
  "suid" INTEGER,
  "fsuid" INTEGER,
  "egid" INTEGER,
  "sgid" INTEGER,
  "fsgid" INTEGER,
  "ouid" INTEGER,
  "ogid" INTEGER,
  "mode" INTEGER,
  "opid" INTEGER,
  CONSTRAINT "fk_MetaOp_1"
    FOREIGN KEY("procid")
    REFERENCES "Process"("procid"),
  CONSTRAINT "fk_MetaOp_2"
    FOREIGN KEY("sc_open_id")
    REFERENCES "syscall_open"("sc_open_id"),
  CONSTRAINT "fk_MetaOp_3"
    FOREIGN KEY("sc_execve_id")
    REFERENCES "syscall_execve"("sc_execve_id"),
  CONSTRAINT "fk_ReqOpMeta_1"
    FOREIGN KEY("uid")
    REFERENCES "user"("uid"),
  CONSTRAINT "fk_ReqOpMeta_2"
    FOREIGN KEY("euid")
    REFERENCES "user"("uid"),
  CONSTRAINT "fk_ReqOpMeta_3"
    FOREIGN KEY("suid")
    REFERENCES "user"("uid"),
  CONSTRAINT "fk_ReqOpMeta_4"
    FOREIGN KEY("fsuid")
    REFERENCES "user"("uid"),
  CONSTRAINT "fk_ReqOpMeta_5"
    FOREIGN KEY("egid")
    REFERENCES "group"("gid"),
  CONSTRAINT "fk_ReqOpMeta_6"
    FOREIGN KEY("sgid")
    REFERENCES "group"("gid"),
  CONSTRAINT "fk_ReqOpMeta_7"
    FOREIGN KEY("fsgid")
    REFERENCES "group"("gid"),
  CONSTRAINT "fk_ReqOpMeta_8"
    FOREIGN KEY("gid")
    REFERENCES "group"("gid"),
  CONSTRAINT "fk_ReqOpMeta_10"
    FOREIGN KEY("ouid")
    REFERENCES "user"("uid"),
  CONSTRAINT "fk_ReqOpMeta_11"
    FOREIGN KEY("ogid")
    REFERENCES "group"("gid"),
  CONSTRAINT "fk_Operation_1"
    FOREIGN KEY("rid")
    REFERENCES "Resource"("rid"),
  CONSTRAINT "fk_OpMeta_1"
    FOREIGN KEY("opid")
    REFERENCES "Operation"("opid")
);
CREATE INDEX "OpMeta.fk_MetaOp_1_idx" ON "OpMeta"("procid");
CREATE INDEX "OpMeta.fk_MetaOp_2_idx" ON "OpMeta"("sc_open_id");
CREATE INDEX "OpMeta.fk_MetaOp_3_idx" ON "OpMeta"("sc_execve_id");
CREATE INDEX "OpMeta.fk_ReqOpMeta_1_idx" ON "OpMeta"("uid");
CREATE INDEX "OpMeta.fk_ReqOpMeta_2_idx" ON "OpMeta"("euid");
CREATE INDEX "OpMeta.fk_ReqOpMeta_3_idx" ON "OpMeta"("suid");
CREATE INDEX "OpMeta.fk_ReqOpMeta_4_idx" ON "OpMeta"("fsuid");
CREATE INDEX "OpMeta.fk_ReqOpMeta_5_idx" ON "OpMeta"("egid");
CREATE INDEX "OpMeta.fk_ReqOpMeta_6_idx" ON "OpMeta"("sgid");
CREATE INDEX "OpMeta.fk_ReqOpMeta_7_idx" ON "OpMeta"("fsgid");
CREATE INDEX "OpMeta.fk_ReqOpMeta_8_idx" ON "OpMeta"("gid");
CREATE INDEX "OpMeta.fk_ReqOpMeta_10_idx" ON "OpMeta"("ouid");
CREATE INDEX "OpMeta.fk_ReqOpMeta_11_idx" ON "OpMeta"("ogid");
CREATE INDEX "OpMeta.fk_Operation_1_idx" ON "OpMeta"("rid");
CREATE INDEX "OpMeta.fk_OpMeta_1_idx" ON "OpMeta"("opid");
CREATE TABLE "GrPerm"(
  "pid" INTEGER PRIMARY KEY NOT NULL,
  "rid" INTEGER,
  "opid" INTEGER,
  "aid" INTEGER,
  CONSTRAINT "index4"
    UNIQUE("rid","opid","aid"),
  CONSTRAINT "fk_GrOpActor_2"
    FOREIGN KEY("aid")
    REFERENCES "Principal"("aid"),
  CONSTRAINT "fk_GrPerm_1"
    FOREIGN KEY("rid")
    REFERENCES "Resource"("rid"),
  CONSTRAINT "fk_GrPerm_2"
    FOREIGN KEY("opid")
    REFERENCES "Operation"("opid")
);
CREATE INDEX "GrPerm.fk_GrOpActor_2_idx" ON "GrPerm"("aid");
CREATE INDEX "GrPerm.fk_GrPerm_1_idx" ON "GrPerm"("rid");
CREATE INDEX "GrPerm.fk_GrPerm_2_idx" ON "GrPerm"("opid");
CREATE TABLE "Config"(
  "cid" INTEGER PRIMARY KEY NOT NULL,
  "csid" INTEGER,
  "value" TEXT,
  "value_shadow" TEXT,
  CONSTRAINT "fk_GrOpMeta_2"
    FOREIGN KEY("csid")
    REFERENCES "ConfigSpec"("csid")
);
CREATE INDEX "Config.fk_GrOpMeta_2_idx" ON "Config"("csid");
CREATE TABLE "NewGrPerm"(
  "pid" INTEGER PRIMARY KEY NOT NULL,
  "rid" INTEGER,
  "opid" INTEGER,
  "aid" INTEGER,
  CONSTRAINT "index4"
    UNIQUE("rid","opid","aid"),
  CONSTRAINT "fk_GrOpActor_20"
    FOREIGN KEY("aid")
    REFERENCES "Principal"("aid"),
  CONSTRAINT "fk_GrPerm_10"
    FOREIGN KEY("rid")
    REFERENCES "Resource"("rid"),
  CONSTRAINT "fk_GrPerm_20"
    FOREIGN KEY("opid")
    REFERENCES "Operation"("opid")
);
CREATE INDEX "NewGrPerm.fk_GrOpActor_2_idx" ON "NewGrPerm"("aid");
CREATE INDEX "NewGrPerm.fk_GrPerm_1_idx" ON "NewGrPerm"("rid");
CREATE INDEX "NewGrPerm.fk_GrPerm_2_idx" ON "NewGrPerm"("opid");
CREATE TABLE "ResourceConfig"(
  "rcid" INTEGER PRIMARY KEY NOT NULL,
  "rid" INTEGER,
  "cid" INTEGER,
  CONSTRAINT "index4"
    UNIQUE("rid","cid"),
  CONSTRAINT "fk_ResourceConfig_1"
    FOREIGN KEY("cid")
    REFERENCES "Config"("cid"),
  CONSTRAINT "fk_ResourceConfig_2"
    FOREIGN KEY("rid")
    REFERENCES "Resource"("rid")
);
CREATE INDEX "ResourceConfig.fk_ResourceConfig_1_idx" ON "ResourceConfig"("cid");
CREATE INDEX "ResourceConfig.fk_ResourceConfig_2_idx" ON "ResourceConfig"("rid");
COMMIT;
