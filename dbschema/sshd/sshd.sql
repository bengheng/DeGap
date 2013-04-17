-- Creator:       MySQL Workbench 5.2.43/ExportSQLite plugin 2009.12.02
-- Author:        Beng Heng Ng
-- Caption:       New Model
-- Project:       Name of the project
-- Changed:       2012-12-27 21:03
-- Created:       2012-10-08 11:55
PRAGMA foreign_keys = OFF;

-- Schema: mydb
BEGIN;
CREATE TABLE "Principal"(
  "aid" INTEGER PRIMARY KEY NOT NULL,
  "user" TEXT
);
CREATE TABLE "ConfigSpec"(
  "csid" INTEGER PRIMARY KEY NOT NULL,
  "key" TEXT,
  "type" TEXT,
  "param" TEXT,
  "default" TEXT
);
CREATE TABLE "Operation"(
  "opid" INTEGER PRIMARY KEY NOT NULL,
  "method" TEXT,
  "protocol" TEXT
);
CREATE TABLE "Resource"(
  "rid" INTEGER PRIMARY KEY NOT NULL,
  "hostname" VARCHAR(45)
);
CREATE TABLE "GrPerm"(
  "pid" INTEGER PRIMARY KEY NOT NULL,
  "rid" INTEGER,
  "opid" INTEGER,
  "aid" INTEGER,
  CONSTRAINT "uniq_permission"
    UNIQUE("aid","opid","rid"),
  CONSTRAINT "fk_GrOp_1"
    FOREIGN KEY("rid")
    REFERENCES "Resource"("rid"),
  CONSTRAINT "fk_GrOp_2"
    FOREIGN KEY("opid")
    REFERENCES "Operation"("opid"),
  CONSTRAINT "fk_GrPerm_1"
    FOREIGN KEY("aid")
    REFERENCES "Principal"("aid")
);
CREATE INDEX "GrPerm.fk_GrOp_1_idx" ON "GrPerm"("rid");
CREATE INDEX "GrPerm.fk_GrOp_2_idx" ON "GrPerm"("opid");
CREATE INDEX "GrPerm.fk_GrPerm_1_idx" ON "GrPerm"("aid");
CREATE TABLE "Config"(
  "cid" INTEGER PRIMARY KEY NOT NULL,
  "csid" INTEGER,
  "value" TEXT,
  "value_shadow" TEXT,
  CONSTRAINT "fk_GrOpMeta_1"
    FOREIGN KEY("csid")
    REFERENCES "ConfigSpec"("csid")
);
CREATE INDEX "Config.fk_GrOpMeta_1_idx" ON "Config"("csid");
CREATE TABLE "NewGrPerm"(
  "pid" INTEGER PRIMARY KEY NOT NULL,
  "rid" INTEGER,
  "opid" INTEGER,
  "aid" INTEGER,
  CONSTRAINT "uniq_permission"
    UNIQUE("aid","opid","rid"),
  CONSTRAINT "fk_GrOpActor_200"
    FOREIGN KEY("aid")
    REFERENCES "Principal"("aid"),
  CONSTRAINT "fk_NewGrPerm_1"
    FOREIGN KEY("rid")
    REFERENCES "Resource"("rid"),
  CONSTRAINT "fk_NewGrPerm_2"
    FOREIGN KEY("opid")
    REFERENCES "Operation"("opid")
);
CREATE INDEX "NewGrPerm.fk_GrOpActor_2_idx" ON "NewGrPerm"("aid");
CREATE INDEX "NewGrPerm.fk_NewGrPerm_1_idx" ON "NewGrPerm"("rid");
CREATE INDEX "NewGrPerm.fk_NewGrPerm_2_idx" ON "NewGrPerm"("opid");
CREATE TABLE "ResourceConfig"(
  "rcid" INTEGER PRIMARY KEY NOT NULL,
  "rid" INTEGER,
  "cid" INTEGER,
  CONSTRAINT "fk_ResourceConfig_1"
    FOREIGN KEY("rid")
    REFERENCES "Resource"("rid"),
  CONSTRAINT "fk_ResourceConfig_2"
    FOREIGN KEY("cid")
    REFERENCES "Config"("cid")
);
CREATE INDEX "ResourceConfig.fk_ResourceConfig_1_idx" ON "ResourceConfig"("rid");
CREATE INDEX "ResourceConfig.fk_ResourceConfig_2_idx" ON "ResourceConfig"("cid");
CREATE TABLE "ReqPerm"(
  "pid" INTEGER PRIMARY KEY NOT NULL,
  "rid" INTEGER,
  "opid" INTEGER,
  "aid" INTEGER,
  CONSTRAINT "uniq_permission"
    UNIQUE("opid","rid","aid"),
  CONSTRAINT "fk_operation_1"
    FOREIGN KEY("opid")
    REFERENCES "Operation"("opid"),
  CONSTRAINT "fk_operation_2"
    FOREIGN KEY("rid")
    REFERENCES "Resource"("rid"),
  CONSTRAINT "fk_ReqPerm_1"
    FOREIGN KEY("aid")
    REFERENCES "Principal"("aid")
);
CREATE INDEX "ReqPerm.fk_operation_1_idx" ON "ReqPerm"("opid");
CREATE INDEX "ReqPerm.fk_operation_2_idx" ON "ReqPerm"("rid");
CREATE INDEX "ReqPerm.fk_ReqPerm_1_idx" ON "ReqPerm"("aid");
CREATE TABLE "OpMeta"(
  "omid" INTEGER PRIMARY KEY NOT NULL,
  "rid" INTEGER,
  "datetime" DATETIME,
  "serial" INTEGER,
  "status" TEXT,
  "user_validity" TEXT,
  "aid" INTEGER,
  "src_port" INTEGER,
  "ip" TEXT,
  "domainname" TEXT,
  CONSTRAINT "fk_ReqOpMeta_1"
    FOREIGN KEY("rid")
    REFERENCES "Resource"("rid"),
  CONSTRAINT "fk_ReqOpMeta_3"
    FOREIGN KEY("aid")
    REFERENCES "Principal"("aid")
);
CREATE INDEX "OpMeta.fk_ReqOpMeta_1_idx" ON "OpMeta"("rid");
CREATE INDEX "OpMeta.fk_ReqOpMeta_3_idx" ON "OpMeta"("aid");
COMMIT;
