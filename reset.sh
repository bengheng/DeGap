#!/bin/bash

echo "Removing all transient files..."

AUDITD="./test/auditd"
rm $AUDITD/ausecure.log \
  $AUDITD/config.ini \
  $AUDITD/db.sl3 \
  $AUDITD/db-users.sl3 \
  $AUDITD/filenames.dat \
  $AUDITD/filetree.dat \
  $AUDITD/strhash.txt

SSHD="./test/sshd"
rm $SSHD/sshd-db.sl3 \
  $SSHD/sshd.log

rm ./src/auditd-parser/ausecure
rm ./bin/ausecure

DEGAP="./scripts/DeGap"
rm $DEGAP/*.pyc \
  $DEGAP/plugins/*.pyc \
  $DEGAP/plugins/Auditd/*.pyc \
  $DEGAP/plugins/Sshd/*.pyc \
  $DEGAP/plugins/Users/*.pyc
