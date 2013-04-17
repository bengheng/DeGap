#!/usr/bin/env python

import os
import sys
import types
import sqlite3
import string
from ConfigParser import SafeConfigParser
from ConfigParser import NoOptionError

sys.path.append(os.path.realpath(os.path.join(sys.path[0], '../../')))
from Degap.Auditd.AuditdResource import *

#------------------------------------------------------------------------------
# Main.
#------------------------------------------------------------------------------
if __name__=='__main__':
	cfgname = 'config.ini'
	if not os.path.exists(cfgname):
		print 'Cannot find configuration file \"%s\".' % cfgname
		sys.exit(-1)

	cfg = SafeConfigParser()
	cfg.read(cfgname)

	db = cfg.get('CONFIG', 'db')
	if not os.path.exists(db):
		print 'Cannot find database \"%s". ' \
						'Please check db configuration in \"%s\".' \
						% (db, cfgname)
		sys.exit(-1)

	conn = sqlite3.connect(db)
	print 'Connected to \"%s\".' % db
	meta = get_meta( conn )
	for m in meta:
		rid = m[0]
		print '### rid %d ###' % rid
		rsrc = AuditdResource( conn, None, None, rid )
		rsrc.compute_hypothesis()
	conn.close()
	print 'Done.'

