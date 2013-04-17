#!/usr/bin/env python

import os
import sys
import sqlite3
from ConfigParser import SafeConfigParser
sys.path.append(os.path.realpath(os.path.join(sys.path[0], '../../')))

from Degap.Sshd.SshdResourceMeta import *
from Degap.Sshd.SshdResource import *
from Degap.Sshd.SshdOpLabel import *
from Degap.Sshd.SshdGrOpMeta import *
from Degap.Sshd.SshdActor import *
from Degap.Sshd.SshdCommon import *
from Degap.Config import *

def update_metadata(conn, cfg, mdfile, rsrc, shadow=False):
	# Update resource (sshd_config)
	configs = load_sshd_config( conn, mdfile, cfg )
	rsrc.compute_permissions( configs, shadow )
	rsrc.compute_actors(shadow)

#------------------------------------------------------------------------------
# Main
#------------------------------------------------------------------------------
if __name__=='__main__':
	cfgname = 'config.ini'
	if not os.path.exists(cfgname):
		print 'Cannot find configuration file \"%s\".' % cfgname
		sys.exit(-1)

	cfg = SafeConfigParser()
	cfg.optionxform = str
	cfg.read(cfgname)

	db = cfg.get('CONFIG', 'db')
	if not os.path.exists(db):
		print 'Cannot find database \"%s". ' \
						'Please check db configuration in \"%s\".' \
						% (db, cfgname)
		sys.exit(-1)

	conn = sqlite3.connect(db)
	cur = conn.cursor()
	cur.execute( 'PRAGMA synchronous = OFF' )
	cur.execute( 'PRAGMA journal_mode = MEMORY' )
	cur.close()

	print 'Connected to \"%s\".' % db

	rsrc_meta = SshdResourceMeta(conn, rmid=None, hostname=cfg.get('CONFIG', 'hostname'))
	rsrc = SshdResource( conn, rsrc_meta, None )

	# Load the default configurations
	mdfile = cfg.get('CONFIG', 'sshdcfg')
	print 'Loading configurations from \"%s\"...' % mdfile
	update_metadata(conn, cfg, mdfile, rsrc, shadow=False)

	# If there is a shadow configuration file, load it.
	if 'sshdcfgshadow' in cfg.options('CONFIG'):
		mdfile = cfg.get('CONFIG', 'sshdcfgshadow')
		print 'Loading shadow configurations from \"%s\"...' % mdfile
		update_metadata(conn, cfg, mdfile, rsrc, shadow=True)

	conn.close()
