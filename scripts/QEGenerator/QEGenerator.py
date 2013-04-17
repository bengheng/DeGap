#!/usr/bin/env python

import os
import sys
import stat
import copy
import sqlite3
import string
from ConfigParser import SafeConfigParser
from ConfigParser import NoOptionError

from QEQuery import *

#------------------------------------------------------------------------------
# Generates the Query Engine by substituting the generated strings.
#------------------------------------------------------------------------------
def make_query( conn, qequery, sql ):
	count_modifier = qequery.get_count_modifier()
	cur = conn.cursor()
	cur.execute( sql )
	if count_modifier == None or count_modifier == False:
		rows = cur.fetchall()
		print '### Query Results ###\n' \
				+ '\n'.join( ', '.join(str(e) for e in t) for t in rows ) \
				+ '\n### End of Query Results ###'

	else:
		r = cur.fetchone()
		res = eval('%d %s %s' % (r[0], count_modifier[0], count_modifier[1]))
		if res is False:
			print 'Error. Expect number of results to be %s %s, but has %d.' %\
					(count_modifier[0], count_modifier[1], r[0])
		else:
			print 'Number of results matches expected value %s.' % count_modifier[1]
	cur.close()


#------------------------------------------------------------------------------
# Main.
#------------------------------------------------------------------------------
if __name__=='__main__':
	cfgname = 'config.ini'
	if not os.path.exists(cfgname):
		print 'Cannot find configuration file \"%s\".' % cfgname
		sys.exit(-1)

	cfg = SafeConfigParser()
	cfg.optionxform = str
	cfg.read(cfgname)

	if len(sys.argv) != 2:
		print 'Usage: %s <option>'
		if cfg != None:
			print 'Available options:'
			for s in cfg.sections():
				if s != 'CONFIG':
					print '- ' + s
		sys.exit(0)

	db = cfg.get('CONFIG', 'db')
	if not os.path.exists(db):
		print 'Cannot find database \"%s". ' \
						'Please check db configuration in \"%s\".' \
						% (db, cfgname)
		sys.exit(-1)

	conn = sqlite3.connect(db)
	print 'Connected to \"%s\".' % db

	section = sys.argv[1]
	qequery = QEQuery( conn, cfg, section )
	sql = qequery.mk_sql()
	make_query( conn, qequery, sql )
	conn.close()
	print 'QEGenerator done.'
