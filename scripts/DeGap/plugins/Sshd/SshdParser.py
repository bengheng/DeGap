#!/usr/bin/env python

import os
import re
import sys
import sqlite3
import subprocess
from ConfigParser import SafeConfigParser
#sys.path.append(os.path.realpath(os.path.join(sys.path[0], '../../')))

#from Degap.Sshd.SshdActor import *
#from Degap.Sshd.SshdResourceMeta import *
#from Degap.Sshd.SshdResource import *
#from Degap.Sshd.SshdReqOpMeta import *
#from Degap.Sshd.SshdOpLabel import *

from plugins.Sshd.SshdResource import *
from plugins.Sshd.SshdPrincipal import *

class SshdParser:

	def __init__(self, conn, cur, rsrc):
		self.conn = conn
		self.cur = cur
		self.rsrc = rsrc
		self.p1 = re.compile('.*sshd\[[0-9]*\]: '\
											 '(Accepted|Failed) .* for .* from .* port [0-9]* .*')
		self.p2 = re.compile('.*sshd\[[0-9]*\]: '\
											 'User .* from .* not allowed because not listed in AllowUsers')

	def parse(self, inlog):
		f = open(inlog, 'r')
		line = f.readline()
		while line:
			if self.p1.match(line) != None:
				l = line.split()
				self.update_op( l, self.rsrc.rid )
			elif self.p2.match(line) != None:
				l = line.split()
				self.update_op_unlisted( l, self.rsrc.rid )
			line = f.readline()

		f.close()

	#------------------------------------------------------------------------------
	# Get datetime string in the format 'yyyy-MM-dd HH:mm:ss' from line l. We'll
	# assume yyyy to be 2012.
	#------------------------------------------------------------------------------
	def get_datetime(self, l):
		s = '2012-'
		if l[0] == 'Jan': s += '01-'
		elif l[0] == 'Feb': s += '02-'
		elif l[0] == 'Mar': s += '03-'
		elif l[0] == 'Apr': s += '04-'
		elif l[0] == 'May': s += '05-'
		elif l[0] == 'Jun': s += '06-'
		elif l[0] == 'Jul': s += '07-'
		elif l[0] == 'Aug': s += '08-'
		elif l[0] == 'Sep': s += '09-'
		elif l[0] == 'Oct': s += '10-'
		elif l[0] == 'Nov': s += '11-'
		elif l[0] == 'Dec': s += '12-'
	 
		s += l[1]
		s += ' ' + l[2]
		return s


	#------------------------------------------------------------------------------
	# Returns serial for operation.
	#------------------------------------------------------------------------------
	def get_serial(self, l):
		serial = int( l[4].split('[')[1].split(']')[0] )
		return serial


	#------------------------------------------------------------------------------
	# Returns True if s matches the regex for ip pattern.
	#------------------------------------------------------------------------------
	def is_ip(self, s):
		return re.match("^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}"\
									"([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$", s)


	#------------------------------------------------------------------------------
	# Returns source ip or domain name.
	#------------------------------------------------------------------------------
	def get_src(self, l):
		ip = None
		domainname = None
		for m in range(0, len(l)):
			if l[m] == 'from':
				n = l[m+1]
				if self.is_ip( n ): 	ip = n
				else:						domainname = n
				break

		return (ip, domainname)


	#------------------------------------------------------------------------------
	# Returns a tuple for important fields.
	#
	# Fields in l are in the following order:
	#
	# month, day, time, host, serial, "Failed"|"Accepted", method,
	# "for"[, "invalid user"], user, "from", ip, "port", portnum, proto
	#------------------------------------------------------------------------------
	def get_fields(self, l):
		i = 5
		status = l[i]
		i += 1
		method = l[i]
		i += 2

		user_validity = None
		if l[i] == 'invalid':
			user_validity = 'invalid'
			i += 2

		user = l[i]
		if user != 'from':
			i += 4
		else:
			user = None
			i += 3

		port = int(l[i])
		i += 1
		protocol = l[i]

		return (status, method, user_validity, user, port, protocol)


	#------------------------------------------------------------------------------
	# Helper function to update db.
	#------------------------------------------------------------------------------
	def update_op_helper( self, aid, rid, dt, serial, status, \
											user_validity, username, src_port, ip, domainname, \
											method, protocol ):

		# Update "OpMeta" table
		sql = 'INSERT INTO `OpMeta` '\
				'(`rid`,`datetime`,`serial`,`status`,`user_validity`,'\
				'`aid`,`src_port`,`ip`,`domainname`) '\
				'VALUES (%d,\"%s\",%d,%s,%s,%d,%s,%s,%s)'\
				% ( rid, dt, serial, \
			 prep_ins_str( status ), \
			 prep_ins_str( user_validity ), \
			 aid, \
			 prep_ins_int( src_port ), \
			 prep_ins_str( ip ), \
			 prep_ins_str( domainname ) )
		omid = update_helper( self.conn, self.cur, sql )

		# Update "Operation" table
		sel_sql = 'SELECT `opid` FROM `Operation` WHERE `method`%s AND `protocol`%s'\
				% (prep_query_str(method), prep_query_str(protocol))
		ins_sql = 'INSERT INTO `Operation` (`method`,`protocol`) VALUES (%s,%s)'\
				% (prep_ins_str(method), prep_ins_str(protocol))
		opid = update_or_get_helper( self.conn, self.cur, sel_sql, ins_sql )

		# Update "ReqPerm" table, only for Accepted connections
		if status == 'Accepted':
			sql = 'INSERT OR IGNORE INTO `ReqPerm` (`rid`,`opid`,`aid`) VALUES (%s,%s,%s)'\
					% (prep_ins_int(rid), prep_ins_int(opid),	prep_ins_int(aid))
			update_helper( self.conn, self.cur, sql )


	#------------------------------------------------------------------------------
	# Updates database for l with format specifying "Accepted" or "Failed"
	# connection.
	#------------------------------------------------------------------------------
	def update_op(self, l, rid):
		(ip, domainname) = self.get_src( l )
		dt = self.get_datetime( l )
		serial = self.get_serial( l )
		(status, method, user_validity, user, port, protocol) = self.get_fields( l )

		principal = SshdPrincipal(self.conn, self.cur, user)
		self.update_op_helper( principal.aid, rid, dt, serial, status, \
									 user_validity, user, port, ip, domainname, method, protocol )


	#------------------------------------------------------------------------------
	# Fields in l are in the following order:
	# month, day, time, host, serial, "User", username, "from", domainname, "not",
	# "allowed', "because", "not", "listed", "in", "AllowUsers"
	#------------------------------------------------------------------------------
	def get_fields_unlisted(self, l):
		i = 6
		user = l[6]
		return (user)

	def update_op_unlisted(self, l, rid):
		(ip, domainname) = self.get_src( l )
		dt = self.get_datetime( l )
		serial = self.get_serial( l )

		(user) = self.get_fields_unlisted( l )

		principal = SshdPrincipal(self.conn, self.cur, user)
		self.update_op_helper( principal.aid, rid, dt, serial, None, \
									 "unlisted", user, None, ip, domainname, None, None )


#------------------------------------------------------------------------------
# Main
#------------------------------------------------------------------------------
if __name__ == '__main__':
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

	schema  = cfg.get('CONFIG', 'schema')
	log     = cfg.get('CONFIG', 'log')
	sshdcfg = cfg.get('CONFIG', 'sshdcfg')
	if cfg.get('CONFIG', 'reset') == 'yes':
		reset( db, schema )

	conn = sqlite3.connect(db)
	if conn == None:
		print 'Error connecting to %s.' % db
		sys.exit(0)
	print 'Connected to %s.' % db

	cur = conn.cursor()
	cur.execute( 'PRAGMA synchronous = OFF' )
	cur.execute( 'PRAGMA journal_mode = MEMORY' )
	cur.close()

	rsrc_meta = SshdResourceMeta(conn, rmid=None, hostname=cfg.get('CONFIG', 'hostname'))
	rsrc = SshdResource( conn, rsrc_meta, None )

	p1 = re.compile('.*sshd\[[0-9]*\]: (Accepted|Failed) .* for .* from .* port [0-9]* .*')
	p2 = re.compile('.*sshd\[[0-9]*\]: User .* from .* not allowed because not listed in AllowUsers')

	f = open(log, 'r')
	line = f.readline()
	while line:
		if p1.match(line) != None:
			l = line.split()
			update_op( conn, l, rsrc.rid )
		elif p2.match(line) != None:
			l = line.split()
			update_op_unlisted( conn, l, rsrc.rid )

		line = f.readline()

	f.close()
	conn.close()
