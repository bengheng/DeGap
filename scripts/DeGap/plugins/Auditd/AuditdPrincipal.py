import os
import sys
from Common import *

class AuditdPrincipal:

	def __init__( self, conn, cur, uid=None, gid=None, aid=None ):
		self.conn = conn
		self.cur = cur
		self.aid = aid
		self.uid = uid
		self.gid = gid
		self.update()

	#-----------------------------------------------------------------------------
	# Update Principal table.
	#-----------------------------------------------------------------------------
	def update( self ):
		if self.aid == None:
			sel_sql = 'SELECT `aid` FROM `Principal` WHERE `uid`%s AND `gid`%s'\
					% (prep_query_int(self.uid), prep_query_int(self.gid))
			ins_sql = 'INSERT INTO `Principal` (`uid`, `gid`) VALUES (%s, %s)'\
					% (prep_ins_int(self.uid), prep_ins_int(self.gid))
			self.aid = update_or_get_helper( self.conn, self.cur, sel_sql, ins_sql )

		else:
			sql = 'SELECT `uid`, `gid` FROM `Principal` WHERE `aid`=%d' % self.aid
			r = fetchall( self.conn, self.cur, sql )
			assert len(r) == 1
			self.uid = r[0][0]
			self.gid = r[0][1]


	def __str__( self ):
		return '(aid=%d uid=%s gid=%s)' % (self.aid, str(self.uid), str(self.gid))

	def __eq__( self, Principal ):
		return self.aid is not None and self.aid == Principal.aid

	def __hash__( self ):
		return self.aid
