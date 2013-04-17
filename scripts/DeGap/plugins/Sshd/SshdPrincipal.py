import os
import sys
from Common import *

class SshdPrincipal:

	def __init__( self, conn, cur, user=None, aid=None ):
		self.conn = conn
		self.cur = cur
		self.aid = aid
		self.user = user
		self.update()


	'''
	Update Principal table.
	'''
	def update( self ):
		if self.aid == None:
			sel_sql = 'SELECT `aid` FROM `Principal` WHERE `user`%s'\
					% (prep_query_str(self.user))
			ins_sql = 'INSERT INTO `Principal` (`user`) VALUES (%s)'\
					% (prep_ins_str(self.user))
			self.aid = update_or_get_helper( self.conn, self.cur, sel_sql, ins_sql )

		else:
			sql = 'SELECT `user` FROM `Principal` WHERE `aid`=%d' % self.aid
			r = fetchall( self.conn, self.cur, sql )
			assert len(r) == 1
			self.user = r[0][0]


	def __str__( self ):
		return '(aid=%d user=%s)' % (self.aid, self.user)

	def __eq__( self, Principal ):
		if Principal == None:
			return False

		return self.aid is not None and self.aid == Principal.aid

	def __hash__( self ):
		return self.aid
