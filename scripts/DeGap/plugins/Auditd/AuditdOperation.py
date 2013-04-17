import os
import sys
from Common import *

class AuditdOperation:
	def __init__( self, conn, cur, opid=None, label=None ):
		self.conn = conn
		self.cur = cur
		self.opid = opid
		self.label = label
		self.update()

	#------------------------------------------------------------------------------
	# Update Operation table.
	#------------------------------------------------------------------------------
	def update( self ):
		if self.opid == None:
			sel_sql = 'SELECT `opid` FROM `Operation` '\
					'WHERE `label`=\"%s\"' % (self.label)
			ins_sql = 'INSERT INTO `Operation` (`label`) '\
					'VALUES (\"%s\")' % (self.label)
			self.opid = update_or_get_helper( self.conn, self.cur, sel_sql, ins_sql )
		else:
			sel_sql = 'SELECT `label` FROM `Operation` WHERE `opid`=%d' % self.opid
			rows = fetchall(self.conn, self.cur, sel_sql)
			self.label = rows[0][0]
