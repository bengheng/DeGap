import os
import sys

from Common import *

class AuditdType:
	def __init__( self, conn, cur, path, filetype ):
		self.conn = conn
		self.cur = cur
		self.filetype = filetype
		self.tyid = self.update_type()

	'''
	Update type.
	'''
	def update_type( self ):
		sel_sql = 'SELECT `tyid` FROM `type` WHERE `description`=\"%s\"' % self.filetype
		ins_sql = 'INSERT INTO `type` (`description`) VALUES (\"%s\")' % self.filetype
		tyid = update_or_get_helper( self.conn, self.cur, sel_sql, ins_sql )
		return tyid

	def get_tyid( self ):
		return self.tyid

	def __str__( self ):
		return self.filetype

	def __eq__( self, auditd_type ):
		return self.tyid == auditd_type.tyid
