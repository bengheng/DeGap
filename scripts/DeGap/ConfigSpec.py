
from Common import *

class ConfigSpec:
	def __init__(self, conn, cur, csid=None, \
							key=None, ty=None, param=None,	default=None):
		self.conn = conn
		self.cur = cur
		self.csid = csid
		self.key = key
		self.ty = ty
		self.param = param
		self.default = default
		self.update()

	def update(self):
		if self.csid == None:
			assert self.key != None
			sel_sql = 'SELECT `csid` FROM `ConfigSpec` WHERE `key`=\"%s\"' \
					% (self.key)
			upd_sql = 'UPDATE `ConfigSpec` SET `type`=%s, `param`=%s, `default`=%s '\
					'WHERE `key`=\"%s\"' \
					% (prep_ins_str(self.ty), \
				prep_ins_str(self.param), \
				prep_ins_str(self.default), \
				self.key)
			ins_sql = 'INSERT INTO `ConfigSpec` (`key`,`type`,`param`, `default`) ' \
					'VALUES (\"%s\",%s,%s,%s)'	\
					% (self.key, \
				prep_ins_str(self.ty), \
				prep_ins_str(self.param), \
				prep_ins_str(self.default) )
			self.csid = update_or_get_helper( self.conn, self.cur, sel_sql, ins_sql, upd_sql )
		elif self.key == None:
			assert self.csid != None
			sel_sql = 'SELECT `key`, `type`, `param`, `default` '\
					'FROM `ConfigSpec` WHERE csid=%d' % (self.csid)
			rows = fetchall( self.conn, self.cur, sel_sql )
			self.key = rows[0][0]
			self.ty = rows[0][1]
			self.param = rows[0][2]
			self.default = rows[0][3]

