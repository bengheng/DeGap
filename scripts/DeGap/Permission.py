from Common import *

class Permission:
	perm_types = ['ReqPerm', 'GrPerm', 'NewGrPerm']

	def __init__(self, conn, cur, perm_id=None, rid=None, opid=None, aid=None):
		self.conn = conn
		self.cur = cur
		self.perm_id = perm_id
		self.rid = rid
		self.opid = opid
		self.aid = aid
		#self.update()


	def commit(self, ty):
		assert ty in self.perm_types

		if self.perm_id == None and self.rid != None \
		 and self.opid != None and self.aid != None:
			# Insert rid, opid, and aid into DB
			sel_sql = 'SELECT `pid` FROM `%s` '\
					'WHERE `rid`=%d AND `opid`=%d AND `aid`=%d' \
					% (ty, self.rid, self.opid, self.aid)
			ins_sql = 'INSERT OR IGNORE INTO `%s` (`rid`, `opid`, `aid`) '\
					'VALUES (%d,%d,%d)' % (ty, self.rid, self.opid, self.aid)
			self.perm_id = update_or_get_helper( self.conn, self.cur, sel_sql, ins_sql )


	def __eq__(self, other):
		return self.rid == other.rid \
				and self.opid == other.opid \
				and self.aid == other.aid

	def __hash__(self):
		return hash('%d|%d|%d' % (self.rid, self.opid, self.aid) )



