from Permission import *

class AuditdPermission(Permission):
	def __str__(self):
		sql = 'SELECT `path` FROM `Resource` WHERE `rid`=%d' % self.rid
		rows = fetchall(self.conn, self.cur, sql)
		path = rows[0][0]

		sql = 'SELECT `label` FROM `Operation` WHERE `opid`=%d' % self.opid
		rows = fetchall(self.conn, self.cur, sql)
		label = rows[0][0]

		sql = 'SELECT `uid`, `gid` FROM `Principal` WHERE `aid`=%d' % self.aid
		rows = fetchall(self.conn, self.cur, sql)
		uid = str(rows[0][0])
		gid = str(rows[0][1])

		#return '%d:%s:%d:%d:%d: %s, %s, %s, %s' \
		#		% (self.perm_id, self.ty, self.rid, self.opid, self.aid, \
		#	 path, label, uid, gid)
		return '(%d, %d, %d) %s, %s, %s, %s' \
				% (self.rid, self.opid, self.aid, \
			 path, label, uid, gid)

