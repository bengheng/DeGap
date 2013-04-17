from Permission import *

class SshdPermission(Permission):
	def __str__(self):
		sql = 'SELECT `hostname` FROM `Resource` WHERE `rid`=%d' % self.rid
		rows = fetchall(self.conn, self.cur, sql)
		hostname = rows[0][0]

		sql = 'SELECT `method`, `protocol` FROM `Operation` WHERE `opid`=%d' % self.opid
		rows = fetchall(self.conn, self.cur, sql)
		method = rows[0][0]
		protocol = rows[0][1]

		sql = 'SELECT `user` FROM `Principal` WHERE `aid`=%d' % self.aid
		rows = fetchall(self.conn, self.cur, sql)
		user = rows[0][0]

		#return '%d:%s:%d:%d:%d: %s, %s, %s, %s' \
		#		% (self.perm_id, self.ty, self.rid, self.opid, self.aid, \
		#	 hostname, method, protocol, user)
		return '(%d, %d, %d) %s, %s, %s, %s' \
				% (self.rid, self.opid, self.aid, \
			 hostname, method, protocol, user)
