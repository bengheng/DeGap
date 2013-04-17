from Permission import *

class UsersPermission(Permission):
	def __str__(self):
		sql = 'SELECT `hostname` FROM `Resource` WHERE `rid`=%d' % self.rid
		rows = fetchall(self.conn, self.cur, sql)
		hostname = rows[0][0]

		sql = 'SELECT `label` FROM `Operation` WHERE `opid`=%d' % self.opid
		rows = fetchall(self.conn, self.cur, sql)
		label = rows[0][0]

		sql = 'SELECT `Principal`.`uid`, `Principal`.`gid` '\
				'FROM `Principal` '\
				'WHERE `Principal`.`aid`=%d' % self.aid
		rows = fetchall(self.conn, self.cur, sql)
		uid = str(rows[0][0])
		gid = str(rows[0][1])

		uname = 'None'
		if uid != 'None':
			sql = 'SELECT `name` FROM `user_name` WHERE `uid`=%s' % uid
			rows = fetchall(self.conn, self.cur, sql)
			uname = '!'.join( [str(r[0]) for r in rows] )

		gname = 'None'
		if gid != 'None':
			sql = 'SELECT `name` FROM `group_name` WHERE `gid`=%s' % gid
			rows = fetchall(self.conn, self.cur, sql)
			gname = '!'.join( [str(r[0]) for r in rows] )

		return '(%d, %d, %d) %s, %s, %s (%s), %s (%s)' \
				% (self.rid, self.opid, self.aid, \
			 hostname, label, uid, uname, gid, gname)
