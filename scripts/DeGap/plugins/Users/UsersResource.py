from Common import *
from Config import *
from Resource import *
from plugins.Users.passwd import *
from plugins.Users.UsersPermission import *

class UsersResource(Resource):
	def __init__(self, conn, cur, rid=None, hostname=None):
		self.conn = conn
		self.cur = cur
		self.rid = rid
		self.hostname = hostname
		self.update()

	def update(self):
		if self.hostname != None:
			sel_sql = 'SELECT `rid` FROM `Resource` WHERE `hostname`=\"%s\"' % self.hostname
			ins_sql = 'INSERT INTO `Resource` (`hostname`) VALUES (\"%s\")' % self.hostname
			self.rid = update_or_get_helper( self.conn, self.cur, sel_sql, ins_sql )
		elif self.rid != None:
			sql = 'SELECT `hostname` FROM `Resource` WHERE `rid`=%d' % self.rid
			cur = self.cur if self.conn == None else self.conn.cursor()
			cur.execute(sql)
			self.hostname = cur.fetchone()[0]
			if self.conn != None:
				cur.close()

	#------------------------------------------------------------------------------
	# Loads sshd configuration file.
	#------------------------------------------------------------------------------
	'''
	def load_config_passwd(self, passwd):
		p = loadpw( passwd )
		for k in p.keys():
			for j in p[k]:
				cs = ConfigSpec( self.conn, self.cur, csid=None, key='p-%d' % j.uid, \
										ty='allof', param=None, default=None )
				cf = Config( self.conn, self.cur, cid=None, config_spec=cs, \
								 value='%d' % j.gid, new=False )
				self.update_config( cf )
		return p


	def load_config_group(self, group, pwds):
		g = loadgrp( group )
		for k in g.keys():
			cs = ConfigSpec( self.conn, self.cur, csid=None, key='g-%d' % g[k].gid, \
									ty='allof', param=None, default=None )
			value = None
			if len(g[k].users) != 0:
				value = '|'.join( [str(pwds[u].uid) for u in g[k].users if u != ''] )
			cf = Config( self.conn, self.cur, cid=None, config_spec=cs, \
							 value=value, new=False )
			self.update_config( cf )
	'''

	def load_config_passwd(self, p):
		uids = set()
		for k in p.keys():
			uids.update( set([j.uid for j in p[k]]) )
		v = '|'.join([str(h) for h in uids])
		cs = ConfigSpec( self.conn, self.cur, csid=None, key='passwd', \
									ty='set', param=None, default=None )
		cf = Config( self.conn, self.cur, cid=None, config_spec=cs, \
							value=v, new=False )
		self.update_config( cf )
		return p


	def load_config_group(self, p, g):
		gids = set()
		for k in p.keys():
			gids.update( set([j.gid for j in p[k]]) )
		for k in g.keys():
			gids.update( set([j.gid for j in g[k]]) )
		v = '|'.join([str(h) for h in gids])
		cs = ConfigSpec( self.conn, self.cur, csid=None, key='group', \
									ty='set', param=None, default=None )
		cf = Config( self.conn, self.cur, cid=None, config_spec=cs, \
							value=v, new=False )
		self.update_config( cf )


	def load_config(self, configs):
		p = loadpw( configs['passwd'] )
		g = loadgrp( configs['group'] )

		self.load_config_passwd( p )
		self.load_config_group( p, g )

	#-----------------------------------------------------------------------------
	# Return permissions. The type of permissions, GrPerm, NewGrPerm, or ReqPerm
	# is determined by ty.
	#-----------------------------------------------------------------------------
	def get_perms( self, ty ):
		sql = 'SELECT `pid`, `opid`, `aid` FROM `%s` WHERE `rid`=%d' % (ty, self.rid)
		rows = fetchall(self.conn, self.cur, sql)
		return set([UsersPermission(self.conn, self.cur, perm_id=r[0], \
												 rid=self.rid, opid=r[1], aid=r[2]) for r in rows])

