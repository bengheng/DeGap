from Common import *
from plugins.Users.UsersPermission import *

class UsersConfigs2Perms:

	def __init__(self, conn, cur):
		self.conn = conn
		self.cur = cur

	def get_opid(self):
		sel_sql = 'SELECT `opid` FROM `Operation` WHERE `label`="access"'
		ins_sql = 'INSERT INTO `Operation` (`label`) VALUES ("access")'
		opid = update_or_get_helper(self.conn, self.cur, sel_sql, ins_sql)
		return opid

	#-----------------------------------------------------------------------------
	# Updates granted principals for operation.
	#-----------------------------------------------------------------------------
	def map_configs_to_perms( self, rsrc, configs ):
		print '.'*30 + ' Mapping configs to perms '+'.'*30
		print '[Configs]\n' + '\n'.join(str(configs[c]) for c in configs)
		grperms = set()

		opid = self.get_opid()

		for c in configs:
			if  c == 'passwd':
				for i in configs[c].value:
					sel_sql = 'SELECT `aid` FROM `Principal` WHERE `uid`=%s AND `gid` IS NULL' % i
					ins_sql = 'INSERT INTO `Principal` (`uid`, `gid`) VALUES (%s,NULL)' % i
					aid = update_or_get_helper(self.conn, self.cur, sel_sql, ins_sql)
					grperms.add( UsersPermission( self.conn, self.cur, perm_id=None, \
																	rid=rsrc.rid, opid=opid, aid=aid) )
			elif c == 'group':
				for i in configs[c].value:
					sel_sql = 'SELECT `aid` FROM `Principal` WHERE `uid` IS NULL AND `gid`=%s' % i
					ins_sql = 'INSERT INTO `Principal` (`uid`, `gid`) VALUES (NULL,%s)' % i
					aid = update_or_get_helper(self.conn, self.cur, sel_sql, ins_sql)
					grperms.add( UsersPermission( self.conn, self.cur, perm_id=None, \
																	rid=rsrc.rid, opid=opid, aid=aid) )
		print '......................................................................'
		return grperms

	#-----------------------------------------------------------------------------
	# Computes granted/new granted permissions for resource and operation.
	#-----------------------------------------------------------------------------
	def compute_grperms( self, rsrc, new=False ):
		print '### compute_grperms ###'
		configs = rsrc.get_configs( new )
		print '\n'.join([str(configs[c]) for c in configs])
	
		ty = 'GrPerm' if new == False else 'NewGrPerm'
		grperms = self.map_configs_to_perms( rsrc, configs )
		for p in grperms:
			p.commit(ty)

		print '### %s ###' % ty
		print '\n'.join( str(p) for p in grperms )
		print '###########################'
