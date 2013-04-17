from plugins.Sshd.SshdPermission import *
from plugins.Sshd.SshdPrincipal import *

class SshdConfigs2Perms:

	def __init__(self, conn, cur):
		self.conn = conn
		self.cur = cur
	
	#-----------------------------------------------------------------------------
	# Helper function to get users.
	#-----------------------------------------------------------------------------
	def get_users_helper(self, configs, usrty):
		users = set()
		if usrty in configs:
			c = configs[usrty]
			if c is not None:
				usrs = c.get_value()
				if usrs != None:
					u = set(usrs.split('|'))
					users.update(u)
		return users

	#-----------------------------------------------------------------------------
	# Get set of denied users.
	#-----------------------------------------------------------------------------
	def get_deny_users(self, configs):
		return self.get_users_helper(configs, 'DenyUsers')


	#-----------------------------------------------------------------------------
	# Get set of allowed principals, also taking into account the denied users.
	#-----------------------------------------------------------------------------
	def get_allow_principals(self, rsrc, configs):
		deny_users = self.get_deny_users(configs)
		allow_users = self.get_users_helper(configs, 'AllowUsers')

		# If allow_users is empty, project from requested users.
		if len(allow_users) == 0:
			sql = 'SELECT `user` FROM `ReqPerm` '\
					'INNER JOIN `Principal` ON `Principal`.`aid`=`ReqPerm`.`aid` '\
					'INNER JOIN `Resource` ON `Resource`.`rid`=`ReqPerm`.`rid` '\
					'WHERE `Resource`.`rid`=%d' % rsrc.rid
			cur = self.cur if self.conn == None else self.conn.cursor()
			cur.execute(sql)
			row = cur.fetchone()
			while row != None:
				allow_users.add(row[0])
				row = cur.fetchone()

		# Root cannot be explicitly denied.
		if 'root' in allow_users:
			if 'PermitRootLogin' in configs:
				c = configs['PermitRootLogin']
				if c != None and c.value == 'no':
					allow_users.remove('root')

		# Remove denied users
		for d in deny_users:
			if d in allow_users:
				allow_users.remove(d)

		allow_principals = set( [SshdPrincipal(self.conn, self.cur, a) for a in allow_users] )
		return allow_principals


	def get_opid(self, method, proto):
		sel_sql = 'SELECT `opid` FROM `Operation` '\
				'WHERE `method`%s AND `protocol`%s'\
				% (prep_query_str(method), prep_query_str(proto))
		ins_sql = 'INSERT INTO `Operation` (`method`, `protocol`) '\
				'VALUES (%s,%s)'\
				% (prep_ins_str(method), prep_ins_str(proto))
		opid = update_or_get_helper(self.conn, self.cur, sel_sql, ins_sql)
		return opid

	#-----------------------------------------------------------------------------
	# Updates granted principals for operation.
	#-----------------------------------------------------------------------------
	def map_configs_to_perms( self, rsrc, configs ):
		print '.'*30 + ' Mapping configs to perms '+'.'*30
		print '[Configs]\n' + '\n'.join(str(configs[c]) for c in configs)
		grperms = set()

		allow_principals = self.get_allow_principals(rsrc, configs)

		# Get supported protocols
		protocols = set()
		if 'Protocol' in configs:
			protocols.update(set(['ssh'+p for p in configs['Protocol'].value.split(',')]))

		# Get value for PermitRootLogin
		prlv = None
		if 'PermitRootLogin' in configs:
			if configs['PermitRootLogin'].value == None:
				prlv = configs['PermitRootLogin'].config_spec.default
			else:
				prlv = configs['PermitRootLogin'].value

		# For each protocol...
		for proto in protocols:
			# Handle PubkeyAuthentication
			if 'PubkeyAuthentication' in configs:
				c = configs['PubkeyAuthentication']
				val = c.value if c.value != None else c.config_spec.default
				if val == 'yes':
					opid = self.get_opid('publickey', proto)
					for p in allow_principals:
						# Skip disallowed root
						if p.user == 'root':
							if prlv == None or (prlv != 'yes' and prlv != 'without-password'):
								continue
						grperms.add(SshdPermission(self.conn, self.cur, perm_id=None, \
																rid = rsrc.rid, opid=opid, \
																aid = p.aid))

			# Handle PasswordAuthentication
			if 'PasswordAuthentication' in configs:
				c = configs['PasswordAuthentication']
				val = c.value if c.value != None else c.config_spec.default
				if val == 'yes':
					opid = self.get_opid('password', proto)
					for p in allow_principals:
						# Skip disallowed root
						if p.user == 'root':
							if prlv == None or (prlv != 'yes'):
								continue
						grperms.add(SshdPermission(self.conn, self.cur, perm_id=None, \
																 rid = rsrc.rid, opid=opid, \
																 aid = p.aid))

			# Handle UsePAM (assumed to be similar to PasswordAuthentication)
			if 'UsePAM' in configs:
				c = configs['UsePAM']
				val = c.value if c.value != None else c.config_spec.default
				if val == 'yes':
					opid = self.get_opid('password', proto)
					for p in allow_principals:
						# Skip disallowed root
						if p.user == 'root':
							if prlv == None or (prlv != 'yes'):
								continue
						grperms.add(SshdPermission(self.conn, self.cur, perm_id=None, \
																 rid = rsrc.rid, opid=opid, \
																 aid = p.aid))

		#print 'grperms\n' + '\n'.join(str(p) for p in grperms)
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

