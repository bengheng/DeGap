import types
import copy
import os
import sys
sys.path.append(os.path.realpath(os.path.join(sys.path[0], '../../')))

from Degap.GrOpMeta import *
from SshdOpLabel import *
from SshdCommon import *
from SshdActor import *

class SshdGrOpMeta(GrOpMeta):
	def __init__( self, conn, cur ):
		self.conn = conn
		self.cur = cur

	#-----------------------------------------------------------------------------
	# Overrides parent's function to return only accepted request actors.
	#-----------------------------------------------------------------------------
	def get_request_actors( self, rsrc, olid=None):
		sql = 'SELECT `ReqOpActor`.`aid` FROM `ReqOpActor` '\
				'INNER JOIN `ReqOp` ON (`ReqOp`.`roid`=`ReqOpActor`.`roid`) '\
				'INNER JOIN `ReqOpMeta` ON (`ReqOpMeta`.`roid`=`ReqOp`.`roid`) '\
				'WHERE `ReqOp`.`rid`=%d AND `ReqOp`.`olid`=%d '\
				'AND `ReqOpMeta`.`status`="Accepted"'	% (rsrc.rid, olid)
		print sql
		rows = fetchall(self.conn, self.cur, sql)
		print str(rows)
		return set([SshdActor(self.conn, self.cur, user=None, aid=r[0]) for r in rows])

	#-----------------------------------------------------------------------------
	# Retrieves the granted/denied actors from DB.
	# Note: Can't put in GrOpMeta because of SshdActor. :(
	#-----------------------------------------------------------------------------
	def get_granted_actors_for_op( self, goid, shadow ):
		t = 'GrOpActor' if shadow == False else 'GrOpActorShadow'
		sql = 'SELECT `aid` FROM `%s` WHERE `goid`=%d' % (t, goid)
		rows = fetchall( self.conn, self.cur, sql )
		gr_actors = set( [ SshdActor(self.conn, self.cur, None, r[0]) for r in rows ] )

		t = 'DenyOpActor' if shadow == False else 'DenyOpActorShadow'
		sql = 'SELECT `aid` FROM `%s` WHERE `goid`=%d' % (t, goid)
		rows = fetchall( self.conn, self.cur, sql )
		dn_actors = set( [ SshdActor(self.conn, self.cur, None, r[0]) for r in rows ] )

		return (gr_actors, dn_actors)


	#-----------------------------------------------------------------------------
	# Updates a list of configurations for the specific operation.
	#-----------------------------------------------------------------------------
	def update_configs(self, configs, rsrc, method, protocol, keys, shadow=False):
		oplabel = SshdOpLabel(self.conn, self.cur, method, protocol)
		goid = self.update_gr_op( rsrc.rid, oplabel.olid )
		for k in keys:
			if k not in configs:
				continue
			configs[k].update_meta(goid, shadow)


	#-----------------------------------------------------------------------------
	# Updates configurations and operation labels.
	#-----------------------------------------------------------------------------
	def update_permission( self, configs, rsrc, shadow=False ):
		print '### Updating Permission ###'
		print '\n'.join([str(configs[c]) for c in configs])

		keys = ['PermitRootLogin', 'AllowUsers', 'DenyUsers', 'Protocol']

		protocol = None
		if 'Protocol' in configs and configs['Protocol'].value == '2':
			protocol = 'ssh2'

		#print '--- publickey ---'
		if 'PubkeyAuthentication' in configs and configs['PubkeyAuthentication'].value == 'yes':
			keys2 = []
			keys2.extend(keys)
			keys2.append('PubkeyAuthentication')
			self.update_configs( configs, rsrc, 'publickey', protocol, keys2, shadow )

		#print '--- password ---'
		if 'UsePAM' in configs and configs['UsePAM'].value == 'yes' or\
		 'PasswordAuthentication' in configs and configs['PasswordAuthentication'].value == 'yes':
			keys3 = []
			keys3.extend(keys)
			keys3.extend(['UsePAM', 'PasswordAuthentication'])
			self.update_configs( configs, rsrc, 'password', protocol, keys3, shadow )


	#-----------------------------------------------------------------------------
	# Returns True if the operation is allowed, i.e. both method and protocol
	# must be sastisfied.
	#-----------------------------------------------------------------------------
	def is_operation_allowed( self, configs, method, protocol ):
		if ('PubkeyAuthentication' in configs and configs['PubkeyAuthentication'].value == 'no')\
		 and method == 'publickey':
			return False

		if (('UsePAM' in configs and configs['UsePAM'].value == 'no') \
			and ('PasswordAuthentication' in configs and configs['PasswordAuthentication'].value == 'no')) \
		 and method == 'password':
			return False

		assert 'Protocol' in configs
		protocols = configs['Protocol'].value.split(',')
		if '2' not in protocols and protocol == 'ssh2':
			return False

		return True


	#-----------------------------------------------------------------------------
	# Returns True if root is allowed.
	#-----------------------------------------------------------------------------
	def is_root_allowed( self, goid, configs, method ):
		'''
		PermitRootLogin:
		Specifies whether root can log in using ssh(1).  The argument
		must be "yes", "without-password", "forced-commands-only" or
		"no".  The default is "yes".
		
		If this option is set to "without-password" password authentica-
		tion is disabled for root.
		
		If this option is set to "forced-commands-only" root login with
		public key authentication will be allowed, but only if the
		command option has been specified (which may be useful for taking
		remote backups even if root login is normally not allowed).  All
		other authentication methods are disabled for root.
		
		If this option is set to "no" root is not allowed to log in.
		'''

		# Look at all overriding factors that will definitely cause root
		# to be denied.
		# (We really need a way to automatically generate this model.)


		if 'DenyUsers' in configs:
			if 'root' in configs['DenyUsers'].value:
				return False

		# Root also needs to be in the AllowUsers field.
		if 'AllowUsers' in configs:
			if configs['PermitRootLogin'].value != 'no' \
			and 'root' not in configs['AllowUsers'].value:
				return False


		# Now look at other options.
		v = configs['PermitRootLogin'].value

		if v == 'yes':
			return True
		elif v == 'no':
			return False
		elif v == 'without-password':
			# Disallow if method is 'password'
			if method == 'password':
				return False
			else:
				return True
		elif v == 'forced-commands-only':
			# The command option is specified in ~/.ssh/authorized_keys. See:
			# http://binblog.info/2008/10/20/openssh-going-flexible-with-forced-commands/
			# 
			# But for now, we'll just assume if method is publickey, root is dis-allowed,
			# implying that root needs more than forced-commands-only.
			return False
			#if method == 'publickey':
			#	return True
			#else:
			#	return False


	#-----------------------------------------------------------------------------
	# Updates granted/denied actors for operation identified by goid.
	#-----------------------------------------------------------------------------
	def map_configs_to_actors( self, rsrc, grop, configs, req_actors ):
		goid = grop[0]
		olid = grop[1]
		method = grop[2]
		protocol = grop[3]

		gr_actors = set()
		dn_actors = set()

		print '### goid %d config ###\n%s' \
			% (goid, '\n'.join( str(configs[c]) for c in configs))
		print '-------'

		# 'DenyUsers' overrides all other options, so we compute them first,
		# regardless of the outcome of other scenarios.
		if 'DenyUsers' in configs:
			users = configs['DenyUsers'].value
			dn_actors.update( set([SshdActor(self.conn, self.cur, u) for u in users]) )

		if self.is_operation_allowed( configs, method, protocol ) == False:
			# Further deny all requested actors. 
			dn_actors.update( req_actors )
			return (True, gr_actors, dn_actors)
		print 'RETURN gr_actors: ' + ','.join(str(a) for a in gr_actors)

		# Is root allowed?
		if self.is_root_allowed( goid, configs, method ) == True:
			gr_actors.add(SshdActor(self.conn, self.cur, 'root'))

		# Now the allowed users.
		if 'AllowUsers' in configs:
			users = copy.copy(configs['AllowUsers'].value)

			# If there are no users, and AllowUsers's default value is *, we use
			# the requested users.
			if len(users) == 0 and configs['AllowUsers'].default == '*':
				gr_actors.update( req_actors )
			else:
				# We handled root separately
				if 'root' in users: users.remove('root')
				gr_actors.update( [SshdActor(self.conn, self.cur, u) for u in users] )
		else:
			# If AllowUsers is not specified, it means all users will be allowed. But
			# since we cannot express all users, we use the set of users who successfully
			# connected.

			gr_actors.update( req_actors )

		return (False, gr_actors, dn_actors)


