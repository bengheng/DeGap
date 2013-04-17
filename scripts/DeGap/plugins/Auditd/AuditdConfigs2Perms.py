import sys

from Config import *
from Common import *
from plugins.Auditd.AuditdPermission import *
from plugins.Auditd.AuditdPrincipal import *
from plugins.Auditd.AuditdOperation import *

class AuditdConfigs2Perms:
	def __init__(self, conn, cur):
		self.conn = conn
		self.cur = cur

	#-----------------------------------------------------------------------------
	# Updates granted principals for operation.
	#-----------------------------------------------------------------------------
	def map_configs_to_perms( self, rsrc, configs ):
		print '.'*30 + ' Mapping configs to perms '+'.'*30
		print 'Using config\n' + '\n'.join(str(configs[c]) for c in configs)
		grperms = set()

		usr = set( [AuditdPrincipal(self.conn, self.cur, uid=rsrc.uid, gid=None)] )
		grp = set( [AuditdPrincipal(self.conn, self.cur, uid=None, gid=rsrc.gid)] )
		# This loop is a generalization. In the general case, we'll
		# need to identify the type of configuration and compute
		# the actors accordingly.
		#
		# Possible operation labels are:
		# rusr, wusr, xusr, rgrp, wgrp, xgrp,
		# roth, woth, xoth, suid, sgid
		for c in configs:
			opids = []
			sql = 'SELECT `opid` FROM `Operation` '\
					'WHERE `Operation`.`label`=\"%s\"'\
					% (configs[c].config_spec.key)
			rows = fetchall(self.conn, self.cur, sql)
			if len(rows) == 0:
				# There are no requested operations for this config key. We'll
				# add a dummy one.
				operation = AuditdOperation( self.conn, self.cur, opid=None, \
																label=configs[c].config_spec.key)
				opids.append( operation.opid )
			else:
				opids.extend( [int(r[0]) for r in rows] )

			usrty = configs[c].config_spec.key[1:]
			for opid in opids:
				if usrty == 'usr' or usrty == 'uid' or usrty == 'gid':
					if configs[c].value == '1':
						#print 'Update usr'
						#print '1A grperms\n' + '\n'.join(str(p) for p in grperms)
						perms = set([AuditdPermission(self.conn, self.cur, perm_id=None, \
															rid=rsrc.rid, opid=opid, \
															aid=p.aid) for p in usr] )
						#print '1A perms\n' + '\n'.join(str(p) for p in perms)
						grperms.update( perms )
						#print '1B grperms\n' + '\n'.join(str(p) for p in grperms)

				elif usrty == 'grp':
					if configs[c].value == '1':
						#print 'Update grp'
						grperms.update( set([AuditdPermission(self.conn, self.cur, perm_id=None, \
																			 rid=rsrc.rid, opid=opid, \
																			 aid=p.aid) for p in grp] ) )
				elif usrty == 'oth':
					if configs[c].value == '1':
						#print 'Update oth'
						# Since we can't feasibly express all other principals,
						# we will use the projection from requested principals.
						reqperms = set()
						reqperms.update( rsrc.get_perms( 'ReqPerm', opid=opid ) )
						#print '### reqperms ###\n' + '\n'.join(str(r) for r in reqperms)
						oth = set( [AuditdPrincipal(self.conn, self.cur, aid=r.aid) for r in reqperms] )
						oth = (oth - usr) - grp
						grperms.update( set([AuditdPermission(self.conn, self.cur, perm_id=None, \
																			 rid=rsrc.rid, opid=opid, \
																			 aid=p.aid) for p in oth] ) )
				else:
					assert False

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

