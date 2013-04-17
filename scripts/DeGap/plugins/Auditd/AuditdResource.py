import os
import sys

from plugins.Auditd.AuditdReqPerm import *
from Resource import *
from Config import *
from ConfigSpec import *

class AuditdResource(Resource):
	def __init__( self, conn, cur, rid=None, path=None, uid=None, gid=None, mode=None):
		self.conn = conn
		self.cur = cur
		self.path = path
		self.rid = rid
		self.uid = uid
		self.gid = gid
		self.mode = mode

		if rid == None or path == None or uid == None or gid == None or mode == None:
			sql = 'SELECT `rid`, `path`, `uid`, `gid`, `mode` FROM `Resource` WHERE '
			if self.rid is not None:
				sql += '`rid`=%d' % self.rid
			elif self.path is not None:
				sql += '`path`=\"%s\"' % self.path

			rows = fetchall(self.conn, self.cur, sql)
			if len(rows) != 0:
				#print str(rows)
				self.rid = rows[0][0]
				self.path = rows[0][1]
				self.uid = rows[0][2]
				self.gid = rows[0][3]
				self.mode = rows[0][4]

	#-----------------------------------------------------------------------------
	# Update resource info.
	#-----------------------------------------------------------------------------
	def update( self, tyid, fileext, uid, gid, mode ):
		self.uid = uid
		self.gid = gid
		self.mode = mode
		sql = 'UPDATE `Resource` SET tyid=%d, extension=\"%s\", '\
				'uid=%d, gid=%d, mode=%d WHERE `rid`=%d' \
				% (tyid, fileext, uid, gid, mode, self.rid)
		update_helper( self.conn, self.cur, sql )

	#-----------------------------------------------------------------------------
	# Helper function to update ConfigSpec and Config.
	#-----------------------------------------------------------------------------
	def load_configs_helper( self, key, value ):
		config_spec = ConfigSpec(self.conn, self.cur, csid=None, key=key, \
													ty='oneof', param='1|0', default='0')
		config = Config( self.conn, self.cur, cid=None, config_spec=config_spec, \
									value=value, new=False )
		self.update_config( config )

	#-----------------------------------------------------------------------------
	# Computes and updates Config, ConfigSpec.
	#
	# Note that we do not compute the granted permissions yet so that we can use
	# the transformer, which would be re-used when testing new configuration
	# values.
	#-----------------------------------------------------------------------------
	def load_configs( self ):
		# FOR SSHD, WE'LL HAVE TO SET DEFAULT VALUE FOR ALLOWUSERS TO THOSE IN
		# REQPERMS IF IT IS EMPY AND DEFAULT IS *

		# Delete old configurations.
		sql = 'DELETE FROM `Config` WHERE `cid` IN '\
				'(SELECT `cid` FROM `ResourceConfig` WHERE `rid`=%d)' % self.rid
		update_helper(self.conn, self.cur, sql)
		sql = 'DELETE FROM `ResourceConfig` WHERE `rid`=%d' % self.rid
		update_helper(self.conn, self.cur, sql)

		self.load_configs_helper( 'suid', '1' if (self.mode & 04000) != 0 else '0' )
		self.load_configs_helper( 'sgid', '1' if (self.mode & 02000) != 0 else '0' )
		self.load_configs_helper( 'rusr', '1' if (self.mode & 00400) != 0 else '0' )
		self.load_configs_helper( 'wusr', '1' if (self.mode & 00200) != 0 else '0' )
		self.load_configs_helper( 'xusr', '1' if (self.mode & 00100) != 0 else '0' )
		self.load_configs_helper( 'rgrp', '1' if (self.mode & 00040) != 0 else '0' )
		self.load_configs_helper( 'wgrp', '1' if (self.mode & 00020) != 0 else '0' )
		self.load_configs_helper( 'xgrp', '1' if (self.mode & 00010) != 0 else '0' )
		self.load_configs_helper( 'roth', '1' if (self.mode & 00004) != 0 else '0' )
		self.load_configs_helper( 'woth', '1' if (self.mode & 00002) != 0 else '0' )
		self.load_configs_helper( 'xoth', '1' if (self.mode & 00001) != 0 else '0' )

	#-----------------------------------------------------------------------------
	# Return permissions. The type of permissions, GrPerm, NewGrPerm, or ReqPerm
	# is determined by ty.
	#-----------------------------------------------------------------------------
	def get_perms( self, ty, opid=None ):
		use_opid = '' if opid == None else ' AND `opid`%s' % prep_query_int(opid)
		sql = 'SELECT `pid`, `opid`, `aid` FROM `%s` WHERE `rid`=%d%s' \
				% (ty, self.rid, use_opid)
		rows = fetchall(self.conn, self.cur, sql)
		return set([AuditdPermission(self.conn, self.cur, perm_id=r[0], \
															 rid=self.rid, opid=r[1], aid=r[2]) for r in rows])


	def __str__( self ):
		return '%s' % (self.path)


