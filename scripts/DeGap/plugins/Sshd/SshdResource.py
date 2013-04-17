import os
import sys

from Common import *
from Config import *
from Resource import *
from plugins.Sshd.SshdPermission import *


class SshdResource(Resource):
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
	# Loads sshd config specifications from cfg.
	# Each value of a config key is a tuple (type, param, default, values).
	#------------------------------------------------------------------------------
	def load_config_specs(self, cfg_parser):
		specs = dict()
		if not cfg_parser.has_section('CONFIGAUX'):
			return specs

		for c in cfg_parser.options('CONFIGAUX'):
			values = cfg_parser.get('CONFIGAUX', c).split('#')
			ty = None
			param = None
			default = None
			# Is there a better way to do this?
			if len(values) >= 1 and values[0] != '': ty = values[0]
			if len(values) >= 2 and values[1] != '': param = values[1]
			if len(values) >= 3 and values[2] != '': default = values[2]

			specs[c] = ConfigSpec(self.conn, self.cur, csid=None, key=c, \
											 ty=ty, param=param, default=default)

		return specs


	def has_config(self, configspec, value, new=False):
		valfield = '`value`' if new == False else '`value_shadow`'

		sql = 'SELECT COUNT(*) '\
				'FROM `ResourceConfig` '\
				'INNER JOIN `Config` ON `Config`.`cid` = `ResourceConfig`.`cid` '\
				'INNER JOIN `ConfigSpec` ON `ConfigSpec`.`csid` = `Config`.`csid` '\
				'WHERE `rid`%s '\
				'AND %s%s '\
				'AND `key`%s '\
				'AND `type`%s '\
				'AND `param`%s '\
				'AND `default`%s'\
				% (prep_query_int(self.rid), valfield, \
			 prep_query_str(value), \
			 prep_query_str(configspec.key), \
			 prep_query_str(configspec.ty), \
			 prep_query_str(configspec.param), \
			 prep_query_str(configspec.default))

		cur = self.cur if self.conn == None else self.conn.cursor()
		cur.execute(sql)
		r = cur.fetchone()
		if r[0] != 0:
			return True
		return False


	#------------------------------------------------------------------------------
	# Loads sshd configuration file.
	#------------------------------------------------------------------------------
	def load_config(self, configs, cfg_parser):
		specs = self.load_config_specs(cfg_parser)

		f = open( configs['sshdcfg'], 'r' )
		l = f.readline()
		while l:
			if len(l) != 0 and l[0] != '#' and l[0] != '\n':
				m = l.split()
				key = m[0]

				# We'll ignore configs not specified in config.ini.
				if key in specs:
					if len(m) == 2:
						value = m[1]
					elif len(m) > 2:
						# We have to cast m[1:] as a set object first to get the order
						# of the elements to be the same as that in Config object (which
						# ultimately joins a set of elements).
						value = '|'.join( set(m[1:]) )

					# Check if Config and ConfigSpec for this resource already exists
					if self.has_config(specs[key], value) == False:
						config = Config( self.conn, self.cur, cid=None, config_spec=specs[key], \
											value=value, new=False)
						self.update_config( config )
					else:
						print 'Skipping existing config \"%s\".' % key

					del specs[key]

			l = f.readline()

		# Add remaining configurations that were not specified in the config file.
		#for k in specs:
		#	if self.has_config(specs[k], None) == False:
		#		config = Config( self.conn, cid=None, config_spec=specs[k], \
		#								value=None, new=False)
		#		self.update_config( config )
		#	else:
		#		print 'Skipping existing config \"%s\".' % k


	def compute_permissions(self, configs, shadow):
		gom = SshdGrOpMeta( self.conn, self.cur )
		gom.update_permission(configs, self, shadow)


	def compute_actors(self, shadow):
		gom = SshdGrOpMeta( self.conn, self.cur )
		grops = self.get_grops( ['method', 'protocol'] )
		# For each operation...
		for grop in grops:
			print 'DEBUG'
			gom.compute_actors(self, grop, shadow)


	def compute_hypothesis( self, do_unify_configs=False ):
		gom = SshdGrOpMeta( self.conn, self.cur )
		grops = self.get_grops( ['method', 'protocol'] )
		for grop in grops:
			gom.compute_bad_configs( self, grop )

		if do_unify_configs == True:
			self.unify_configs()

	#-----------------------------------------------------------------------------
	# Returns set of values to be excluded when getting next configuration value
	# for cfg.
	#-----------------------------------------------------------------------------
	def get_config_excludes( self, cfg ):
		config_excludes = set()
		if cfg == 'AllowUsers':
			sql = 'SELECT `user` FROM `ReqPerm` '\
					'INNER JOIN `Principal` ON `Principal`.`aid`=`ReqPerm`.`aid` '\
					'INNER JOIN `Resource` ON `Resource`.`rid`=`ReqPerm`.`rid` '\
					'WHERE `Resource`.`rid`=%d' % self.rid
			cur = self.cur if self.conn == None else self.conn.cursor()
			cur.execute(sql)
			rows = cur.fetchall()
			config_excludes.update([r[0] for r in rows])

		return config_excludes

	#-----------------------------------------------------------------------------
	# Return permissions. The type of permissions, GrPerm, NewGrPerm, or ReqPerm
	# is determined by ty.
	#-----------------------------------------------------------------------------
	def get_perms( self, ty ):
		sql = 'SELECT `pid`, `opid`, `aid` FROM `%s` WHERE `rid`=%d' % (ty, self.rid)
		rows = fetchall(self.conn, self.cur, sql)
		return set([SshdPermission(self.conn, self.cur, perm_id=r[0], \
												 rid=self.rid, opid=r[1], aid=r[2]) for r in rows])


	def __str__( self ):
		return '%s' % (self.hostname)

