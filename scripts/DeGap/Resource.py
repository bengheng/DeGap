from Common import *
from Config import *
from Permission import *

class Resource:

	def __init__( self, conn, cur, rsrc_meta=None, rid=None ):
		assert rsrc_meta != None or rid != None
		self.conn = conn
		self.cur = cur
		self.rsrc_meta = rsrc_meta
		self.rid = rid
		self.roids = set()
		self.roaids = set()

	#-----------------------------------------------------------------------------
	# Updates configuration.
	#-----------------------------------------------------------------------------
	def update_config( self, config ):
		ins_sql = 'INSERT OR IGNORE INTO `ResourceConfig` '\
				'(`rid`,`cid`) VALUES (%d,%d)' % (self.rid, config.cid)
		update_helper( self.conn, self.cur, ins_sql )


	#-----------------------------------------------------------------------------
	# Returns configs for rid.
	#-----------------------------------------------------------------------------
	def get_configs( self, new ):
		configs = dict()
		sql = 'SELECT `cid` FROM `ResourceConfig` WHERE `rid`=%d' % (self.rid)
		rows = fetchall(self.conn, self.cur, sql)
		for r in rows:
			config = Config( self.conn, self.cur, r[0], new=new )
			#excludes = self.get_config_excludes( config.config_spec.key )
			#config.add_next_excludes( excludes )
			configs[config.config_spec.key] = config
		return configs


	#-----------------------------------------------------------------------------
	# Copy GrPerm to NewGrPerm.
	#-----------------------------------------------------------------------------
	def copy_grperm_to_newgrperm( self ):
		sql = 'INSERT OR IGNORE INTO `NewGrPerm` (`rid`,`opid`,`aid`) '\
				'SELECT `rid`,`opid`,`aid` FROM `GrPerm` '\
				'WHERE `rid`=%d' % (self.rid)
		update_helper( self.conn, self.cur, sql )

	#-----------------------------------------------------------------------------
	# Copy value to value_shadow in Config table.
	#-----------------------------------------------------------------------------
	def copy_config_value_to_shadow( self ):
		sql = 'UPDATE `Config` SET `value_shadow`=`Config`.`value` '\
			'WHERE `cid` IN (SELECT `cid` FROM `ResourceConfig` WHERE `rid`=%d)' % self.rid
		update_helper( self.conn, self.cur, sql )
