from ConfigRestrictor import *
from plugins.Users.UsersConfigs2Perms import *

class UsersConfigRestrictor(ConfigRestrictor):

	def map_configs_to_perms( self, rsrc, configs ):
		c2p = UsersConfigs2Perms(self.conn, self.cur)
		return c2p.map_configs_to_perms( rsrc, configs )
