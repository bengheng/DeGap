from ConfigRestrictor import *
from plugins.Sshd.SshdConfigs2Perms import *

class SshdConfigRestrictor(ConfigRestrictor):

	def map_configs_to_perms( self, rsrc, configs ):
		c2p = SshdConfigs2Perms(self.conn, self.cur)
		return c2p.map_configs_to_perms( rsrc, configs )
