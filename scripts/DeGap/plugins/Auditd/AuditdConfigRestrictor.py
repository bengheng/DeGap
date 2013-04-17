from ConfigRestrictor import *
from plugins.Auditd.AuditdConfigs2Perms import *

class AuditdConfigRestrictor(ConfigRestrictor):

	def map_configs_to_perms( self, rsrc, configs ):
		c2p = AuditdConfigs2Perms(self.conn, self.cur)
		return c2p.map_configs_to_perms( rsrc, configs )
