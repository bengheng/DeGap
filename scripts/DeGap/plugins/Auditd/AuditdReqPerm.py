import os
import sys

from plugins.Auditd.AuditdOperation import *
from plugins.Auditd.AuditdPrincipal import *
from plugins.Auditd.AuditdPermission import *

class AuditdReqPerm:
	O_RDONLY = 0
	O_WRONLY = 1
	O_RDWR = 2
	SC_OPEN = 2
	SC_EXECVE = 59

	def __init__(self, conn, cur):
		self.conn = conn
		self.cur = cur

	#-----------------------------------------------------------------------------
	# Returns 0 for owner, 1 for group, 2 for others.
	#-----------------------------------------------------------------------------
	def get_user_type( self, ouid, ogid, euid, egid ):
		# Assume root uid is 0
		if euid == 0 or euid == ouid: return 'usr'
		elif egid == ogid:						return 'grp'
		else:													return 'oth'

	#-----------------------------------------------------------------------------
	# Computes granted permissions for all operations on resource rsrc.
	#-----------------------------------------------------------------------------
	def compute( self, rsrc ):
		sql = 'SELECT `omid`, `syscall`, `uid`, `gid`, `euid`, `egid`, `flags` FROM `OpMeta` '\
				'INNER JOIN `syscall_open` ON `OpMeta`.`sc_open_id`=`syscall_open`.`sc_open_id` '\
				'WHERE `rid`=%d' % rsrc.rid
		rows = fetchall(self.conn, self.cur, sql)

		reqperms = set()

		# For each operation...
		for (omid, syscall, uid, gid, euid, egid, flags) in rows:
			usrty = self.get_user_type( rsrc.uid, rsrc.gid, euid, egid )

			op = []
			if syscall == self.SC_OPEN:
				# Checks for read and write
				f = flags & 0x3
				if (f == self.O_RDONLY or f == self.O_RDWR): op.append('r')
				if (f == self.O_WRONLY or f == self.O_RDWR): op.append('w')

			elif syscall == self.SC_EXECVE:
				# Checks for execute-related permissions
				op.append('x')

				if rsrc.uid == euid\
					and euid != uid\
					and (rsrc.mode & 04000) != 0:
					principal = AuditdPrincipal(self.conn, self.cur, euid, None)
					operation = AuditdOperation(self.conn, self.cur, label='suid')
					reqperms.add( AuditdPermission(self.conn, self.cur, perm_id=None, rid=rsrc.rid, \
															opid=operation.opid, aid=principal.aid) )

				if rsrc.uid != euid\
					and egid == rsrc.gid\
				 	and egid != gid\
				 	and (rsrc.mode & 02000) != 0:
					principal = AuditdPrincipal(self.conn, self.cur, euid, None)
					operation = AuditdOperation(self.conn, self.cur, label='sgid')
					reqperms.add( AuditdPermission(self.conn, self.cur, perm_id=None, rid=rsrc.rid, \
															opid=operation.opid, aid=principal.aid) )

			for o in op:
				use_uid = euid if usrty == 'usr' or usrty == 'oth' else None
				use_gid = egid if usrty == 'grp' else None
				principal = AuditdPrincipal(self.conn, self.cur, use_uid, use_gid)
				operation = AuditdOperation(self.conn, self.cur, label=o+usrty)
				reqperms.add( AuditdPermission(self.conn, self.cur, perm_id=None, rid=rsrc.rid, \
														 opid=operation.opid, aid=principal.aid) )

				cur = self.conn.cursor() if self.conn != None else self.cur
				cur.execute('UPDATE `OpMeta` SET `opid`=%d WHERE `omid`=%d' % (operation.opid, omid))
				if self.conn != None:
					cur.close()
					self.conn.commit()
				

		for p in reqperms:
			p.commit('ReqPerm')
