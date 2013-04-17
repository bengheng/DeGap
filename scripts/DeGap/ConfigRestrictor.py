from Common import *
from Config import *

class ConfigRestrictor:

	def __init__( self, conn, cur ):
		self.conn = conn
		self.cur = cur

	#-----------------------------------------------------------------------------
	# Restrict each configuration on resource in turn. If restriction does not
	# cause any change in allowed users, it is saved (committed to database).
	# Otherwise, the change is reverted.
	#-----------------------------------------------------------------------------
	def restrict_auto( self, rsrc ):
		print '### %s ###' % str(rsrc)

		'''
		One way to optimize is to differentiate the operations and look at only
		what may affect each operation. For example, permissions for read-other
		is distinct from the permissions for write-other. We'll just keep the
		following code here, which would be what we might use.

		reqperms = dict()
		grperms = dict()

		sql = 'SELECT `opid` FROM `Operation`'
		rows = fetchall(self.conn, self.cur, sql)
		opids = [int(r[0]) for r in rows]
		for opid in opids:
			if opid not in reqperms:
				reqperms[opid] = set()

			# Get set of requested permissions
			reqperms[opid].update( rsrc.get_reqperms( opid ) )

			# Copy grperms to new grperms
			rsrc.copy_grperm_to_newgrperm( opid )

			# Get current set of granted permissions for this op
			if opid not in grperms:
				grperms[opid] = set()
			grperms[opid].update( rsrc.get_grperms( opid, new=True ) )

		'''

		reqperms = set(rsrc.get_perms('ReqPerm'))   # Get requested permissions
		cur_grperms = set(rsrc.get_perms('GrPerm')) # Get granted permissions
		rsrc.copy_config_value_to_shadow()    		  # Update all config values to shadow
		configs = rsrc.get_configs( new=True )      # Get new configs
		print '\n'.join(str(configs[c]) for c in configs)
		new_grperms = None
		for c in configs:
			print '### Tightening %s, %s  ###'\
					% (str(configs[c]), str(configs[c].config_spec.default))
			print 'original value: ' + str(configs[c].get_value())

			if configs[c].config_spec.ty == 'set':
				(new_value, excluded) = configs[c].get_next_value(configs[c].get_value())
				configs[c].add_next_excludes( excluded )
			else:
				new_value = configs[c].get_next_value(configs[c].get_value())
			while (new_value != None):
				print '+'*80 + '\n%s <== %s' % (c, str(new_value))

				# Update restricted value and compute new granted permissions
				org_value = configs[c].get_value()
				configs[c].set_value(new_value)
				new_grperms	= self.map_configs_to_perms( rsrc, configs )

				print '# OG #\n' + '\n'.join(str(a) for a in cur_grperms)
				print '# NG #\n' + '\n'.join(str(a) for a in new_grperms)
				print '# RQ #\n' + '\n'.join(str(a) for a in reqperms)
				print 'NG <= OG: %d' % (new_grperms <= cur_grperms)
				print 'RQ <= NG: %d' % (reqperms <= new_grperms)

				if new_grperms <= cur_grperms and reqperms <= new_grperms:
					# Save value
					print 'Saving new value %s' % new_value
					configs[c].commit_value_to_db(new=True)
					cur_grperms = new_grperms
				else:
					print 'Restoring \"%s\" to \"%s\".' % (c, org_value)
					configs[c].set_value(org_value)

				# If cannot tighten further, go to next config
				if len(reqperms - new_grperms) == 0 \
			 and len(new_grperms - reqperms) == 0:
					break


				if configs[c].config_spec.ty == 'set':
					(new_value, excluded) = configs[c].get_next_value(configs[c].get_value())
					configs[c].add_next_excludes( excluded )
				else:
					new_value = configs[c].get_next_value(new_value)


			# End while (new_value != None)
		# End for c in configs

		if new_grperms != None:
			for p in new_grperms:
				p.commit('NewGrPerm')



	#-----------------------------------------------------------------------------
	# Restrict each configuration on resource in turn. If restriction does not
	# cause any change in allowed users, it is saved (committed to database).
	# Otherwise, the change is reverted.
	#-----------------------------------------------------------------------------
	def restrict_step_helper( self, rsrc, configs, reqperms, cur_grperms ):
		cand_configs = dict()

		print '### %s ###' % str(rsrc)
		print '\n'.join(str(configs[c]) for c in configs)
		for c in configs:
			print '### Tightening %s, %s  ###'\
					% (str(configs[c]), str(configs[c].config_spec.default))
			org_value = configs[c].get_value()
			print 'original value: ' + str(org_value)

			if configs[c].config_spec.ty == 'set':
				saved_excludes = set( configs[c].next_excludes )
				(new_value, excluded) = configs[c].get_next_value(org_value)
				print str(configs[c].next_excludes)
				print new_value
				while (new_value != None):
					configs[c].add_next_excludes( excluded )
					configs[c].set_value(new_value)
					new_grperms	= self.map_configs_to_perms( rsrc, configs )

					print '# OG #\n' + '\n'.join(str(a) for a in cur_grperms)
					print '# NG #\n' + '\n'.join(str(a) for a in new_grperms)
					print 'NG <= OG: %d' % (new_grperms <= cur_grperms)
					print 'RQ <= NG: %d' % (reqperms <= new_grperms)

					if new_grperms <= cur_grperms and reqperms <= new_grperms:
						cand_configs[c+':'+excluded] = (new_value, new_grperms, excluded)

					configs[c].set_value(org_value)
					(new_value, excluded) = configs[c].get_next_value(org_value)

				configs[c].next_excludes = saved_excludes

			else:
				new_value = configs[c].get_next_value(org_value)

				if (new_value != None):
					print '+'*80 + '\n%s <== %s' % (c, str(new_value))

					# Update restricted value and compute new granted permissions
					configs[c].set_value(new_value)
					new_grperms	= self.map_configs_to_perms( rsrc, configs )

					print '# OG #\n' + '\n'.join(str(a) for a in cur_grperms)
					print '# NG #\n' + '\n'.join(str(a) for a in new_grperms)
					print 'NG <= OG: %d' % (new_grperms <= cur_grperms)
					print 'RQ <= NG: %d' % (reqperms <= new_grperms)

					if new_grperms <= cur_grperms and reqperms <= new_grperms:
						# Save value
						#print 'Saving new value %s' % new_value
						#configs[c].commit_value_to_db(new=True)
						#cur_grperms = new_grperms

						cand_configs[c] = (new_value, new_grperms)

				# If cannot tighten further, go to next config
				#if len(reqperms - new_grperms) == 0 \
			 	#and len(new_grperms - reqperms) == 0:
				#	break

				#	print 'Restoring \"%s\" to \"%s\".' % (c, org_value)
				#	configs[c].set_value(org_value)

				# If cannot tighten further, go to next config
				#if len(reqperms - new_grperms) == 0 \
			  #and len(new_grperms - reqperms) == 0:
				#	print 'Cannot tighten \"%s\" further.' % c


				#if configs[c].config_spec.ty == 'set':
				#	new_value = configs[c].get_next_value(configs[c].get_value(), used)
				#else:
				#	new_value = configs[c].get_next_value(new_value, used)
			# End while (new_value != None)
			configs[c].set_value(org_value) # Restore config value
		# End for c in configs

		return cand_configs


	def restrict_step( self, rsrc ):
		reqperms = set(rsrc.get_perms('ReqPerm'))   # Get requested permissions
		cur_grperms = set(rsrc.get_perms('GrPerm')) # Get granted permissions
		rsrc.copy_config_value_to_shadow()    		  # Update all config values to shadow
		configs = rsrc.get_configs( new=True )      # Get new configs

		print '# RQ #\n' + '\n'.join(str(a) for a in reqperms)

		cand_configs = self.restrict_step_helper( rsrc, configs, reqperms, cur_grperms )
		while len(cand_configs) != 0:
			for c in cand_configs:
				d = c.split(':')[0]
				print '%s: %s -> %s' % (c, str(configs[d].get_value()), cand_configs[c][0])
				for p in cand_configs[c][1]:
					print '\t[+] %s' % str(p)
				print '\t' + '.'*20
				diff_perms = cur_grperms - cand_configs[c][1]
				for d in diff_perms:
					print '\t[-] %s' % str(d)
			c = ''
			while c not in cand_configs:
				print 'Type choice: ',
				c = raw_input()

			d = c.split(':')[0]

			# Update new configuration
			print 'Update \"%s\" to \"%s\" from \"%s\".' \
					% (c, cand_configs[c][0], str(configs[d].get_value()))
			configs[d].set_value( cand_configs[c][0] )
			configs[d].commit_value_to_db(new=True)

			# Update new granted permissions
			sql = 'DELETE FROM `NewGrPerm` WHERE `rid`=%d' % rsrc.rid
			update_helper( self.conn, self.cur, sql )
			cur_grperms = cand_configs[c][1]
			for p in cur_grperms:
				p.commit('NewGrPerm')

			if configs[d].config_spec.ty == 'set':
				configs[d].add_next_excludes( cand_configs[c][2] )

			#for f in cand_configs:
			#	if f != c and configs[c].config_spec.ty == 'set':
			#		configs[c].next_excludes = configs[c].next_excludes - cand_configs[c][2]

			cand_configs = self.restrict_step_helper( rsrc, configs, reqperms, cur_grperms )


