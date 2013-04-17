import types
import copy

from Common import *
from ConfigSpec import *

class Config:
	def __init__(self, conn, cur, cid=None, config_spec=None, value=None, new=False, next_excludes=None):
		self.conn = conn
		self.cur = cur
		self.cid = cid
		self.config_spec = config_spec
		if self.cid == None:
			self.set_value( value )
		self.new = new
		self.update()
		self.next_excludes = set() if next_excludes == None else next_excludes


	def update(self):
		val = 'value' if self.new == False else 'value_shadow'
		if self.cid == None:
			ins_sql = 'INSERT INTO `Config` (`csid`,`%s`) ' \
					'VALUES (%d,%s)'	\
					% (val, self.config_spec.csid, prep_ins_str(self.get_value()) )
			self.cid = update_helper( self.conn, self.cur, ins_sql )
		else:
			sel_sql = 'SELECT `csid`, `%s` '\
					'FROM `Config` WHERE cid=%d' % (val, self.cid)
			rows = fetchall( self.conn, self.cur, sel_sql )
			self.config_spec = ConfigSpec( self.conn, self.cur, rows[0][0] )
			self.set_value( rows[0][1] )

	#-----------------------------------------------------------------------------
	# Sets the value. If its type is a set, but input value is a string, it is
	# converted into a set type.
	#-----------------------------------------------------------------------------
	def set_value( self, value ):
		#print 'key: %s value: %s' % (self.config_spec.key, value)
		#val = None
		#if value != None:
		#	val = value
		#elif self.config_spec.ty != 'set' or self.config_spec.default != '*':
		#	val = self.config_spec.default
		val = value

		if val != None and str(type(val)) == '<type \'unicode\'>':
			val = val.encode('ascii','replace')

		if self.config_spec.ty != None and self.config_spec.ty == 'set':
			if val != None:
				if str(type(val)) == '<type \'str\'>':
					self.value = set(val.split('|'))
				else:
					self.value = value
			else:
				self.value = set()
		else:
			self.value = val

	#-----------------------------------------------------------------------------
	# Returns the value.
	# If it is a set, it is converted into a '|'-delimited string.
	#-----------------------------------------------------------------------------
	def get_value( self):
		if str(type(self.value)) == '<type \'set\'>':
		 if len(self.value) != 0:
			 return '|'.join(str(v) for v in self.value)
		 else:
			 return None
		else:
			return self.value



	#-----------------------------------------------------------------------------
	# Inserts into GrOpMeta table. This table binds the configuration field with
	# the granted permission.
	#-----------------------------------------------------------------------------
	def commit_value_to_db(self, new):
		value = self.get_value()

		v = 'value' if new == False else 'value_shadow'

		upd_sql = 'UPDATE `Config` SET `%s`=%s WHERE `cid`=%d AND `csid`=%d' \
				% (v, prep_ins_str(value), self.cid, self.config_spec.csid)
		update_helper( self.conn, self.cur, upd_sql )

	#-----------------------------------------------------------------------------
	# Add values to be excluded when calling get_next_value.
	#-----------------------------------------------------------------------------
	def add_next_excludes(self, excludes):
		#assert(excludes != None)
		if excludes is None:
			return

		if str(type(excludes)) == '<type \'set\'>':
			self.next_excludes.update(excludes)
		else:
			self.next_excludes.add(excludes)

	#-----------------------------------------------------------------------------
	# 'used' is the list of used values, i.e.
	# 1. values from a tuple that have been used, or
	# 2. values from a set that have been removed.
	#-----------------------------------------------------------------------------
	def get_next_value(self, cur_value):
		if self.config_spec.ty == 'oneof':
			# Gets the next value in the tuple
			opts = self.config_spec.param.split('|')
			if cur_value not in opts:
				return None
			next_idx = opts.index(cur_value) + 1
			if next_idx >= len(opts):
				return None
			return opts[next_idx]

		elif self.config_spec.ty == 'set':
			# Removes the last element of the sorted intersection
			opts = self.value
			cur_valueset = copy.copy(self.value)

			# Remove the value that has not been excluded
			# and is in opts.
			u = None
			for cv in cur_valueset:
				if cv not in self.next_excludes and cv in opts:
					cur_valueset.remove(cv)
					#used.append(cv)
					u = cv
					break

			if u == None:
				return (None, u)

			return (cur_valueset, u)

	def __str__(self):
		return '%s = %s' % (str(self.config_spec.key).ljust(30), self.get_value())
