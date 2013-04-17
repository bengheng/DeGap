
class QEAttrib:
	def __init__(self, name):
		self.name = name
		self.foreign_table = None
		self.query = None

	def set_foreign_table(self, ft):
		self.foreign_table = ft

	def set_query(self, query):
		self.query = query


class QENode:
	def __init__(self, name):
		self.name = name
		self.primary_key = None
		self.attribs = set()
		self.parents = set()
		self.imm_parents = set()
		self.children = set()
		self.level = 0

	def add_attrib(self, attrib, primary_key=False):
		self.attribs.add( attrib )
		if primary_key == True:
			self.primary_key = attrib

	def add_child(self, node):
		self.children.add( node )

	def add_parent(self, node):
		self.parents.add( node )
		self.imm_parents.add( node )

	def get_shortest_parents(self, path, disallowed):
		minp = None
		for p in self.imm_parents:
			if p in disallowed:
				continue
			if minp is None or minp.level > p.level:
				minp = p

		if minp != None:
			minp.get_shortest_parents( path, disallowed )
		path.append(self)

	def set_level(self, level):
		self.level = level
		for p in self.parents:
			self.level = max(self.level, p.level + 1)

		for child in self.children:
			child.set_level( self.level + 1 )

	def prnt(self, level):
		print ' '*level + '%d %s' % (self.level, self.name)
		for child in self.children:
			child.prnt( level + 1)


	def __eq__(self, other):
		return self.name == other.name

	def __hash__(self):
		return hash(self.name)

	def __str__(self):
		return self.name


