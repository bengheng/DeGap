from QENode import *

#------------------------------------------------------------------------------
# Returns a dictionary of columns that are foreign keys.
# The key is the column name. The value is a tuple for the foreign
# key's table and column name.
#------------------------------------------------------------------------------
def get_foreign_keys(conn, tbl_name):
	fks = {}
	cur = conn.cursor()
	cur.execute('PRAGMA foreign_key_list("%s")' % tbl_name)
	r = cur.fetchone()
	while r:
		fks[r[3]] = ( r[2], r[4] )
		r = cur.fetchone()
	cur.close()
	#print 'fks %s: ' % tbl_name,
	#print fks
	return fks


#------------------------------------------------------------------------------
# Returns list of attribute tuples for table.
# Each tuple is in the format (name, pri_key).
#------------------------------------------------------------------------------
def get_attribs_from_db(conn, tbl_name, tables):
	table = tables[tbl_name]

	# Get foreign keys
	fks = get_foreign_keys(conn, tbl_name)

	cur = conn.cursor()
	cur.execute('PRAGMA table_info(`%s`)' % tbl_name)
	r = cur.fetchone()
	while r:
		attrib = QEAttrib( r[1] )

		# Set first element of tuple to False for now.
		# Will init to true if specified in config file.
		pri_key = False
		if r[5]==1:
			pri_key = True
		elif r[1] in fks:
			ft = tables[ fks[r[1]][0] ]
			attrib.set_foreign_table( ft )

		table.add_attrib( attrib, primary_key=pri_key )
		r = cur.fetchone()
	cur.close()


#------------------------------------------------------------------------------
# Returns dictionary keyed by table names.
#------------------------------------------------------------------------------
def get_tables_from_db(conn):
	tables = dict()
	cur = conn.cursor()
	cur.execute('SELECT name FROM sqlite_master WHERE type="table"');
	r = cur.fetchone()
	while r:
		if r[0] != 'sqlite_sequence':
			tables[r[0]] = QENode(r[0])
		r = cur.fetchone()
	cur.close()
	return tables

#------------------------------------------------------------------------------
# Returns set of tables that have foreign keys to input table, or input table
# has foreign keys to them.
#------------------------------------------------------------------------------
def get_relatives(tables, table):
	relatives = set()
	# Get all foreign keys in table attributes
	for attrib in table.attribs:
		if attrib.foreign_table is not None \
		 and attrib.foreign_table != table:
			relatives.add( attrib.foreign_table )
	# Get tables for which tbl_name is referred to
	for u in tables:
		if tables[u] == table:
			continue
		for attrib in tables[u].attribs:
			if attrib.foreign_table is None:
				continue
			if attrib.foreign_table == table:
				relatives.add( tables[u] )
	return relatives

#------------------------------------------------------------------------------
# Builds the tree structure by setting children and parents for each table.
# Tables in the priority list will be examined first.
#------------------------------------------------------------------------------
def build_tree(table, tables, priority):
	block = ['OpLabel', 'Actor']
	relatives = get_relatives( tables, table )
	children = relatives - table.parents
	#print 'Parents: ' + ','.join( str(p) for p in table.parents )
	#print 'Children: ' + ','.join( str(c) for c in children )

	if table.name in block:
		return

	# Do priority list
	for child in children:
		if child.name not in priority:
			continue
		table.add_child( child )
		child.add_parent( table )
		child.parents.update( table.parents )
		build_tree( child, tables, priority )

	# The rest...
	for child in children:
		if child.name in priority:
			continue
		table.add_child( child )
		child.add_parent( table )
		child.parents.update( table.parents )
		build_tree( child, tables, priority )


#------------------------------------------------------------------------------
# Returns a dictionary of all tables in database.
#------------------------------------------------------------------------------
def get_tables(conn, cfg, section):
	print 'Extracting query format...'
	tables = get_tables_from_db(conn)
	for t in tables:
		get_attribs_from_db( conn, t, tables )

	priority =  ['Resource', 'ReqOp', 'ReqOpMeta', 'ReqOpActor', 'Actor', \
							'OpLabel', 'GrOp', 'GrOpMeta', 'ConfigKey', \
							'GrOpActor', 'DenyOpActor', 'GrOpActorShadow', 'DenyOpActorShadow']
	root = tables['ResourceMeta']
	build_tree( root, tables,  priority)
	root.set_level(0)

	# Update table with values from cfg
	queries = cfg.options(section)

	# Now set attribute to use or don't use
	for t in tables:
		for a in tables[t].attribs:
			field = '%s.%s' % (t, a.name)
			if field in queries:
				a.set_query( cfg.get(section, field) )

	return tables


#------------------------------------------------------------------------------
# Returns query tables, i.e. tables on which queries will be made.
#------------------------------------------------------------------------------
def get_qtables(tables):
	qtables = set()
	for t in tables:
		for attrib in tables[t].attribs:
			if attrib.query != None:
				qtables.add( tables[t] )
				break
	return qtables

