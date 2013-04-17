import sys
import types
from pyparsing import *
from collections import deque

from QEQuery import *

actor_tables = ['ReqOpActor', 'GrOpActor', 'DenyOpActor', 'GrOpActorShadow', 'DenyOpActorShadow']
sqlite_op = ['UNION', 'UNION ALL', 'INTERSECT', 'EXCEPT']

#------------------------------------------------------------------------------
# Parses 'opactor' field that specifies set operations on Actor tables.
#------------------------------------------------------------------------------
def parse_sqlite_rule(line):
	op = oneOf( sqlite_op )
	lpar = Suppress(Literal( '(' ))
	rpar = Suppress(Literal( ')' ))
	
	expr = Forward()
	tbl = oneOf( actor_tables )
	atom =  tbl | Group( lpar + tbl + op + tbl + rpar ) | Group( lpar + expr + rpar )
	expr << atom + ZeroOrMore(op + (expr|tbl))
	return expr.parseString(line)

#------------------------------------------------------------------------------
# Returns true if the two tables are conflicting, meaning if they are in the
# same conjuctive query, they will cause side-effects. For example, if GrOp and
# ReqOp are used together, if there are no Requested Ops, the result is empty
# even if there are Granted Ops.
#------------------------------------------------------------------------------
def is_conflict(t1, t2):
	# Elements in each set are non-conflicting.
	set1 = set(['ReqOpActor', 'ReqOp'])
	set2 = set(['GrOpActor', 'GrOpActorShadow'])
	set3 = set(['DenyOpActor', 'DenyOpActorShadow'])

	if t1 in set1 and (t2 in set2 or t2 in set3 or t2 == 'GrOp'):
		return True
	if t2 in set1 and (t1 in set2 or t1 in set3 or t1 == 'GrOp'):
		return True

	if t1 in set2 and (t2 in set1 or t2 in set3):
		return True
	if t2 in set2 and (t1 in set1 or t1 in set3):
		return True

	if t1 in set3 and (t2 in set1 or t2 in set2):
		return True
	if t2 in set3 and (t1 in set1 or t1 in set2):
		return True

	if t1 == 'GrOp' and (t2 in set1):
		return True
	if t2 == 'GrOp' and (t1 in set1):
		return True

	return False

'''
def get_compatible(t):
	if t == 'ReqOpActor' or t == 'ReqOp':
		return set(['ReqOpActor', 'ReqOp'])
	if t == 'GrOp' or t == 'GrOpActor' or t == 'GrOpActorShadow':
		return set(['GrOp', 'GrOpActor', 'GrOpActorShadow'])
	if t == 'Gr'
'''

#------------------------------------------------------------------------------
# Returns a work scheme, i.e. the list of tables to be joined.
#------------------------------------------------------------------------------
def get_work_scheme( root, work, disallowed ):
	scheme = []
	# Use breadth-first-search to look for nearest allowed parent.
	queue = deque( [root] )
	while len(queue) != 0 and len(work) != 0:
		e = queue.popleft()
		if e in work:
			work.remove(e)
			# Add to scheme
			if e not in scheme:
				path = []
				e.get_shortest_parents( path, disallowed )
				#print '%s: %s' % (e.name, ', '.join(str(p) for p in path))
				# Only add if it is not already in the scheme
				for p in path:
					if p not in scheme:
						scheme.append( p )
					
		for child in e.children:
			queue.append(child)

	return scheme


#------------------------------------------------------------------------------
# Returns a list of pairs on attributes that are added and have relationships
# with tbl.
# It can be a foreign key in either direction.
#------------------------------------------------------------------------------
def get_relationships( tables, table, added ):
	reln = []
	# Get all foreign keys in table attributes
	for attrib in table.attribs:
		if attrib.foreign_table is not None \
		 and attrib.foreign_table in added:
			reln.append( ((table.name,attrib.name),\
								 (attrib.foreign_table.name, \
					attrib.foreign_table.primary_key.name)) )

	# Get tables for which tbl_name is referred to
	for foreign_table in added:
		for attrib in foreign_table.attribs:
			if attrib.foreign_table is not None \
			and attrib.foreign_table == table:
				reln.append( ((foreign_table.name, attrib.name), \
									(table.name, table.primary_key.name)) )

	return reln

#------------------------------------------------------------------------------
# Return conflicting tables that should not be in the same subquery.
#------------------------------------------------------------------------------
def get_conflicts(t):
	conflicts = set()
	atblnames = ['ReqOp', 'GrOp', 'ReqOpActor', \
							'GrOpActor', 'GrOpActorShadow', \
							'DenyOpActor', 'DenyOpActorShadow']
	for i in atblnames:
		if is_conflict(t, i):
			conflicts.add( i )
	return conflicts

#------------------------------------------------------------------------------
# Makes the main inner join string.
# Python's copying is giving us a hell lot of trouble.
#------------------------------------------------------------------------------
def mk_simple_inner_join(tables, qtables):
	print 'QTABLES: ' + ','.join(str(q) for q in qtables)

	atblnames = ['ReqOp', 'GrOp', 'ReqOpActor', \
							'GrOpActor', 'GrOpActorShadow', \
							'DenyOpActor', 'DenyOpActorShadow']

	nactor = 0
	for q in qtables:
		if q.name == "Actor":
			nactor += 1

	n = 0
	for q in qtables:
		if q.name in atblnames:
			n = n + 1
	if nactor != 0 and n == 0:
		print 'Actor was specified but exactly one of %s is required.' % ', '.join(atblnames)
		print 'qtables: ' + ', '.join(str(q) for q in qtables)
		sys.exit(0)

	disallowed = set()
	for q in qtables:
		conflicts = get_conflicts( q.name )
		disallowed.update( set([tables[t] for t in conflicts]) )

	print 'Disallowed: ' + ', '.join(str(d) for d in disallowed)
	# For each table to be queried, we need to find all other tables referencing it.
	# Actor tables are also ignored as they may lead to NULL results.
	'''
	q2tables = set()
	for q in qtables:
		for t in tables:
			if t in atblnames or tables[t] in disallowed:
				continue
			for attrib in tables[t].attribs:
				if attrib.foreign_table != None\
			 and attrib.foreign_table == q :
					q2tables.add( tables[t] )
	qtables = qtables | q2tables
	'''

	# Get work scheme
	work = set([q for q in qtables])
	print 'WORK: ' + ','.join(str(w) for w in work)
	root = tables['ResourceMeta']

	########
	# DEBUG!!!!!
	disallowed.clear()
	scheme = get_work_scheme( root, work, disallowed )
	print 'SCHEME: ' + ','.join(str(s) for s in scheme)

	joins = list()
	joins.append('FROM `%s`' % scheme[0].name)

	added = set([scheme[0]])
	for n in range(1, len(scheme)):
		table = scheme[n]
		relns = get_relationships( tables, table, added )
		joins.append( 'INNER JOIN `%s` ON (%s)' \
							 % (table.name, \
					 ' AND '.join(['`%s`.`%s`=`%s`.`%s`'%(r[0][0],r[0][1],r[1][0],r[1][1]) for r in relns])))
		added.add( table )

	j = '\n'.join(joins)
	return j


#------------------------------------------------------------------------------
# Helper function to make joins recursively from AST-like list.
#------------------------------------------------------------------------------
def  mk_join_recurse( qequery, tables, qtables, l, cstrs ):

	if type(l) is types.StringType:
		if l in sqlite_op:
			return '%s\n' % l
		else:
			use_qtables = set()
			for t in qtables:
				if t.name == l or not is_conflict(l, t.name):
					use_qtables.add( t )
			h = mk_simple_inner_join(tables, use_qtables)
			j = 'SELECT `%s`.`aid` AS `aid`\n%s\n%s\n' % (l, h, \
																							 'WHERE %s'%cstrs if cstrs != '' else '')
			return j

	j = ''
	for i in l:
		#print '\t' + i
		# This weird thing is to make SQLite happy. It can't use brackets for set ops.
		if type(i) is ParseResults:
			j +=  'SELECT `aid` FROM (%s)\n' % mk_join_recurse(qequery, tables, qtables, i, cstrs)

		else:
			j += mk_join_recurse(qequery, tables, qtables, i, cstrs)
			
	return j


#------------------------------------------------------------------------------
# Returns opactor tables specified in opactor.
#------------------------------------------------------------------------------
def get_opactor_tables(tables, l):
	j = set()
	if type(l) is types.StringType:
		if l in sqlite_op:
			return j
		else:
			assert l in tables
			j.add(tables[l])
			return j

	for i in l:
		j.update( get_opactor_tables(tables, i) )

	return j

#------------------------------------------------------------------------------
# Makes the main inner join string.
# Python's copying is giving us a hell lot of trouble.
#------------------------------------------------------------------------------
def mk_opactor_inner_join(qequery, tables, qtables, opactor, cstrs):
	# Get the component tables for opactor and add them to qtables.
	oa = parse_sqlite_rule(opactor)
	oat = get_opactor_tables( tables, oa )
	qtables.update( oat )
	return mk_join_recurse( qequery, tables, qtables, oa, cstrs)
