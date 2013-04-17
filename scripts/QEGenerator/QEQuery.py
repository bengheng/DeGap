#!/usr/bin/env python

import os
import sys
import types
import sqlite3
import subprocess
from pyparsing import *
from ConfigParser import SafeConfigParser

from QEJoin import *
from QETable import *


class QEQuery:
	compare_op = ['<', '<=', '>', '>=', '==', '!=', '<>']

	sqlite_op = ['||',
							 '*', '/', '%',
							 '+', '-',
							 '<<', '>>', '&', '|',
							 '<', '<=', '>', '>=',
							 '=', '==', '!=', '<>', 'IS', 'IS NOT', 'IN', 'LIKE', 'GLOB', 'MATCH', 'REGEXP',
							 'AND', 'OR']

	def __init__(self, conn, cfg, section):
		self.conn = conn
		self.cfg = cfg
		self.section = section

	#------------------------------------------------------------------------------
	# Parses line into AST-like list structure for SQLite conditions. E.g.
	#
	# '((<>,\"hello\") AND (<>,\"world\")) OR (=,\"test\") AND (IS NOT,5)'
	#
	# becomes
	#
	# [[['<>', '"hello"'], 'AND', ['<>', '"world"']], 'OR', ['=', '"test"'], 'AND', ['IS NOT', '5']]
	#
	#------------------------------------------------------------------------------
	def parse_sqlite_rule(self, line):
		op = oneOf( self.sqlite_op )
		lpar = Suppress(Literal( '(' ))
		rpar = Suppress(Literal( ')' ))
		comma = Suppress(Literal( ',' ))
		table = Combine(Word(alphanums) + Literal('.') + Word(alphanums))
		
		expr = Forward()
		value = quotedString | Word(nums) | table
		atom =	Group( lpar + op + comma + value + rpar ) | Group( lpar + expr + rpar )
		expr << atom + ZeroOrMore( op + expr )
		return expr.parseString(line)

	#------------------------------------------------------------------------------
	# Returns True if list is a terminal node, i.e. there are only two elements
	# and both are not lists. e.g. ['<>', '"hello"']
	#------------------------------------------------------------------------------
	def is_terminal(self, l):
		return (len(l) == 2 \
				and type(l[0]) is types.StringType \
				and type(l[1]) is types.StringType)
	
	
	#------------------------------------------------------------------------------
	# Helper function to make constraints recursively from AST-like list.
	#------------------------------------------------------------------------------
	def	mk_constraints_recurse(self, f, l, converter=None):
		cstrs = ''
		if self.is_terminal( l ) == True:
			cstrs += '%s %s ' % (f, l[0])
			if converter != None:
				cstrs += converter( l[1] )
			else:
				cstrs += l[1]
			return cstrs
		
		for i in l:
			if type(i) is ParseResults:
				cstrs += '(' + self.mk_constraints_recurse( f, i, converter ) + ')'
			elif i in sqlite_op:
				cstrs += ' %s ' % i
	
		return cstrs
	
	
	#------------------------------------------------------------------------------
	# Helper function to make constraints.
	# 'converter' is used to specify conversion from the user input to string
	# format that is consumable by SQLite. For example, the user may be allowed
	# to specify octet numbers, but it needs to be translated into integer, and
	# then string.
	#------------------------------------------------------------------------------
	def mk_constraints_helper( self, cstrs, f, c, converter=None ):
		if c == '-' or c[0] == '?':
			return cstrs
		l = self.parse_sqlite_rule( c )
		print str(l)
		o = self.mk_constraints_recurse( f, l, converter )
		if o != None:
			if cstrs != '':
				cstrs += ' AND '
			cstrs += o
		return cstrs
	
	
	#------------------------------------------------------------------------------
	# Make constraints.
	#------------------------------------------------------------------------------
	def mk_constraints( self, tables, cstrs ):
		for t in tables:
			for attrib in tables[t].attribs:
				if attrib.query != None:
				#attrib.foreign_table is None:
					cstrs = self.mk_constraints_helper( cstrs, \
																		'`%s`.`%s`'%(t, attrib.name), \
																		attrib.query )
		return cstrs
	
	
	#------------------------------------------------------------------------------
	# Helper function to make query.
	#------------------------------------------------------------------------------
	def concat_query( self, q, v, f ):
		#if v != '?':
		if v == '-':
		 return q
		if len(q) > 0: q += ','
		q += f
		return q
	
	
	#------------------------------------------------------------------------------
	# Returns None if count not required.
	# Returns False if count is required, but comparison not required.
	# Otherwise, returns a list where first element specifies the operator and second
	# element specifies the value.
	#------------------------------------------------------------------------------
	def get_count_modifier( self ):
		if 'count' not in self.cfg.options(self.section):
			return None
	
		c = self.cfg.get(self.section, 'count')
		if c == '-':
			return None
		
		if c[0] == '?':
			return False
	
		l = self.parse_sqlite_rule( c )
		if type(l[0][0]) is not types.StringType \
			 and type(l[0][1]) is not types.StringType:
			print 'Invalid syntax for count.'
			sys.exit(-1)
	
		if l[0][0] not in self.compare_op:
			print 'Invalid comparison operator for count. Expect:'
			print self.compare_op
			sys.exit(-1)
	
		return l[0]


	def mk_query_select(self, tables):
		# SELECTS
		p=''
		for t in tables:
			for attrib in tables[t].attribs:
				if attrib.query == None or attrib.query[0] != '?':
					continue
				selectvalue = '`%s`.`%s`'%(t, attrib.name)
				p = self.concat_query(p, attrib.query, selectvalue)
				
	
		q = 'SELECT'
		if 'distinct' in self.cfg.options(self.section) \
		and self.cfg.get(self.section, 'distinct') == 'yes':
			q += ' DISTINCT'
	
		count_modifier = self.get_count_modifier( )
		if count_modifier != None:
			q += ' COUNT(*)'
		else:
			if q[-1] != ' ':
				q += ' '
			q += p+'\n'

		return q


	def mk_sql_helper( self, tables, qtables, cstrs ):
		q = self.mk_query_select(tables)
		q += mk_simple_inner_join(tables, qtables) 
		if cstrs != '':
			if q[-1] != ' ':
				q += ' '
			q += 'WHERE ' + cstrs

		return q

	#------------------------------------------------------------------------------
	# Entry function to generate SQL.
	#------------------------------------------------------------------------------
	def mk_sql( self ):
		opactor = None
		if 'opactor' in self.cfg.options(self.section):
			opactor = self.cfg.get(self.section, 'opactor')
	
		tables = get_tables( self.conn, self.cfg, self.section )
	
		# Constraints
		cstrs = ''
		cstrs = self.mk_constraints( tables, cstrs )
	
		# Joins
		qtables = get_qtables( tables )
		if opactor is None:
			q = self.mk_sql_helper( tables, qtables, cstrs )	
		else:
			q = mk_opactor_inner_join(self, tables, qtables, opactor, cstrs)
			count_modifier = self.get_count_modifier()
			if count_modifier != None:
				q= 'SELECT COUNT(`aid`) FROM (%s)' % q
	
	
		print q
		return q
	
	
