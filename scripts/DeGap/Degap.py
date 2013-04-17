#!/usr/bin/env python

import os
import imp
import sys
import sqlite3
import subprocess
import ConfigParser
#import cProfile
#import pstats

print sys.path[0]
plugin_dir = os.path.join(sys.path[0], "./plugins")
main_module = "__init__"
options = ['parse-logs', 'load-metadata', 'load-configs', 'compute-grperms', \
					'restrict-auto', 'restrict-step']

def load_plugin(plugin_name):
	plugin = None
	possible_plugins = os.listdir(plugin_dir)
	for i in possible_plugins:
		location = os.path.join(plugin_dir, i)
		if not os.path.isdir(location) or not main_module + ".py" in os.listdir(location):
			continue
		info = imp.find_module(main_module, [location])
		if i == plugin_name:
			plugin = {"name": i, "info": info}

	if plugin != None:
		return imp.load_module(main_module, *plugin["info"])
	return None



def load_db(db):
	if not os.path.exists(db):
		print 'Cannot find database \"%s". ' \
				'Please check db configuration in \"%s\". ' \
				'If you are using \"Users\" plugin, you need to use \"Auditd\" plugin '  \
				'first to load the database. The \"Users\" plugin derives its database ' \
				'from the \"Auditd\"\'s database.' \
				% (db, cfgname)
		sys.exit(-1)
	conn = sqlite3.connect(db)
	cur = conn.cursor()
	cur.execute( 'PRAGMA synchronous = OFF' )
	cur.execute( 'PRAGMA journal_mode = MEMORY' )
	cur.close()
	print 'Connected to \"%s\".' % db
	return conn


def reset_db(db, dbschema):
	# Delete database, then create a new one.
	if os.path.exists(db):
		print 'Removing database \"%s\"...' % db
		os.remove(db)
	print 'Creating database \"%s\" using schema \"%s\"...' % (db, dbschema)
	dbproc = subprocess.Popen(['sqlite3', db], stdin=open(dbschema, 'r') )
	dbproc.communicate()


def get_option():
	if len(sys.argv) != 2 or sys.argv[1] not in options:
		print 'Invalid option.\nUsage: %s %s' % (sys.argv[0], ' | '.join(options))
		sys.exit(0)
	return sys.argv[1]

#------------------------------------------------------------------------------
# Main
#------------------------------------------------------------------------------
if __name__=='__main__':

	try:
		# Get option
		option = get_option()

		# Load config.ini
		cfgname = 'config.ini'
		if not os.path.exists(cfgname):
			print 'Cannot find configuration file \"%s\".' % cfgname
			sys.exit(-1)
		cfg = ConfigParser.SafeConfigParser()
		cfg.optionxform = str
		cfg.read(cfgname)
		configs = dict(i[0:] for i in cfg.items('CONFIG'))

		# Load plugin
		plugin = load_plugin( configs['plugin'] )
		if plugin == None:
			print 'Plugin \"%s\" not found. Aborting.' % configs['plugin']
			sys.exit(-1)
		plugin.init()

		if option == 'parse-logs' and configs['plugin'] != 'Users':
			reset_db(configs['db'], configs['dbschema'])

		conn = load_db(configs['db'])
		if option == 'parse-logs':				plugin.parse_logs(conn, configs)
		#elif option == 'load-metadata':		cProfile.run('plugin.load_metadata(conn, configs)', 'load-metadata-profile')
		elif option == 'load-metadata':		plugin.load_metadata(conn, configs)
		elif option == 'load-configs':		plugin.load_configs(conn, configs, cfg)
		elif option == 'compute-grperms':	plugin.compute_grperms(conn, configs)
		elif option == 'restrict-auto':		plugin.restrict_auto(conn, configs)
		elif option == 'restrict-step':		plugin.restrict_step(conn, configs)
		else:
			print 'Unsupported option \"%s\".' % option
		conn.close()

		#p = pstats.Stats('load-metadata-profile')
		#p.strip_dirs().sort_stats('cum').print_stats()

	except (ConfigParser.NoSectionError, ConfigParser.NoOptionError) as err:
		print str(err)
