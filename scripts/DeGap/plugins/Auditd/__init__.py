import os
import sys
import mmap
import time
import ctypes
import ConfigParser
import subprocess
from multiprocessing import Process, Queue

from plugins.Auditd.AuditdConfigs2Perms import *
from plugins.Auditd.AuditdType import *
from plugins.Auditd.AuditdResource import *
from plugins.Auditd.AuditdConfigRestrictor import *

def init():
	print('Using \"Auditd\" plugin.')

def parse_logs(conn, configs):
	print 'Parsing logs...'
	base = './'
	
	logs = []
	log_dir = './auditlogs'
	for l in os.listdir('./auditlogs'):
		if l.startswith('audit.'):
			logs.append(os.path.join(log_dir, l))

	ausecure = configs['ausecure']
	if not os.path.exists(ausecure):
		print 'ausecure, the log parser for Auditd, ' \
				'is not found at \"%s\". Aborting.' % ausecure
		sys.exit(-1)

	sout = None
	if 'ausecurelog' in configs:
		ausecurelog = configs['ausecurelog']
		sout = open(ausecurelog, 'w')

	print 'Begin parsing logs for %s...' % configs['hostname']
	print '='*80
	if sout != None:
		print '[stdout and stderr is piped to \"%s\".]' % (ausecurelog)
	tic = time.time()
	log_parser = subprocess.Popen([ausecure, \
																'-b', base, \
																'-a', ','.join(logs), \
																'-d', configs['db']], \
															 stdout = sout,
															 stderr = sout)
	log_parser.communicate()
	toc = time.time()
	print '='*80
	elapsed = toc - tic
	print 'Done parsing logs for %s. Took %f seconds.' \
			% (configs['hostname'], elapsed)




#------------------------------------------------------------------------------
# Reads each line from mdfile and updates database.
#------------------------------------------------------------------------------


def load_metadata_worker(db, task_queue):

	for task in iter(task_queue.get, 'STOP'):
		conn = sqlite3.connect(db, timeout=60)

		cur = conn.cursor()
		fullpath = task[0]
		fileext = task[1]
		nfileext = task[2]
		filetype = task[3]
		nfiletype = task[4]
		mode = task[5]
		uid = task[6]
		gid = task[7]

		req_perm = AuditdReqPerm(None, cur)
		rsrc = AuditdResource( None, cur, path=fullpath, rid=None )
		if rsrc.rid != None:
			tyid = AuditdType( None, cur,
										 fullpath if 'directory' in filetype.lower() \
										 else os.path.dirname(fullpath),
										 filetype ).get_tyid()
			rsrc.update( tyid, fileext, uid, gid, mode )
			req_perm.compute(rsrc)
			#rsrc.compute_actors( shadow=False )
		cur.close()

		conn.close()


def load_metadata_mp(conn, configs):
	mdfile = configs['metadatafile']
	print 'Using metadata from \"%s\"...' % mdfile

	print 'Begin loading metadata for %s...' % configs['hostname']
	print '='*80
	tic = time.time()

	task_queue = Queue()

	NUMBER_OF_PROCESSES = 7
	processes = []
	for i in range(NUMBER_OF_PROCESSES):
		print 'Starting Process #%d' % i
		proc = Process(target=load_metadata_worker, args=(configs['db'], task_queue,))
		processes.append( proc )
		proc.start()

	with open(mdfile, 'r+b') as f:
		map = mmap.mmap(f.fileno(), 0)
		line = map.readline()
		while line:
			m = line.split('|')
			fullpath = m[0]
			fileext = m[1]
			nfileext = int(m[2]) # unused
			filetype = m[3]
			nfiletype = int(m[4]) # unused
			mode = ctypes.c_int32(int(m[5])).value
			uid = ctypes.c_int32(int(m[6])).value
			gid = ctypes.c_int32(int(m[7])).value

			# Skip entries for which we don't have info.
			if mode == -1 or uid == -1 or mode == -1:
				line = map.readline()
				continue

			#cur = conn.cursor()
			#cur.execute('BEGIN TRANSACTION')
			#cur.close()
			
			task_queue.put((fullpath, fileext, nfileext, filetype, nfiletype, mode, uid, gid))
			
			#cur = conn.cursor()
			#cur.execute('END TRANSACTION')
			#conn.commit()
			#cur.close()

			line = map.readline()
		map.close()

	for i in range(NUMBER_OF_PROCESSES):
		task_queue.put('STOP')
		#print 'Stopping Process #%d' % i

	for i in range(len(processes)):
		processes[i].join()
		print '%d process joined.' % i

	toc = time.time()
	print '='*80
	elapsed = toc - tic
	print 'Done loading metadata for %s. Took %f seconds.' \
			% (configs['hostname'], elapsed)


def create_index_for_principal(conn):
	cur = conn.cursor()
	cur.execute('PRAGMA INDEX_LIST(\'Principal\');')
	rows = cur.fetchall()
	for r in rows:
		if r[1] == 'idx_principal':
			print 'In table \"Principal\", index \"idx_principal\" already exists.'
			cur.close()
			return
	print 'Creating index \"idx_principal\" for \"Principal\" on (uid, gid)'
	cur.execute('CREATE INDEX idx_principal ON Principal (uid, gid)')
	cur.close()


def create_index_for_resource(conn):
	cur = conn.cursor()
	cur.execute('PRAGMA INDEX_LIST(\'Resource\');')
	rows = cur.fetchall()
	for r in rows:
		if r[1] == 'idx_resource':
			print 'In table \"Resource\", index \"idx_resource\" already exists.'
			cur.close()
			return
	print 'Creating index \"idx_resource\" for \"Resource\" on (path)'
	cur.execute('CREATE INDEX idx_resource ON Resource (path)')
	cur.close()


def create_index_for_operation(conn):
	cur = conn.cursor()
	cur.execute('PRAGMA INDEX_LIST(\'Operation\');')
	rows = cur.fetchall()
	for r in rows:
		if r[1] == 'idx_operation':
			print 'In table \"Operation\", index \"idx_operation\" already exists.'
			cur.close()
			return
	print 'Creating index \"idx_operation\" for \"Operation\" on (label)'
	cur.execute('CREATE INDEX idx_operation ON Operation (label)')
	cur.close()


def load_metadata(conn, configs):
	mdfile = configs['metadatafile']
	print 'Using metadata from \"%s\"...' % mdfile

	print 'Begin loading metadata for %s...' % configs['hostname']
	print '='*80
	tic = time.time()

	create_index_for_principal(conn)
	create_index_for_resource(conn)
	create_index_for_operation(conn)


	with open(mdfile, 'r+b') as f:
		map = mmap.mmap(f.fileno(), 0)
		line = map.readline()
		while line:
			m = line.split('|')
			fullpath = m[0]
			fileext = m[1]
			nfileext = int(m[2]) # unused
			filetype = m[3]
			nfiletype = int(m[4]) # unused
			mode = ctypes.c_int32(int(m[5])).value
			uid = ctypes.c_int32(int(m[6])).value
			gid = ctypes.c_int32(int(m[7])).value

			# Skip entries for which we don't have info.
			if mode == -1 or uid == -1 or mode == -1:
				line = map.readline()
				continue

			cur = conn.cursor()
			cur.execute('BEGIN TRANSACTION')
			#cur.close()

			req_perm = AuditdReqPerm(None, cur)
			rsrc = AuditdResource( None, cur, path=fullpath, rid=None )
			if rsrc.rid != None:
				tyid = AuditdType( None, cur,
											 fullpath if 'directory' in filetype.lower() \
											 else os.path.dirname(fullpath),
											 filetype ).get_tyid()
				rsrc.update( tyid, fileext, uid, gid, mode )
				req_perm.compute(rsrc)
				#rsrc.compute_actors( shadow=False )

			#cur = conn.cursor()
			#cur.execute('END TRANSACTION')
			cur.close()
			conn.commit()

			line = map.readline()
		map.close()

	toc = time.time()
	print '='*80
	elapsed = toc - tic
	print 'Done loading metadata for %s. Took %f seconds.' \
			% (configs['hostname'], elapsed)

#------------------------------------------------------------------------------
# Returns list of valid resources.
#------------------------------------------------------------------------------
def get_valid_rsrcs(conn, cur):
	rsrcs = []
	sql = 'SELECT `rid`, `path`, `uid`, `gid`, `mode` FROM `Resource`'
	if conn != None:
		cur = conn.cursor()
	cur.execute(sql)
	row = cur.fetchone()
	while row:
		rid = row[0]
		path = row[1]
		uid = row[2]
		gid = row[3]
		mode = row[4]
		if rid != None and path != None \
		 and uid != None and gid != None and mode != None:
			rsrc = AuditdResource( conn, cur, rid, path,	uid, gid, mode )
			rsrcs.append(rsrc)
		row = cur.fetchone()
	if conn != None:
		cur.close()
	return rsrcs


def load_configs(conn, configs, cfg_parser):
	print 'Begin loading configs for %s...' % configs['hostname']
	print '='*80
	tic = time.time()

	cur = conn.cursor()
	cur.execute('BEGIN TRANSACTION')
	rsrcs = get_valid_rsrcs(None, cur)
	# For each resource...
	for rsrc in rsrcs:
		rsrc.load_configs()
	cur.close()
	conn.commit()

	toc = time.time()
	print '='*80
	elapsed = toc - tic
	print 'Done loading configs for %s. Took %f seconds.' \
			% (configs['hostname'], elapsed)


def compute_grperms(conn, configs):
	print 'Begin computing GrPerm for %s...' % configs['hostname']
	print '='*80
	tic = time.time()

	cur = conn.cursor()
	cur.execute('BEGIN TRANSACTION')
	c2p = AuditdConfigs2Perms(None, cur)
	rsrcs = get_valid_rsrcs(None, cur)
	for rsrc in rsrcs:
		c2p.compute_grperms( rsrc, new=False )
	cur.close()
	conn.commit()

	toc = time.time()
	print '='*80
	elapsed = toc - tic
	print 'Done computing GrPerm for %s. Took %f seconds.' \
			% (configs['hostname'], elapsed)

def restrict_auto(conn, configs):
	print 'Begin restricting config (auto) for %s...' % configs['hostname']
	print '='*80
	tic = time.time()

	cur = conn.cursor()
	cur.execute('BEGIN TRANSACTION')
	restrictor = AuditdConfigRestrictor(None, cur)
	rsrcs = get_valid_rsrcs(None, cur)
	for rsrc in rsrcs:
		restrictor.restrict_auto( rsrc )
	cur.close()
	conn.commit()

	toc = time.time()
	print '='*80
	elapsed = toc - tic
	print 'Done restricting config (auto) for %s. Took %f seconds.' \
			% (configs['hostname'], elapsed)

