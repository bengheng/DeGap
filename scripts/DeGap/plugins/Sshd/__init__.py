import os
import sys
import mmap
import time
import ctypes
import ConfigParser

from plugins.Sshd.SshdResource import *
from plugins.Sshd.SshdParser import *
from plugins.Sshd.SshdConfigs2Perms import *
from plugins.Sshd.SshdConfigRestrictor import *


def init():
	print('Using \"Sshd\" plugin.')

def parse_logs(conn, configs):
	print 'Parsing logs...'

	print 'Begin parsing logs for %s...' % configs['hostname']
	print '='*80
	tic = time.time()

	rsrc = SshdResource( conn, None, rid=None, hostname=configs['hostname'] )
	parser = SshdParser(conn, None, rsrc)
	parser.parse(configs['inlog'])

	toc = time.time()
	print '='*80
	elapsed = toc - tic
	print 'Done parsing logs for %s. Took %f seconds.' \
			% (configs['hostname'], elapsed)

def load_metadata(conn, configs):
	print 'No metadata to load for Sshd.'


def load_configs(conn, configs, cfg_parser):
	print 'Begin loading configs for %s...' % configs['hostname']
	print '='*80
	tic = time.time()

	rsrc = SshdResource(conn, None, rid=None, hostname=configs['hostname'])
	rsrc.load_config(configs, cfg_parser)

	toc = time.time()
	print '='*80
	elapsed = toc - tic
	print 'Done loading configs for %s. Took %f seconds.' \
			% (configs['hostname'], elapsed)

def compute_grperms(conn, configs):
	print 'Begin computing GrPerm for %s...' % configs['hostname']
	print '='*80
	tic = time.time()

	c2p = SshdConfigs2Perms(conn, None)
	rsrc = SshdResource(conn, None, rid=None, hostname=configs['hostname'])
	c2p.compute_grperms( rsrc, new=False )

	toc = time.time()
	print '='*80
	elapsed = toc - tic
	print 'Done computing GrPerm for %s. Took %f seconds.' \
			% (configs['hostname'], elapsed)

def restrict_auto(conn, configs):
	print 'Begin restricting config (auto) for %s...' % configs['hostname']
	print '='*80
	tic = time.time()

	restrictor = SshdConfigRestrictor(conn, None)
	rsrc = SshdResource(conn, None, rid=None, hostname=configs['hostname'])
	restrictor.restrict_auto( rsrc )

	toc = time.time()
	print '='*80
	elapsed = toc - tic
	print 'Done restricting config (auto) for %s. Took %f seconds.' \
			% (configs['hostname'], elapsed)


def restrict_step(conn, configs):
	print 'Begin restricting config (step) for %s...' % configs['hostname']
	print '='*80
	tic = time.time()

	restrictor = SshdConfigRestrictor(conn, None)
	rsrc = SshdResource(conn, None, rid=None, hostname=configs['hostname'])
	restrictor.restrict_step( rsrc )

	toc = time.time()
	print '='*80
	elapsed = toc - tic
	print 'Done restricting config (auto) for %s. Took %f seconds.' \
			% (configs['hostname'], elapsed)

