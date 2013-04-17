#!/usr/bin/env python

''' Reads files from a list, and gets the filetype.
Appends filetype to entry and writes to output file.
'''
import os
import sys
import getopt
import magic
import stat
import string
import subprocess


def simplify_file_type(filetype):
	''' Removes overly specific information in file types.
	'''

	filetype = filetype.split(',')[0]
	filters = ["symbolic link", "DBase 3 data file", "gzip compressed data", \
						"PNG image data", "GIF image data", "TDB database version 6", \
						"timezone data", "MS Windows icon resource"]
	for f in filters:
		if filetype.startswith(f):
			return f
		
	return filetype

def get_filetype(filename):
	filetype = str(m.file( filename )).replace('\"', '')
	filetype = simplify_file_type(filetype)
	return filetype

def get_counts(path):
	''' Returns two dictionaries for files in path:
		1. Count of each filetype
		2. Count of each extension
	'''
	dicts = ({}, {})
	try:
		filelist = os.listdir(path)
		for f in filelist:
			p = os.path.join(path, f)
			ft = get_filetype(p)
			if ft in dicts[0]:
				dicts[0][ft] += 1
			else:
				dicts[0][ft] = 1

			e = os.path.splitext(f)[1]
			if e in dicts[1]:
				dicts[1][e] += 1
			else:
				dicts[1][e] = 1
	except OSError:
		pass
	return dicts

def print_usage():
	print 'Usage: %s -i <infile> -o <outfile>' % sys.argv[0]

if __name__ == '__main__':
	infilename = None
	outfilename = None
	
	opts, args = getopt.getopt(sys.argv[1:], 'i:o:')

	for o, a in opts:
		if o in ('-i'):
			infilename = a
		elif o in ('-o'):
			outfilename = a
		else:
			assert False, 'Unknown option \"%s\"' % o

	if infilename == None or outfilename == None:
		print_usage()
		sys.exit(0)
		
	pathinfo = {}

	m = magic.open(magic.MAGIC_NONE)
	m.load()
	infile = open(infilename, 'r')
	outfile = open(outfilename, 'w')
	line = infile.readline().rstrip('\n')
	while line != '':
		
		mode = 0xffffffff
		uid = 0xffffffff
		gid = 0xffffffff
		try:
			st = os.stat(line)
			mode = st.st_mode
			uid = st.st_uid
			gid = st.st_gid
		except OSError:
			pass
		
		filepath = os.path.split(line)[0]
		if filepath not in pathinfo:
			pathinfo[filepath] = get_counts(filepath)
	
		filetype = get_filetype(line)
		fileext = os.path.splitext(line)[1]

		filetype_count = -1
		if filetype in pathinfo[filepath][0]:
			filetype_count = pathinfo[filepath][0][filetype]

		fileext_count = -1
		if fileext in pathinfo[filepath][1]:
			fileext_count = pathinfo[filepath][1][fileext]

		outfile.write(line + '|' + \
								fileext + '|' + \
								str(fileext_count) + '|' + \
								filetype + '|' + \
								str(filetype_count) + '|' + \
								str(mode) + '|' + \
								str(uid) + '|' + str(gid) + '\n')
		line = infile.readline().rstrip('\n')

	m.close()
	infile.close()
	outfile.close()
