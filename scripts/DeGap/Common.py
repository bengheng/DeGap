import sqlite3

#------------------------------------------------------------------------------
# Returns id if it exists (as queried using sql), otherwise returns None.
#------------------------------------------------------------------------------
def get_helper( conn, cur, sql ):
	id = None
	if conn != None:
		cur = conn.cursor()
	cur.execute( sql )
	row = cur.fetchone()
	if row != None:
		id = int(row[0])
	if conn != None:
		cur.close()
	return id


#------------------------------------------------------------------------------
# Executes the sql to update the db.
#------------------------------------------------------------------------------
def update_helper( conn, cur, sql ):
	if conn != None:
		cur = conn.cursor()
	cur.execute( sql )
	lrid = cur.lastrowid
	if conn != None:
		cur.close()
		conn.commit()
	return lrid


#------------------------------------------------------------------------------
# Update helper that first checks if the id exists using sel_sql.
# If not, insert using ins_sql.
#------------------------------------------------------------------------------
def update_or_get_helper( conn, cur, sel_sql, ins_sql, upd_sql=None ):
	id = get_helper( conn, cur, sel_sql )
	if id != None:
		if upd_sql != None:
			update_helper( conn, cur, upd_sql )
		return id
	if conn != None:
		cur = conn.cursor()
	cur.execute( ins_sql )
	id = cur.lastrowid
	if conn != None:
		cur.close()
		conn.commit()
	return id


#------------------------------------------------------------------------------
# Fetches all tuples.
#------------------------------------------------------------------------------
def fetchall( conn, cur, sql ):
	if conn != None:
		cur = conn.cursor()
	cur.execute( sql )
	rows = cur.fetchall()
	if conn != None:
		cur.close()
	return rows

#------------------------------------------------------------------------------
# Formats string value for sql query.
#------------------------------------------------------------------------------
def prep_query_str( v ):
	return ' IS NULL' if v is None else '=\"%s\"' % v

#------------------------------------------------------------------------------
# Formats integer value for sql query.
#------------------------------------------------------------------------------
def prep_query_int( v ):
	return ' IS NULL' if v is None else '=%d' % v

#------------------------------------------------------------------------------
# Formats string for sql insert.
#------------------------------------------------------------------------------
def prep_ins_str( v ):
	return 'NULL' if v == None else '\"%s\"' % v

#------------------------------------------------------------------------------
# Formats integer for sql insert.
#------------------------------------------------------------------------------
def prep_ins_int( v ):
	return 'NULL' if v == None else '%d' % v



