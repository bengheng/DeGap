import os
import sys
sys.path.append(os.path.realpath(os.path.join(sys.path[0], '../../')))
from Degap.Common import *
from Degap.Config import *


#------------------------------------------------------------------------------
# Get oplable for specified goid. Mostly for printing friendly messages.
#------------------------------------------------------------------------------
def get_oplabel_for_goid( conn, cur, goid ):
	sql = 'SELECT `method`, `protocol` FROM `OpLabel` '\
			'INNER JOIN `GrOp` ON (`GrOp`.`olid`=`OpLabel`.`olid`) '\
			'WHERE `GrOp`.`goid`=%d' % goid
	results = fetchall( conn, cur, sql )	
	return (results[0][0], results[0][1])

def get_user_for_aid( conn, cur, aid ):
	sql = 'SELECT `user` FROM `Actor` WHERE `aid`=%d' % aid
	results = fetchall( conn, cur, sql )
	return results[0][0]


