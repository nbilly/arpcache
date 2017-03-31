# Author: Nicolas Billy (nbilly@paloaltonetworks.com)
# Senior TAC engineer - Palo Alto Networks - March 2017
# Made for case 00623240

import re
import os
import string
import random

def id_generator(size=6, chars=string.ascii_lowercase + string.digits):
	return ''.join(random.choice(chars) for _ in range(size))

def processing_log(filename, debug):
	
	i_count_cache = 0
	i_count_tiger = 0
	p_1 = "ethernet\d+/\d+\.?\d*\s*([0-9]*\.){3}[0-9]*\s*([a-f0-9]{2}:){5}[a-f0-9]{2}"
	p_2 = "\d+\s*([a-f0-9]+:){5}[a-f0-9]+\s*([a-f0-9]+:){5}[a-f0-9]+\s*\d+\s*.\s*.\s*.\s*\d+\s*\d+\s*\d"
	re_cache = re.compile(p_1)
	re_tiger = re.compile(p_2)
		
	if debug:
		debugfile_tiger="."+id_generator()+"_tiger.log"
		debugfile_cache="."+id_generator()+"_cache.log"
		f_debug_tiger = open(debugfile_tiger,"w")
		f_debug_cache = open(debugfile_cache,"w")
	
	f_current = open(filename, "r")
	
	for record in f_current:
		result = re_cache.search(record)
		if result:
			i_count_cache+=1
			if debug:
				f_debug_cache.write(result.group(0)+'\n')
		else:
			result = re_tiger.search(record)
			if result:
				i_count_tiger+=1
				if debug:
					f_debug_tiger.write(result.group(0)+'\n')
					
	if debug:
		f_debug_tiger.close()
		f_debug_cache.close()
		
	f_current.close()
	print "number of entries in cache: ",i_count_cache," - tiger: ",i_count_tiger
	
#Main
#output_cache=".output_cache.log"
#output_tiger=".output_tiger.log"

active_log="active.log"
passive_log="passive.log"

print "Active Firewall"
print
processing_log(active_log,1)
print
print "Passive Firewall"
print
processing_log(passive_log,1)


	