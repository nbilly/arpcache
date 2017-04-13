# Author: Nicolas Billy (nbilly@paloaltonetworks.com)
# Senior TAC engineer - Palo Alto Networks - March 2017
# Made for case 00623240

import re
import os
import string
import random
from collections import defaultdict

def id_generator(size=6, chars=string.ascii_lowercase + string.digits):
	return ''.join(random.choice(chars) for _ in range(size))

#dict_tiger:
#key: MAC address
#[0]: Interface
#[1]...[x]: vlan tag

#dict_cache:
#key: MAC address
#[0]...[x]: ip address

def processing_log(filename,dict_cache, dict_tiger,debug):
	
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
			l_result=result.group(0).split()	
			dict_cache[l_result[2]].append(l_result[1])			
			if debug:
				f_debug_cache.write(result.group(0)+'\n')
		else:
			result = re_tiger.search(record)
			if result:
				i_count_tiger+=1
				l_result=result.group(0).split()
				if not dict_tiger.has_key(l_result[2]):
					dict_tiger[l_result[2]].append(l_result[8])
					dict_tiger[l_result[2]].append(l_result[3])
				else:
					dict_tiger[l_result[2]].append(l_result[3])
				
				if debug:
					f_debug_tiger.write(result.group(0)+'\n')				
	if debug:
		f_debug_tiger.close()
		f_debug_cache.close()
		
	f_current.close()
	print "number of entries in cache: ",i_count_cache," - tiger: ",i_count_tiger
	
#Main

active_log="active.log"
passive_log="passive.log"


dict_cache_active=defaultdict(list)
dict_tiger_active=defaultdict(list)

dict_cache_passive=defaultdict(list)
dict_tiger_passive=defaultdict(list)


print "Active Firewall processing"
print
processing_log(active_log,dict_cache_active,dict_tiger_active,0)
print len(dict_cache_active), " Different MAC addresses in Cache"
print len(dict_tiger_active), " Different MAC addresses in Tiger"
print
print "Passive Firewall processsing"
print
processing_log(passive_log,dict_cache_passive,dict_tiger_passive,0)
print len(dict_cache_passive), " Different MAC addresses in Cache"
print len(dict_tiger_passive), " Different MAC addresses in Tiger"


	