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
		print "number of entries in cache: ",i_count_cache," - tiger: ",i_count_tiger
		f_debug_tiger.close()
		f_debug_cache.close()
		
	f_current.close()
	
	
#Main

active_log="active.log"
passive_log="passive.log"
b_diff=0

dict_cache_active=defaultdict(list)
dict_tiger_active=defaultdict(list)

dict_cache_passive=defaultdict(list)
dict_tiger_passive=defaultdict(list)


print "#Active Firewall"
print
processing_log(active_log,dict_cache_active,dict_tiger_active,0)
print len(dict_cache_active), " Different MAC addresses in ARP Table"
print len(dict_tiger_active), " Different MAC addresses in Tiger Table"

# Invalid test as Tiger and Arp does not have similar MAC address notation
#for t_key in dict_cache_active.keys():
#	if t_key not in dict_tiger_active.keys():
#for t_key in dict_tiger_active.keys():
#	if t_key not in dict_cache_active.keys():
#		print t_key, " not in arp table but in Tiger"	

print
print "#Passive Firewall"
print
processing_log(passive_log,dict_cache_passive,dict_tiger_passive,0)
print len(dict_cache_passive), " Different MAC addresses in ARP Tache"
print len(dict_tiger_passive), " Different MAC addresses in Tiger Table"

# Invalid test  as Tiger and Arp does not have similar MAC address notation
#for t_key in dict_cache_passive.keys():
#	if t_key not in dict_tiger_passive.keys():
#		print t_key," not in Tiger but in arp table"
#for t_key in dict_tiger_passive.keys():
#	if t_key not in dict_cache_passive.keys():
#		print t_key, " not in arp table but in Tiger"

print
print "#Consistency Checks Between Active and Passive node"
print
print "ARP Tables:"
print "==========="

active_keys= dict_cache_active.keys()
passive_keys= dict_cache_passive.keys()
active_keys.sort()
passive_keys.sort()

# Check on Arp Tables sizes and differences
if len(active_keys)==len(passive_keys):
	print "ARP tables have same size"
	if cmp(active_keys,passive_keys)==0:
		print "ARP tables have identical MAC list"
	else:
		b_diff=1
elif len(active_keys)>len(passive_keys):
	print "ARP table on Active is bigger"
	b_diff=1
elif len(active_keys)<len(passive_keys):
	print "ARP table on Passive is bigger"
	b_diff=1

if b_diff:
	print "Entries not in Passive"	
	for t_key in active_keys:
		if t_key not in passive_keys:
			print t_key," : ", dict_cache_active[t_key]
	print "Entries not in Active"
	for t_key in passive_keys:
		if t_key not in active_keys:
			print t_key," : ", dict_cache_passive[t_key]
#---------------------------------------------------------------#
b_diff=0
print
print "Tiger Tables:"
print "============="
active_keys= dict_tiger_active.keys()
passive_keys= dict_tiger_passive.keys()
active_keys.sort()
passive_keys.sort()

# Check Tiger Tables sizes and differences
if len(active_keys)==len(passive_keys):
	print "Tiger tables have same size"
	if cmp(active_keys,passive_keys)==0:
		print "Tiger tables have identical MAC list"
	else:
		b_diff=1
elif len(active_keys)>len(passive_keys):
	print "Tiger table on Active is bigger"
	b_diff=1
elif len(active_keys)<len(passive_keys):
	print "Tiger table on Passive is bigger"
	b_diff=1

if b_diff:	
	print "Entries not in Passive"	
	for t_key in active_keys:
		if t_key not in passive_keys:
			print t_key," : ", dict_tiger_active[t_key]

	print "Entries not in Active"
	for t_key in passive_keys:
			if t_key not in active_keys:
				print t_key," : ", dict_tiger_passive[t_key]