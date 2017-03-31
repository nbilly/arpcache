# Author: Nicolas Billy (nbilly@paloaltonetworks.com)
# Senior TAC engineer - Palo Alto Networks - March 2017
# Made for case 00623240

import re

active_log="active.log"
output_cache=".output_cache.log"
output_tiger=".output_tiger.log"
i_count_cache = 0
i_count_tiger = 0

f_active = open(active_log, "r")
f_cache = open(output_cache, "w")
f_tiger = open(output_tiger, "w")

p_1 = "ethernet\d+/\d+\.?\d*\s*([0-9]*\.){3}[0-9]*\s*([a-f0-9]{2}:){5}[a-f0-9]{2}"
p_2 = "\d+\s*([a-f0-9]+:){5}[a-f0-9]{2}\s*([a-f0-9]+:){5}[a-f0-9]\s*\d+\s*.\s*.\s*.\s*\d+\s*\d+\s*\d"
re_cache = re.compile(p_1)
re_tiger = re.compile(p_2)

for record in f_active:
	result = re_cache.search(record)
	if result:
		i_count_cache+=1
		f_cache.write(result.group(0)+'\n')
	else:
		result = re_tiger.search(record)
			if result:
				i_count_tiger+=1
				f_tiger.write(result.group(0)+'\n')
		

print "number of entries in cache: ",i_count_cache," - tiger: ",icount_tiger
f_active.close()
f_cache.close()
f_tiger.close()

	