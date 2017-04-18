# arpcache
Checking arp table consistency between HA nodes



1. execute following commands on Active and Passive devices and log output in a single file:
```
> show arp all
```
```
> debug dataplane internal pdt tiger egr nexthop dump
```
2. Rename these files into _active.log_ and _passive.log_, corresponding to device the commands have been ran from.
3. These 2 files need to be copied in the same directory of the script
4. Run the script
```
#sudo python arpcheck.py
```
