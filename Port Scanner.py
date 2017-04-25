#! /usr/bin/env python
#! -*- coding : utf -8 -*-

import nmap

ip1 = raw_input("Site IP = ")

nm = nmap.PortScanner()
host = ip1
nm.scan(host, '1-1024')
nm.command_line()
nm.scaninfo()

for host in nm.all_hosts():
    print 'Host : %s (%s)' % (host, nm[host].hostname())
    print 'State : %s' % nm[host].state()
    
for proto in nm[host].all_protocols():
    print 'Protocol : %s' % proto
    print '------------------'

lport = nm[host]['tcp'].keys()
lport.sort()
for port in lport:
    print 'port : %s\tstate : %s\tservice : %s\tversion  : %s ' % (port, nm[host][proto][port]['state'],nm[host][proto][port]['name'],nm[host][proto][port]['product'])
    den = 'port : %s\tstate : %s\tservice : %s\tversion  : %s  \n  <br/> ' % (port, nm[host][proto][port]['state'],nm[host][proto][port]['name'],nm[host][proto][port]['product'])
    a = open("kaydet2.html","a+")
    a.writelines(den)


 