# SysCam
 monitor network traffic and pulls suspected file(s) that connecting to specific server
## usage
 install SystemTap
 sudo stap -e 'probe netfilter.ip.local_out{ printf("%d><%s><%s><%s\n", pid(), daddr, cmdline_str(), data_hex)}' | python syscam.py

## todo
 sysdig support
 add webserver to monitor traffic and download suspected files
