# SysCam
 monitor network traffic and pulls suspected file(s) that connecting to specific server
## usage
 $ sudo apt-get install systemtap   
 $ pip install requests
 $ sudo stap-prep
 $ sudo stap -e 'probe netfilter.ip.local_out{ printf("%d><%s><%s><%s\n", pid(), daddr, cmdline_str(), data_hex)}' | python syscam.py -d www.exampie.com test.com  
 

## todo
 sysdig support  
 add webserver to download suspected files
