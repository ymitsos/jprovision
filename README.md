# jprovision
A python script that uses junos-eznc and consequently ncclient and NETCONF to push massively 
configuration, read from a file, to a number of Juniper equipment. Results are tracked in 
log file.

Usage:
jprovision.py --hosts hosts_file.txt --log=DEBUG -c config_file.cli
