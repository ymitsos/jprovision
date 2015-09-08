#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
A python script that uses junos-eznc and consequently ncclient and
NETCONF to push massively configuration, read from a file, to a number
of Juniper equipment. Results are tracked in log file.

Usage:
jprovision.py --hosts hosts_file.txt --log=DEBUG -c config_file.cli

'''
# Authors: {ymitsos,mmamalis}_at_noc_dot_grnet_dot_gr

import os
import sys
import argparse
import getpass
import logging
import subprocess
# import re
from jnpr.junos import Device
from jnpr.junos.utils.config import Config
import jnpr.junos.exception
from termcolor import colored
from IPy import IP

SUCCESSFUL = 0
CONNECTION_FAILED = 1
UNABLE_TO_LOCK = 2
COMMIT_FAILED_WARNING = 3
COMMIT_FAILED_ERROR = 4
COMMIT_ABORTED = 5

def provision(host, **kwargs):

    #host = kwargs['host']
    username = kwargs['username']
    password = kwargs['password']
    port = kwargs['port']
    compareconfig = kwargs['compareconfig']
    configuration = kwargs['configuration']
    waitconfirm = kwargs[b'waitconfirm']

    print colored("-------------------------------------------------------------------------------\n", 'yellow')
    print colored("Start committing configuration to: ", "cyan") + colored("%s" % host['address'], "yellow")
    logging.info("Start committing configuration to %s" % host['address'])

    dev = Device(host=host['address'],
                 username=username,
                 password=password,
                 port=port,
                 timeout=5,
                 device_params={'name':'junos'},
                 hostkey_verify=False)
    try:
        logging.info("Connecting to %s" % host)
        #logging.debug("Connecting to %s" % host)
        dev.open()
    except jnpr.junos.exception.ConnectAuthError as err:
        logging.info("Wrong username or password while connecting to %s." % host['address'])
        print colored("Wrong username or password while connecting to %s." ,"red") % host['address']
        host['status'] = CONNECTION_FAILED
        return
    except jnpr.junos.exception.ConnectUnknownHostError as err:
        logging.info("Wrong hostname: %s." % host['address'])
        print "Host: " + colored("%s" % host['address'], "red") + " not found. Wrong FQDN?"
        host['status'] = CONNECTION_FAILED
        return
    except jnpr.junos.exception.ConnectRefusedError as err:
        logging.info("NETCONF session to %s failed." % host['address'])
        print "Host: " + colored('NETCONF session to %s failed', 'red') % host['address']
        host['status'] = CONNECTION_FAILED
        return
    except jnpr.junos.exception.ConnectTimeoutError as err:
        logging.info("Time-out error. Could not open socket to: %s." % host['address'])
        print "Time-out error. Could not open socket to : " + colored("%s" % host['address'], "red")
        host['status'] = CONNECTION_FAILED
        return

    #Create an instance of Config
    cu = Config(dev)
    logging.debug("Acquiring lock to %s." % host)

    #lock the device
    try:
        cu.lock()
    except jnpr.junos.exception.LockError as err:
        logging.info("Error: unable to lock configuration in %s." % host['address'])
        print colored("Error: unable to lock configuration in %s", "red") % host['address']
        host['status'] = UNABLE_TO_LOCK
        dev.close()
        return

    #parse configuration file and load commands. Handle exceptions accordingly
    for line in configuration:
        if line[0] != '#':
            logging.debug("Loading command: %s in %s " % (line.rstrip('\n'), host['address']))
            try:
                cu.load(line, format="set", merge=False)
            except jnpr.junos.exception.ConfigLoadError as err:
                logging.info("Failed loading command '%s' with severity %s in %s." %  (line.rstrip('\n'), err.errs['severity'], host['address']))
                print colored("Loading command failed with severity: %s", 'red') % err.errs['severity']
                host['status'] = COMMIT_FAILED_WARNING
                if err.errs['severity'] == 'error':
                    cu.rollback()
                    logging.info("Commit failed. Rolling back in %s and exiting the script" % host['address'])
                    logging.debug("Commit failed with %s rolling back in %s" % (err, host['address']))
                    print colored("Exiting, configuration rolled-back", "red")
                    host['status'] = COMMIT_FAILED_ERROR
                    cu.unlock()
                    dev.close()
                    sys.exit(1)

    #print "show|compare" results to stdout if requested
    if compareconfig != 'true':
        print colored("\n'show | compare' output:", 'blue')
        print cu.diff()

    if waitconfirm == b'true':
        if kwargs['first_host'] == b'true':
            ack = raw_input('Proceed with commiting? [y/n]: ')
        else:
            ack = 'yes'
    else:
        ack = 'yes'

    if ack == 'y' or ack == 'yes':
        try:
            cu.commit(comment="This is netconf jprovision script")
            logging.info("Committing to %s succeded." % host['address'])
            logging.debug("Committing to %s succeded." % host['address'])
            print colored("Succeeded", "green")
            if not str(host['status']): host['status'] = SUCCESSFUL
        except jnpr.junos.exception.CommitError as err:
            cu.rollback()
            logging.info("Commit failed rolling back in %s" % host['address'])
            logging.debug("Commit failed with %s rolling back in %s" % (err, host['address']))
            print colored("Configuration rolled-back due to commit error",
                "red")
            host['status'] = COMMIT_FAILED_ERROR

    elif ack == 'n' or ack == 'no':
        logging.info("User aborted commiting")
        sys.stdout.write('User aborted, rolling back and exiting.\n')
        cu.rollback()
        host['status'] = COMMIT_ABORTED
        sys.exit(0)

    cu.unlock()
    dev.close()
    logging.info("Finished.")

def main():

    parser = argparse.ArgumentParser(description='Input parameters', epilog='''EXAMPLE:
       jprovision.py -h router.grnet.gr -c config_file_with_commands.cli''', add_help=False, formatter_class=argparse.RawDescriptionHelpFormatter)

    parser.add_argument('--help', dest='printhelp', action='store_true', help="Print help.")
    try:
        # parse (only) --help here, before the "required" params to other flags cause problems
        printhelp = parser.parse_known_args()[0].printhelp
    except AttributeError:
        printhelp = False

    parser.add_argument('-u', '--username', dest='username', action='store', default=os.environ['USER'], help='username to connect to netconf server.')
    parser.add_argument('-p', '--password', dest='password', action='store', help='user\'s password.')
    parser.add_argument('-t', '--target', dest='target', action='store', help='Network device to connect to. Could be a single IP e.g. 127.0.0.1 or a network e.g. 10.0.1.0/24')
    parser.add_argument('--hosts', dest='hostsfile', action='store', help='File with hostnames to apply configuration.')
    parser.add_argument('-c', '--config', dest='configfile', action='store', required=True, help='Configuration file to read.')
    parser.add_argument('--port', dest='port', action='store', help='NETCONF server port.')
    parser.add_argument('--logfile', dest='logfile', action='store', help='File to dump logging output.')
    parser.add_argument('--log', dest='loglevel', action='store', help='Loglevel. Possible values: INFO, DEBUG')
    parser.add_argument('--no-compareconfig', dest='compareconfig', action='store_false', help='Do not display "commit \| compare" in stdin.')
    parser.add_argument('--wait-confirm', dest='waitconfirm', action='store_false', help='Wait for user confirmation after show\|compare')

    if printhelp:
        parser.print_help()
        sys.exit(0)

    args = parser.parse_args()

    if not bool(args.target) != bool(args.hostsfile):
        sys.stdout.write("Either -t or --hosts flag must be defined. Not both.\n")
        sys.exit(1)

    if not (bool(args.compareconfig) or bool(args.waitconfirm)):
        sys.stdout.write("--wait-confirm cannot be used when --no-compareconfig is set.\n")
        sys.exit(1)

    loglevel = args.loglevel or 'info'
    numeric_level = getattr(logging, loglevel.upper(), None)

    if not numeric_level:
        sys.stderr.write("Wrong log level, using INFO instead")
        numeric_level = 20
    logfile = args.logfile or 'jprovision.log'
    logging.basicConfig(filename=logfile, filemode='a', format='%(asctime)s - %(levelname)s - %(message)s', level=numeric_level, datefmt='%Y %B %d %H:%M:%S')
    logging.info("Logging level set to %d." % numeric_level)

    with open(args.configfile, mode='r') as configfile:
        configuration = configfile.readlines()

    logging.info("Parsing hosts list.")
    hosts = []
    if args.hostsfile:
        with open(args.hostsfile, mode='r') as hostsfile:
            for line in hostsfile:
                hosts.append({'address': line.rstrip('\n'), 'status': ''})
    else:
        subnet = IP(args.target)
        print"Starting ping sweep on subnet %s" % subnet
        for i in subnet:
            if i != subnet.broadcast() and i != subnet.net():
                ping_result=subprocess.call("ping -c 1 -n -i 0.5 -W 2 %s" % i,
                    shell=True,
                    stdout=open('/dev/null', 'w'),
                    stderr=subprocess.STDOUT)
                if bool(ping_result) == 0:
                    hosts.append({'address': i, 'status': ''})
                    logging.debug("Adding IP: %s to hosts list" % i)
        print "Found %d hosts alive in subnet %s" % (len(hosts), subnet)

    logging.info("%d hosts found" % len(hosts))

    if not args.port:
        port = 22
    else:
        port = args.port

    if not args.password:
        args.password = getpass.getpass(args.username + '\'s Password:')

    params = {
            'username': args.username,
            'password': args.password,
            'port': port,
            'configuration': configuration,
            'compareconfig': args.compareconfig,
            'waitconfirm': b'false'
            }

    #FALSE
    if not args.waitconfirm:
        params['waitconfirm'] = 'true'
        params['first_host'] = b'true'
        provision (hosts[0], **params)
        params['first_host'] = b'false'
        params['waitconfirm'] = b'false'
        for host in hosts[1:]:
            provision (host, **params)
    else:
        for host in hosts:
            provision (host, **params)

    successful_hosts = []
    connectionfailed_hosts = []
    unablelock_hosts = []
    commit_warning = []
    commit_error = []
    commit_aborted = []

    for host in hosts:
        for key, value in host.items():
            if key == 'status' and value == SUCCESSFUL:
                successful_hosts.append(host)
            if key == 'status' and value == CONNECTION_FAILED:
                connectionfailed_hosts.append(host)
            if key == 'status' and value == UNABLE_TO_LOCK:
                unablelock_hosts.append(host)
            if key == 'status' and value == COMMIT_FAILED_WARNING:
                commit_warning.append(host)
            if key == 'status' and value == COMMIT_FAILED_ERROR:
                commit_error.append(host)
            if key == 'status' and value == COMMIT_ABORTED:
                commit_aborted.append(host)

    print colored("-------------------------------------------------------------------------------\n", 'magenta')
    print colored("Results:", "cyan")
    if len(successful_hosts) > 0:
        print colored("Commited succesfully to %d devices", "green") %len(successful_hosts)
    if len(connectionfailed_hosts) > 0:
        print colored("Connection to %d devices failed", "red") %len(connectionfailed_hosts)
    if len(unablelock_hosts) > 0:
        print colored("Unabled to lock database in %d devices", "red") %len(unablelock_hosts)
    if len(commit_warning) > 0:
        print colored("Commited to %d devices with warning(s)", "yellow") %len(commit_warning)
    if len(commit_error) > 0:
        print colored("Commited to %d devices returned error(s)", "red") %len(commit_error)
    print colored("-------------------------------------------------------------------------------\n", 'magenta')

    sys.exit(0)

logging.getLogger('paramiko').addHandler(logging.NullHandler())

if __name__ == "__main__":
    main()
