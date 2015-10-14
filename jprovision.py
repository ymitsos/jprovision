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
import re
import jnpr.junos.exception
import multiprocessing as mp
from pprint import pprint
from jnpr.junos import Device
from jnpr.junos.op.phyport import *
from jnpr.junos.utils.config import Config
from jnpr.junos.utils.scp import SCP
from termcolor import colored
from IPy import IP
from jexceptions import jException

SUCCESSFUL = 0
CONNECTION_FAILED = 1
UNABLE_TO_LOCK = 2
COMMIT_FAILED_WARNING = 3
COMMIT_FAILED_ERROR = 4
COMMIT_ABORTED = 5
FILE_TRANSFER_COMPLETE = 6
FILE_TRANSFER_FAILED = 7

class myDev():

    def __init__(self, hostname=None, port=None, username=None, password=None):
        self.hostname = hostname
        self.port = port
        self.username = username
        self.password = password
        self.jnprdev = Device(host=hostname,
            username=username,
            password=password,
            port=port,
            timeout=5,
            device_params={'name':'junos'},
            hostkey_verify=False)
        self.rpc = self.jnprdev.rpc

    def _open(self):
        try:
            self.jnprdev.open()
        except (jnpr.junos.exception.ConnectAuthError,
                jnpr.junos.exception.ConnectUnknownHostError,
                jnpr.junos.exception.ConnectRefusedError,
                jnpr.junos.exception.ProbeError,
                jnpr.junos.exception.ConnectTimeoutError) as err:
            raise jException(err)

    def open_config(self):
        self._open()
        self.jnprdev.bind(cu=Config)

        try:
            self.jnprdev.cu.lock()
        except jnpr.junos.exception.LockError as err:
            raise jException(err, self.hostname)

    def open_show(self):
        self._open()

    def open_fileupload(self):
        self._open()

    def load_configuration(self, configuration):
        try:
            self.jnprdev.cu.load(configuration, format='set', merge=False)
        except jnpr.junos.exception.ConfigLoadError as err:
            raise jException(err, self.hostname)

    def showcompare(self):
        return self.jnprdev.cu.diff()

    def commit(self, comment):
        try:
            self.jnprdev.cu.commit(comment=comment, sync=True)
        except jnpr.junos.exception.CommitError as err:
            raise jException(err)

    def rollback(self):
        # rolling back current changes only
        self.jnprdev.cu.rollback(rb_id=0)

    def show_cmd(self, command):
        self.jnprdev.cli(command, format='text', warning=True)

    def fileloader(self, package, remotepath):
        with SCP(self.jnprdev) as scp:
            try:
                scp.put(package, remotepath)
            except Exception as err:
                raise jException(err, self.hostname)

    def close(self):
        if hasattr(self.jnprdev, 'cu'):
            self.jnprdev.cu.unlock()
        self.jnprdev.close()

def provision(host, logger, **kwargs):
    compareconfig = kwargs['compareconfig']
    configuration = kwargs['configuration']
    waitconfirm = kwargs[b'waitconfirm']
    print colored('-------------------------------------------------------------------------------\n', 'yellow')
    print colored('Start committing configuration to: ', 'cyan') + colored('%s' % host['address'], 'yellow')
    logger.info('Start committing configuration to %s' % host['address'])

    dv = myDev(hostname=host['address'],
                 username=kwargs['username'],
                 password=kwargs['password'],
                 port=kwargs['port'])

    logger.info('Connecting to %s' % host['address'])

    try:
        dv.open_config()
    except jException as err:
        logging.info(err)
        print colored(err, 'red')
        host['status'] = CONNECTION_FAILED
        return

    try:
        dv.load_configuration(configuration)
    except jException as err:
        logging.info(err)
        print colored(err , 'red')
        print colored('Loading command failed with severity: %s', 'red') % err.errs['severity']
        host['status'] = COMMIT_FAILED_WARNING
        if err.errs['severity'] == 'error':
            dv.rollback()
            logging.info('Commit failed. Rolling back in %s and exiting the script' % host['address'])
            logging.debug('Commit failed with %s rolling back in %s' % (err, host['address']))
            print colored('Exiting, configuration rolled-back', 'red')
            host['status'] = COMMIT_FAILED_ERROR
            dv.close()
            sys.exit(1)

    if compareconfig is True:
        print colored("\n'show | compare' output:", 'blue')
        diff = dv.showcompare()
        print diff

    if waitconfirm == b'true':
        if kwargs['first_host'] == b'true':
            ack = raw_input('Proceed with commiting? [y/n]: ')
        else:
            ack = 'yes'
    else:
        ack = 'yes'

    if ack == 'y' or ack == 'yes':
        try:
            dv.commit(comment='This is netconf jprovision script')
        except jException as err:
            dv.rollback()
            logging.info('Commit failed rolling back in %s' % host['address'])
            logging.debug('Commit failed with %s rolling back in %s' % (err, host['address']))
            print colored('Configuration rolled-back due to commit error', 'red')
            host['status'] = COMMIT_FAILED_ERROR
            return

        logger.info('Committing to %s succeded.' % host['address'])
        print colored('Succeeded', 'green')
        if not str(host['status']): host['status'] = SUCCESSFUL

    elif ack == 'n' or ack == 'no':
        logger.info('User aborted commiting')
        sys.stdout.write('User aborted, rolling back and exiting.\n')
        dv.rollback()
        dv.close()
        host['status'] = COMMIT_ABORTED
        sys.exit(0)

    dv.close()
    logger.info('Finished.')

def fileloader(host, logger, package, remotepath, **kwargs):
    """
    use scp to upload a file to
    a remote host
    """
    print colored("-------------------------------------------------------------------------------\n", 'yellow')
    print colored("Start file transfer to: ", "cyan") + colored("%s" % host['address'], "yellow")
    logging.info("Start file transfer to %s" % host['address'])

    dv = myDev(hostname=host['address'],
                 username=kwargs['username'],
                 password=kwargs['password'],
                 port=kwargs['port'])

    logger.info('Connecting to %s' % host['address'])

    try:
        dv.open_fileupload()
    except jException as err:
        logging.info(err)
        print colored(err, 'red')
        host['status'] = CONNECTION_FAILED
        return

    try:
        dv.fileloader(package, remotepath)
        if not str(host['status']): host['status'] = FILE_TRANSFER_COMPLETE
    except jException as err:
        logging.info(err)
        print colored(err, 'red')
        host['status'] = FILE_TRANSFER_FAILED

    dv.close()
    logger.info('Finished.')

def pinger(jobq, resultsq, failedq):
    """
    send one ICMP request to each host
    in subnet and record output to Queue
    """
    for ip in iter(jobq.get, None):
        try:
            pinging = subprocess.call(['ping', '-n', '-c1', '-W1', ip],
                stdout=open('/dev/null', 'w'),
                stderr=subprocess.STDOUT)
            if pinging == 0:
                resultsq.put(ip)
            else:
                failedq.put(ip)
        except:
            pass

def sort_ip_list(failed):
    """
    sort ip addresses that failed to respond to icmp request
    """
    iplist = [(IP(ip).int(), ip) for ip in failed]
    iplist.sort()
    return [ip[1] for ip in iplist]

def main():

    parser = argparse.ArgumentParser(description='Input parameters', epilog='''EXAMPLE:
       jprovision.py -h router.grnet.gr -c config_file_with_commands.cli''', add_help=False, formatter_class=argparse.RawDescriptionHelpFormatter)

    parser.add_argument('--help', dest='printhelp', action='store_true', help='Print help.')
    try:
        # parse (only) --help here, before the 'required' params to other flags cause problems
        printhelp = parser.parse_known_args()[0].printhelp
    except AttributeError:
        printhelp = False

    parser.add_argument('-u', '--username', dest='username', action='store', default=os.environ['USER'], help='username to connect to netconf server.')
    parser.add_argument('-p', '--password', dest='password', action='store', help='user\'s password.')
    parser.add_argument('-t', '--target', dest='target', action='store', help='Network device to connect to. Could be a single IP e.g. 127.0.0.1 or a network e.g. 10.0.1.0/24')
    parser.add_argument('--hosts', dest='hostsfile', action='store', help='File with hostnames to apply configuration.')
    parser.add_argument('-c', '--config', dest='configfile', action='store', required=False, help='Configuration file to read.')
    parser.add_argument('--port', dest='port', action='store', help='NETCONF server port.')
    parser.add_argument('--logfile', dest='logfile', action='store', help='File to dump logging output.')
    parser.add_argument('--log', dest='loglevel', action='store', help='Loglevel. Possible values: INFO, DEBUG')
    parser.add_argument('--no-compareconfig', dest='compareconfig', action='store_false', help='Do not display "commit \| compare" in stdin.')
    parser.add_argument('--wait-confirm', dest='waitconfirm', action='store_false', help='Wait for user confirmation after show\|compare')
    parser.add_argument('--package', dest='package', action='store', help='File to be loaded to device via SCP')
    parser.add_argument('--remotepath', dest='remotepath', action='store', help='Remote path for file load via SCP')

    if printhelp:
        parser.print_help()
        sys.exit(0)

    args = parser.parse_args()

    if not args.configfile:
        if not (args.package or args.remotepath):
            sys.stdout.write("""
                Either input --config flag 
                or --package (with) --remotepath flags
                or --help for help\n
                """)
            sys.exit(1)

    if not bool(args.target) != bool(args.hostsfile):
        sys.stdout.write('Either -t or --hosts flag must be defined. Not both.\n')
        sys.exit(1)

    if not (bool(args.compareconfig) or bool(args.waitconfirm)):
        sys.stdout.write('--wait-confirm cannot be used when --no-compareconfig is set.\n')
        sys.exit(1)

    loglevel = args.loglevel or 'info'
    numeric_level = getattr(logging, loglevel.upper(), None)

    if not numeric_level:
        sys.stderr.write('Wrong log level, using INFO instead')
        numeric_level = 20
    logfile = args.logfile or 'jprovision.log'
    logging.basicConfig(filename=logfile, filemode='a', format='%(asctime)s - %(name)s - %(levelname)s - %(message)s', level=numeric_level, datefmt='%Y %B %d %H:%M:%S')
    logger = logging.getLogger('jprovision')
    logger.info('Logging level set to %d.' % numeric_level)

    logger.info('Parsing hosts list.')
    hosts = []
    failedhosts = []
    if args.hostsfile:
        with open(args.hostsfile, mode='r') as hostsfile:
            for line in hostsfile:
                trim = line.strip()
                hosts.append({'address': trim.rstrip('\n'), 'status': ''})
    else:
        subnet = IP(args.target)
        try:
            if len(subnet) == 1:
                print'Sending icmp request to host %s' % subnet
                ping_result = subprocess.call('ping -c 1 -n -W 1 %s' % subnet,
                    shell=True,
                    stdout=open('/dev/null', 'w'),
                    stderr=subprocess.STDOUT)
                if ping_result == 0:
                    hosts.append({'address': str(subnet), 'status': ''})
                    print colored("Host %s is responding to icmp request" % subnet, 'green')
                    logging.debug('Adding IP: %s to hosts list' % subnet)
                else:
                    print colored("Host %s is not responding to icmp request" % subnet, 'red')
                    logging.info("Host %s is not responding to icmp request" % subnet)
                    sys.exit(1)
            else:
                print'Starting ping sweep on subnet %s' % subnet
                jobs = mp.Queue()
                results = mp.Queue()
                failed = mp.Queue()
                pool_size = len(subnet)
                procs_pool = [mp.Process(target=pinger,
                    args=(jobs, results, failed)) for i in range(pool_size)]

                for i in subnet:
                    ip = str(i)
                    jobs.put(ip)
                for p in procs_pool:
                    p.start()
                for p in procs_pool:
                    jobs.put(None)
                for p in procs_pool:
                    p.join()

                while not results.empty():
                    i = results.get()
                    hosts.append({'address': str(i), 'status': ''})
                    logging.debug('Adding IP: %s to hosts list' % i)
                while not failed.empty():
                    i = failed.get()
                    failedhosts.append(i)
                    logging.debug('Adding IP: %s to failedhosts list' % i)

                failed_sorted = sort_ip_list(failedhosts)

                with open('no_icmp_response.txt', 'w+') as f:
                    for ipaddr in failed_sorted:
                        f.write("%s\n" % ipaddr)

                print colored('Found %d hosts alive in subnet %s', 'green') % (len(hosts), subnet)
                print colored('No icmp reply from %d hosts in subnet %s (please see no_icmp_response.txt file)', 'yellow') % (len(failedhosts), subnet)
        except ValueError as err:
            logging.info(err)
            print colored(err, 'red')
            sys.exit(1)

    logger.info('%d hosts found' % len(hosts))

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
            'compareconfig': args.compareconfig,
            'waitconfirm': b'false'
            }

    if args.configfile:
        logger.debug('Opening configfile %s.' % args.configfile)
        with open(args.configfile, mode='r') as configfile:
            configuration = configfile.read()
        params['configuration'] = configuration
        if not args.waitconfirm:
            params['waitconfirm'] = 'true'
            params['first_host'] = b'true'
            provision (hosts[0], logger, **params)
            params['first_host'] = b'false'
            params['waitconfirm'] = b'false'
            for host in hosts[1:]:
                provision (host, logger, **params)
        else:
            for host in hosts:
                provision (host, logger, **params)
    elif args.package and args.remotepath:
        for host in hosts:
            fileloader(host, logger, args.package, args.remotepath, **params)
    else:
        sys.stderr.write("Shouldn't reach this point\n")
        sys.exit(1)

    successful_hosts = []
    connectionfailed_hosts = []
    unablelock_hosts = []
    commit_warning = []
    commit_error = []
    commit_aborted = []
    ftransfer_complete = []
    ftransfer_fail = []

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
            if key == 'status' and value == FILE_TRANSFER_COMPLETE:
                ftransfer_complete.append(host)
            if key == 'status' and value == FILE_TRANSFER_FAILED:
                ftransfer_fail.append(host)

    print colored("-------------------------------------------------------------------------------\n", 'magenta')
    print colored("Results:", "cyan")
    if len(successful_hosts) > 0:
        print colored("Commited succesfully to %d devices", "green") % len(successful_hosts)
    if len(connectionfailed_hosts) > 0:
        print colored("Connection to %d devices failed", "red") % len(connectionfailed_hosts)
    if len(unablelock_hosts) > 0:
        print colored("Unabled to lock database in %d devices", "red") % len(unablelock_hosts)
    if len(commit_warning) > 0:
        print colored("Commited to %d devices with warning(s)", "yellow") % len(commit_warning)
    if len(commit_error) > 0:
        print colored("Commited to %d devices returned error(s)", "red") % len(commit_error)
    if len(ftransfer_complete) > 0:
        print colored("File transfer completed successfully to %d devices", "green") % len(ftransfer_complete)
    if len(ftransfer_fail) > 0:
        print colored("File transfer failed to %d devices", "red") % len(ftransfer_fail)
    print colored("-------------------------------------------------------------------------------\n", 'magenta')

    #dump results to file
    regex = re.compile('[\w.-]+grnet[\w.-]+')
    with open('failedhosts.txt', 'w+') as f:
        for i in range(len(connectionfailed_hosts)):
            match = regex.search(connectionfailed_hosts[i]['address'])
            if match:
                f.write("%s\n" % match.group())

    sys.exit(0)

logging.getLogger('paramiko').addHandler(logging.NullHandler())
Device.auto_probe = 2

if __name__ == '__main__':
    main()