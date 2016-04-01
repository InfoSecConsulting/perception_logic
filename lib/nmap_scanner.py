from subprocess import Popen, PIPE
from os import mkdir, devnull, system
from time import sleep
from re import match
from lib.db_connector import connect
from models.db_tables import LocalHost
import sys

"""Connect to the database"""
Session = connect()
session = Session()


FNULL = open(devnull, 'w')


def get_hosts_to_scan():
  hosts = session.query(LocalHost).all()
  if hosts:
    hosts_to_scan = []
    for host in hosts:
      hosts_to_scan.append(host.ip_addr)
    return hosts_to_scan


def nmap_ss_scan(tmp_dir, scan_targets):

  try:
    mkdir(tmp_dir)
  except FileExistsError:
    """moving on.."""

  # Find nmap
  p = Popen(['which', 'nmap'],
            shell=False,
            stdout=PIPE)

  nmap = p.stdout.read().strip().decode("utf-8")

  # Kick off the nmap scan
  try:

    for element in scan_targets:
      ip_addr = match(r'\b(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.'
                      r'(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.'
                      r'(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.'
                      r'(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b', element)

      subnet = match(r'((?:[0-9]{1,3}\.){3}[0-9]{1,3}/\d+)', element)

      if ip_addr:
        Popen([nmap, '-sS', '-sV', element, '-Pn', '-oX', '%s/%s.nmap.xml' % (tmp_dir, element)],
              shell=False,
              stdout=FNULL)

      if subnet:
        Popen([nmap, '-sS', '-sV', element, '-oX' '%s/%s.nmap.xml' % (tmp_dir, element[:-3])],
              shell=False,
              stdout=FNULL)

    look_for_nmap = check_if_nmap_running()

    while len(look_for_nmap.communicate()[0]) is not 0:
      print('nmap is still running...')

      # Check to see if nmap is still running
      sleep(5)
      look_for_nmap = check_if_nmap_running()

    else:
      print('no nmap processes')

  except TypeError:
    print('not ready to scan hosts')


def check_if_nmap_running():
    # Check to see if nmap is still running
    ps_ef = Popen(['ps', '-ef'],
                  shell=False,
                  stdout=PIPE)

    look_for_nmap = Popen(['grep', 'nm\\ap'],
                          shell=False,
                          stdin=ps_ef.stdout,
                          stdout=PIPE)
    return look_for_nmap
