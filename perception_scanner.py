from os import walk
from re import match
from shutil import rmtree as rmtree
from lib.nmap_scanner import nmap_ssa_scan, get_hosts_to_scan
from lib.nmap_output_parser import parse_seed_nmap_xml

tmp_dir = '/tmp/perception'
ios_show_hosts_file = '%s/ios_show_hosts.txt' % tmp_dir
ios_show_local_conn_file = '%s/show_local_conn.txt' % tmp_dir
ios_show_cdp_detail_file = '%s/show_cdp_detail.txt' % tmp_dir
ios_show_fqdn_file = '%s/ios_show_fqdn.txt' % tmp_dir


def main():

  hosts_to_scan = get_hosts_to_scan()
  nmap_ssa_scan(tmp_dir, hosts_to_scan)
  for root, dirs, files in walk(tmp_dir):
    for name in files:
      nmap_xml = match(r'(^(.*?).nmap.xml)', name)
      if nmap_xml:
        parse_seed_nmap_xml(str('%s/%s' % (tmp_dir, nmap_xml.group(0))))
  rmtree(tmp_dir)

  print('done scanning hosts')
  exit()

  #if profile_windows:
  #  print('looking for Windows hosts..')
  #  profile_windows_hosts()
  #  exit()


if __name__ == '__main__':
  try:
    main()
  except (IOError, SystemExit):
    raise
  except KeyboardInterrupt:
    print('Crtl+C Pressed. Shutting down.')
