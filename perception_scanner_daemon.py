from os import walk
from re import match
from shutil import rmtree as rmtree
from lib.host_profiler import match_creds_to_hosts
from lib.db_connector import connect
from lib.openvas import create_task, \
  create_targets, \
  create_targets_with_smb_lsc, \
  create_targets_with_ssh_lsc, \
  delete_targets, \
  delete_task, \
  delete_reports, \
  check_task, \
  update_openvas_db, \
  start_task, \
  get_report, \
  scanning
from lib.nmap_scanner import nmap_ss_scan
from models.db_tables import OpenvasAdmin, OpenvasLastUpdate, InventoryHost, SmbUser, LinuxUser
from datetime import datetime, timedelta
from time import sleep
from lib.latest_hosts_query import get_hosts
from os import system
from lib.xml_output_parser import parse_nmap_xml
import threading
from queue import Queue

# Connect to the database
Session = connect()
session = Session()

# Get openvas user information
openvas_user = session.query(OpenvasAdmin).first()

# make user user is configured
if not openvas_user:
  print('It appears that there is not a current OpenVAS admin in the database, please make sure seed daemon is running.')
  quit()

openvas_user_username = openvas_user.username
openvas_user_password = openvas_user.password
tmp_dir = '/tmp/perception_logic'


def main():
  while True:

    # variables
    smb_tuple_list = list()
    linux_tuple_list = list()
    smb_scan_list = list()
    linux_scan_list = list()
    dict_list = list()
    smb_dict = {}
    linux_dict = {}

    # get current local hosts
    scan_list = get_hosts()

    # validate credentials
    #match_creds_to_hosts(scan_list)

    # update openvas NVT's, CERT data, and CPE's
    one_day_ago = datetime.now() - timedelta(hours=24)
    check_last_update = session.query(OpenvasLastUpdate).order_by(OpenvasLastUpdate.id.desc()).first()

    if check_last_update is None or check_last_update.updated_at <= one_day_ago:
      update_openvas_db()
      system('openvassd && openvasmd --migrate && openvasmd --progress --rebuild')
      add_update_info = OpenvasLastUpdate(updated_at=datetime.now())
      session.add(add_update_info)
      session.commit()

    '''
    # get list of smb user ids
    smb_users = session.query(SmbUser).all()
    for smb_u in smb_users:
      smb_tuple_list.append((smb_u.id, smb_u.openvas_lsc_id))

    # get list of linux user ids
    linux_users = session.query(LinuxUser).all()
    for linux_u in linux_users:
      linux_tuple_list.append((linux_u.id, linux_u.openvas_lsc_id))

    # build smb scan list
    for element in smb_tuple_list:
      for smb_h in scan_list:
        lookup = session.query(InventoryHost).filter(InventoryHost.smb_user_id == element[0],
                                                     InventoryHost.ipv4_addr == smb_h).first()
        if lookup:
          smb_scan_list.append(smb_h)
      smb_dict = {'lsc_id': element[1], 'host_list': smb_scan_list, 'lsc_type': 'smb'}

    # build linux scan list
    for element in linux_tuple_list:
      for linux_host in scan_list:
        lookup = session.query(InventoryHost).filter(InventoryHost.linux_user_id == element[0],
                                                     InventoryHost.ipv4_addr == linux_host).first()
        if lookup:
          linux_scan_list.append(linux_host)
      linux_dict = {'lsc_id': element[1], 'host_list': linux_scan_list, 'lsc_type': 'ssh'}

    # remove smb hosts from scan list
    for host in smb_scan_list:
      scan_list.remove(host)

    # remove linux hosts from scan list
    for host in linux_scan_list:
      scan_list.remove(host)

    dict_list.append(linux_dict)
    dict_list.append(smb_dict)
    '''
    #dict_list.append(scan_list)

    # start the scanning
    #for x in range(len(dict_list)):
    #  t = threading.Thread(target=scanning(dict_list[x], openvas_user_username, openvas_user_password))
    #  t.daemon = True
    #  t.start()

    # send tmp directory and scan_list to nmap
    nmap_ss_scan(tmp_dir, scan_list)

    # loop through all xml nmap scans to parse
    for root, dirs, files in walk(tmp_dir):
      for name in files:
        nmap_xml = match(r'(^(.*?).nmap.xml)', name)
        if nmap_xml:
          parse_nmap_xml(str('%s/%s' % (tmp_dir, nmap_xml.group(0))))
    rmtree(tmp_dir)

    print('sleeping')
    sleep(300)


if __name__ == '__main__':
  try:
    main()
  except (IOError, SystemExit):
    raise
  except KeyboardInterrupt:
    print('Crtl+C Pressed. Shutting down.')
