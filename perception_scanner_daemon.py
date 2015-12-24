from os import walk
from re import match
from shutil import rmtree as rmtree
from lib.host_profiler import match_creds_to_hosts
from lib.nmap_scanner import nmap_ss_scan
from lib.nmap_output_parser import parse_seed_nmap_xml
from lib.db_connector import connect
from models.db_tables import LocalHost, InventoryHost
from datetime import datetime, timedelta
from time import sleep
from subprocess import check_output

"""Connect to the database"""
Session = connect()
session = Session()

tmp_dir = '/tmp/perception_logic'


def main():

  while True:

    inventory = list()
    scan_list = list()

    now = datetime.now()
    five_minutes_ago = str(datetime.now() - timedelta(minutes=5))
    five_min_query = session.query(LocalHost).filter(LocalHost.updated_at.between(five_minutes_ago, now))

    all_local_hosts = session.query(LocalHost).all()
    all_inventory_hosts = session.query(InventoryHost).all()

    for i in all_inventory_hosts:
      inventory.append(i.ipv4_addr)

    for i in all_local_hosts:
      if i.ip_addr not in inventory:
        scan_list.append(i.ip_addr)

    for i in five_min_query:
      if i.ip_addr not in scan_list:
        scan_list.append(i.ip_addr)

    '''
    daba56c8-73ec-11df-a475-002264764cea

    username = 'perception_admin'
    password = '3aa27420-bf15-47a0-a984-78bfc0fd6166'
    create_target = '<create_target><name>core.h1tb.com</name><hosts>10.1.1.1</hosts></create_target>'

    create_target = check_output(['omp',
                                  '--port=9390',
                                  '--host=localhost',
                                  '--username=%s' % username,
                                  '--password=%s' % password,
                                  '--xml=%s' % create_target])

    resp = 13a3795b-2be9-4e97-913d-6ffeaeba8d91

    omp --port=9390 --host=localhost --username=perception_admin --password="3aa27420-bf15-47a0-a984-78bfc0fd6166"
    --xml='<create_task><name>Core scan</name><comment>Scan in Core</comment><config id="daba56c8-73ec-11df-a475-002264764cea"/><target id="13a3795b-2be9-4e97-913d-6ffeaeba8d91"/></create_task>'

    resp = bf15f5f2-6c2a-4312-bffa-a107a9243000

    omp --port=9390 --host=localhost --username=perception_admin --password="3aa27420-bf15-47a0-a984-78bfc0fd6166"
    --xml='<start_task task_id="bf15f5f2-6c2a-4312-bffa-a107a9243000"/>'

    resp = bda1f0a9-cd8f-4352-b4b2-ffc9bfd4fe3b

    omp --port=9390 --host=localhost --username=perception_admin --password="3aa27420-bf15-47a0-a984-78bfc0fd6166"
    -iX '<get_reports report_id="bda1f0a9-cd8f-4352-b4b2-ffc9bfd4fe3b"/>'
    '''


    ## send tmp directory and scan_list to nmap
    #nmap_ss_scan(tmp_dir, scan_list)

    ## loop threw all xml nmap scans to parse
    #for root, dirs, files in walk(tmp_dir):
    #  for name in files:
    #    nmap_xml = match(r'(^(.*?).nmap.xml)', name)
    #    if nmap_xml:
    #      parse_seed_nmap_xml(str('%s/%s' % (tmp_dir, nmap_xml.group(0))))

    #rmtree(tmp_dir)

    match_creds_to_hosts(scan_list)

    print(scan_list)
    print('sleeping')
    sleep(300)


if __name__ == '__main__':
  try:
    main()
  except (IOError, SystemExit):
    raise
  except KeyboardInterrupt:
    print('Crtl+C Pressed. Shutting down.')
