from lib.db_connector import connect
from lib.host_profiler import match_creds_to_hosts

"""Connect to the database"""
Session = connect()
session = Session()

tmp_dir = '/tmp/perception_logic'


def main():
  scan_list = ['10.1.1.1', '10.1.1.2', '172.31.252.15', '172.31.249.16', '172.31.253.50']

  match_creds_to_hosts(scan_list)


if __name__ == '__main__':
  try:
    main()
  except (IOError, SystemExit):
    raise
  except KeyboardInterrupt:
    print('Crtl+C Pressed. Shutting down.')
