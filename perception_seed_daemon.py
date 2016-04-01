from lib.get_from_core import get_network_info
from lib.ios_output_parser import local_hosts, local_connections, cdp_neighbors_detail, ios_fqdn_detail
from lib.openvas import setup_openvas, create_lsc_credential, get_lsc_crdentials
from shutil import rmtree as rmtree
from time import sleep
from sqlalchemy.exc import ProgrammingError
from models.db_tables import OpenvasAdmin, SmbUser, LinuxUser
from lib.db_connector import connect
from lib.crypt import decrypt_string

tmp_dir = '/tmp/perception'
ios_show_hosts_file = '%s/ios_show_hosts.txt' % tmp_dir
ios_show_local_conn_file = '%s/show_local_conn.txt' % tmp_dir
ios_show_cdp_detail_file = '%s/show_cdp_detail.txt' % tmp_dir
ios_show_fqdn_file = '%s/ios_show_fqdn.txt' % tmp_dir

"""Connect to the database"""
Session = connect()
session = Session()

create_lsc_credential_error = 'LSC Credential exists already'


def main():
  while True:

    # verify openvas is configured
    openvas_user = session.query(OpenvasAdmin).first()

    if not openvas_user:  # if it's not configured
      setup_openvas()     # configured it

    # make sure service accounts are created in OpenVAS
    smb_users = session.query(SmbUser).all()
    linux_users = session.query(LinuxUser).all()

    for smb_u in smb_users:
      if smb_u.openvas_lsc_id is None:
        smb_passwd = decrypt_string(str.encode(smb_u.encrypted_password),
                                    str.encode(smb_u.encrypted_password_salt)).decode("utf-8")

        create_lsc_credential_response_smb = create_lsc_credential(smb_u.description,
                                                                   smb_u.username,
                                                                   smb_passwd,
                                                                   openvas_user.username,
                                                                   openvas_user.password)
        if create_lsc_credential_response_smb != create_lsc_credential_error:
          session.query(SmbUser).update({SmbUser.openvas_lsc_id: create_lsc_credential_response_smb})
          session.commit()
        else:
          print('User exists already')
          lsc_smb_list = get_lsc_crdentials(openvas_user.username, openvas_user.password)
          for lsc_smb in lsc_smb_list:
            if smb_u.description in lsc_smb:
              print('lsc id is %s' % lsc_smb[1])

    for linux_u in linux_users:
      if linux_u.openvas_lsc_id is None:
        linux_passwd = decrypt_string(str.encode(linux_u.encrypted_password),
                                      str.encode(linux_u.encrypted_password_salt)).decode("utf-8")

        create_lsc_credential_response_linux = create_lsc_credential(linux_u.description,
                                                                     linux_u.username,
                                                                     linux_passwd,
                                                                     openvas_user.username,
                                                                     openvas_user.password)
        if create_lsc_credential_response_linux != create_lsc_credential_error:
          session.query(LinuxUser).update({LinuxUser.openvas_lsc_id: create_lsc_credential_response_linux})
          session.commit()
        else:
          print('User exists already')
          lsc_linux_list = get_lsc_crdentials(openvas_user.username, openvas_user.password)
          for lsc_linux in lsc_linux_list:
            if linux_u.description in lsc_linux:
              print('lsc id is %s' % lsc_linux[1])

    try:

      # get info from core, save in tmp/perception/
      get_network_info(tmp_dir,  # ssh to Cisco IOS core switch
                       ios_show_hosts_file,
                       ios_show_local_conn_file,
                       ios_show_cdp_detail_file,
                       ios_show_fqdn_file)

      # parse the local hosts file from /tmp/perception
      local_hosts(ios_show_hosts_file)  # this function also removes stale hosts from inventory

      # parse the local connections file from /tmp/perception
      local_connections(ios_show_local_conn_file)

      # parse the ios fqdn file from /tmp/perception
      ios_fqdn = ios_fqdn_detail(ios_show_fqdn_file)

      # parse the cdp detail file from /tmp/perception
      cdp_neighbors_detail(ios_show_cdp_detail_file, ios_fqdn)

      try:
        rmtree(tmp_dir)
      except FileNotFoundError as e:
        print(e)

    except ProgrammingError:
      print('database not ready')

    print('sleeping')
    sleep(300)


if __name__ == '__main__':
  try:
    main()
  except (IOError, SystemExit):
    raise
  except KeyboardInterrupt:
    print('Crtl+C Pressed. Shutting down.')
