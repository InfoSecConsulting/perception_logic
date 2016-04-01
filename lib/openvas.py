from re import match, search
from subprocess import check_output, CalledProcessError
from os import system, path
from OpenSSL import crypto
from models.db_tables import OpenvasAdmin, OpenvasLastUpdate
from lib.db_connector import connect
from lib.xml_output_parser import parse_openvas_xml
from datetime import datetime
from time import sleep


redis_conf = '/etc/redis/redis.conf'
port_regex = 's/^\(#.\)\?port.*$/port 0/'
unixsocket_regex = 's/^\(#.\)\?unixsocket \/.*$/unixsocket \/var\/lib\/redis\/redis.sock/'
unixsocketperm_regex = 's/^\(#.\)\?unixsocketperm.*$/unixsocketperm 700/'
cacert_pem = '/var/lib/openvas/CA/cacert.pem'
servercert_pem = '/var/lib/openvas/CA/servercert.pem'
clientkey_pem = '/var/lib/openvas/private/CA/clientkey.pem'
clientcert_pem = '/var/lib/openvas/CA/clientcert.pem'


"""Connect to the database"""
Session = connect()
session = Session()


def setup_openvas():

    # verify redis configuration
    # validate that unixsocket is enabled
    if check_redis_unixsocket_conf(redis_conf) is not 1:
      # disable tcp in redis configuration
      find_replace(port_regex, redis_conf)
      # enable unixsocket
      find_replace(unixsocket_regex, redis_conf)
      find_replace(unixsocketperm_regex, redis_conf)

    # check for the openvas ca, if it's not there create it
    test_cacert_pem = path.isfile(cacert_pem)

    if test_cacert_pem is not True:
      system('openvas-mkcert -q')

    # verify CAfile certs with OpenSSL
    servercert_valid = verify_certificate_chain(servercert_pem, cacert_pem)

    if servercert_valid is not True:
      system('openvas-mkcert -q -f')

    # update openvas CERT, SCAP and NVT data
    update_openvas_db()

    # make sure client certs and client key files exist
    test_clientcert_pem = path.isfile(clientcert_pem)
    # test_clientkey_pem = path.isfile(clientkey_pem)

    if test_clientcert_pem is not True:
      system('openvas-mkcert-client -n -i')

    # verify CAfile client certs with OpenSSL
    clientcert_valid = verify_certificate_chain(clientcert_pem, cacert_pem)

    if clientcert_valid is not True:
      system('openvas-mkcert-client -n -i')

    # stop services and migrate database
    system('service openvas-manager stop && service openvas-scanner stop')
    system('openvassd && openvasmd --migrate && openvasmd --progress --rebuild -v')

    # kill all openvas services
    system('killall --wait openvassd')

    # start all openvas services
    system('service openvas-scanner start && service openvas-manager start')

    # create the admin user
    try:
      new_user = check_output(["openvasmd", "--create-user=perception_admin"]).decode()
      new_user_passwd = search(r'\w+[-]\w+[-]\w+[-]\w+[-]\w+', new_user).group(0)
    except CalledProcessError:
      system('openvasmd --delete-user=perception_admin')
      new_user = check_output(["openvasmd", "--create-user=perception_admin"]).decode()
      new_user_passwd = search(r'\w+[-]\w+[-]\w+[-]\w+[-]\w+', new_user).group(0)

    # create the GNU Privacy Guard directory for LSC (Local Security Checks) accounts
    system('mkdir /var/lib/openvas/gnupg')

    add_user = OpenvasAdmin(username='perception_admin',
                            password=new_user_passwd)
    session.add(add_user)

    add_update_info = OpenvasLastUpdate(updated_at=datetime.now())
    session.add(add_update_info)

    session.commit()


def check_redis_unixsocket_conf(conf):
  with open(conf, mode='r') as f:
    for line in f:
      if match(r'^unixsocket\s+', line):
        return 1
    else:
      return 0


def find_replace(sed_regex, conf):
  system('sed -i -e \'%s\' %s' % (sed_regex, conf))


def verify_certificate_chain(cert_str, trusted_certs):
    ca_cert_list = list()

    with open(cert_str) as f1:
      client_cert = f1.read()

    with open(trusted_certs) as f2:
      ca_cert = f2.read()
      ca_cert_list.append(ca_cert)

    certificate = crypto.load_certificate(crypto.FILETYPE_PEM, client_cert.encode())
    trusted_cert = crypto.load_certificate(crypto.FILETYPE_PEM, ca_cert.encode())

    # Create a certificate store and add your trusted certs
    store = crypto.X509Store()
    store.add_cert(trusted_cert)

    # Create a certificate context using the store and the downloaded certificate
    store_ctx = crypto.X509StoreContext(store, certificate)

    # Verify the certificate. Returns None if it can validate the certificate
    store_ctx.verify_certificate()

    return True


def update_openvas_db():
  system('openvas-nvt-sync && openvas-scapdata-sync && openvas-certdata-sync')


def create_targets(targets_name, openvas_user_username, openvas_user_password, scan_list):
  create_target_cli = '<create_target>' \
                      '<name>%s</name>' \
                      '<hosts>%s</hosts>' \
                      '</create_target>' % (targets_name, ', '.join(scan_list))

  create_target_response = check_output(['omp',
                                         '--port=9390',
                                         '--host=localhost',
                                         '--username=%s' % openvas_user_username,
                                         '--password=%s' % openvas_user_password,
                                         '--xml=%s' % create_target_cli]).decode()

  create_target_response_id = search(r'\w+[-]\w+[-]\w+[-]\w+[-]\w+', create_target_response).group(0)

  return create_target_response_id


def create_targets_with_smb_lsc(targets_name, openvas_user_username, openvas_user_password, lsc_id, smb_scan_list):
  create_target_cli = '<create_target>' \
                      '<name>%s</name>' \
                      '<hosts>%s</hosts>' \
                      '<smb_lsc_credential id="%s"/>' \
                      '</create_target>' % (targets_name, ', '.join(smb_scan_list), lsc_id)

  create_target_response = check_output(['omp',
                                         '--port=9390',
                                         '--host=localhost',
                                         '--username=%s' % openvas_user_username,
                                         '--password=%s' % openvas_user_password,
                                         '--xml=%s' % create_target_cli]).decode()

  create_target_response_id = search(r'\w+[-]\w+[-]\w+[-]\w+[-]\w+', create_target_response).group(0)

  return create_target_response_id


def create_targets_with_ssh_lsc(targets_name, openvas_user_username, openvas_user_password, lsc_id, ssh_scan_list):
  create_target_cli = '<create_target>' \
                      '<name>%s</name>' \
                      '<hosts>%s</hosts>' \
                      '<ssh_lsc_credential id="%s"/>' \
                      '</create_target>' % (targets_name, ', '.join(ssh_scan_list), lsc_id)

  create_target_response = check_output(['omp',
                                         '--port=9390',
                                         '--host=localhost',
                                         '--username=%s' % openvas_user_username,
                                         '--password=%s' % openvas_user_password,
                                         '--xml=%s' % create_target_cli]).decode()

  create_target_response_id = search(r'\w+[-]\w+[-]\w+[-]\w+[-]\w+', create_target_response).group(0)

  return create_target_response_id


def create_task(task_name, target_id, openvas_user_username, openvas_user_password):
  create_task_cli = '<create_task>' \
                    '<name>%s</name>' \
                    '<comment></comment>' \
                    '<config id="daba56c8-73ec-11df-a475-002264764cea"/>' \
                    '<target id="%s"/>' \
                    '</create_task>' % (task_name, target_id)

  create_task_response = check_output(['omp',
                                       '--port=9390',
                                       '--host=localhost',
                                       '--username=%s' % openvas_user_username,
                                       '--password=%s' % openvas_user_password,
                                       '--xml=%s' % create_task_cli]).decode()

  create_task_response_id = search(r'\w+[-]\w+[-]\w+[-]\w+[-]\w+', create_task_response).group(0)

  return create_task_response_id


def create_lsc_credential(name, login, password, openvas_user_username, openvas_user_password):

  create_lsc_credential_cli = '<create_lsc_credential>' \
                              '<name>%s</name>' \
                              '<login>%s</login>' \
                              '<password>%s</password>' \
                              '<comment></comment>' \
                              '</create_lsc_credential>' % (name, login, password)

  create_lsc_credential_cli_response = check_output(['omp',
                                                     '--port=9390',
                                                     '--host=localhost',
                                                     '--username=%s' % openvas_user_username,
                                                     '--password=%s' % openvas_user_password,
                                                     '--xml=%s' % create_lsc_credential_cli]).decode()

  return parse_openvas_xml(create_lsc_credential_cli_response)


def get_lsc_crdentials(openvas_user_username, openvas_user_password):
  get_lsc_credential_cli = '<get_lsc_credentials/>'

  get_lsc_credential_cli_response = check_output(['omp',
                                                  '--port=9390',
                                                  '--host=localhost',
                                                  '--username=%s' % openvas_user_username,
                                                  '--password=%s' % openvas_user_password,
                                                  '--xml=%s' % get_lsc_credential_cli]).decode()

  return parse_openvas_xml(get_lsc_credential_cli_response)


def start_task(task_id, openvas_user_username, openvas_user_password):
  start_task_cli = '<start_task task_id="%s"/>' % task_id

  start_task_response = check_output(['omp',
                                      '--port=9390',
                                      '--host=localhost',
                                      '--username=%s' % openvas_user_username,
                                      '--password=%s' % openvas_user_password,
                                      '--xml=%s' % start_task_cli]).decode()

  xml_report_id = search(r'\w+[-]\w+[-]\w+[-]\w+[-]\w+', start_task_response).group(0)

  return xml_report_id


def check_task(task_id, openvas_user_username, openvas_user_password):
  get_task_cli = '<get_tasks task_id="%s"/>' % task_id
  get_task_cli_response = check_output(['omp',
                                        '--port=9390',
                                        '--host=localhost',
                                        '--username=%s' % openvas_user_username,
                                        '--password=%s' % openvas_user_password,
                                        '--xml=%s' % get_task_cli]).decode()

  return parse_openvas_xml(get_task_cli_response)


def get_report(report_id, openvas_user_username, openvas_user_password):
  get_report_cli = '<get_reports report_id="%s"/>' % report_id
  get_report_cli_response = check_output(['omp',
                                          '--port=9390',
                                          '--host=localhost',
                                          '--username=%s' % openvas_user_username,
                                          '--password=%s' % openvas_user_password,
                                          '--xml=%s' % get_report_cli]).decode()

  parse_openvas_xml(get_report_cli_response)


def delete_task(task_id, openvas_user_username, openvas_user_password):
  delete_task_cli = '<delete_task task_id="%s"/>' % task_id
  delete_task_cli_response = check_output(['omp',
                                           '--port=9390',
                                           '--host=localhost',
                                           '--username=%s' % openvas_user_username,
                                           '--password=%s' % openvas_user_password,
                                           '--xml=%s' % delete_task_cli]).decode()

  return delete_task_cli_response


def delete_targets(target_id, openvas_user_username, openvas_user_password):
  delete_targets_cli = '<delete_target target_id="%s"/>' % target_id
  delete_targets_cli_response = check_output(['omp',
                                              '--port=9390',
                                              '--host=localhost',
                                              '--username=%s' % openvas_user_username,
                                              '--password=%s' % openvas_user_password,
                                              '--xml=%s' % delete_targets_cli]).decode()

  return delete_targets_cli_response


def delete_reports(report_id, openvas_user_username, openvas_user_password):
  delete_report_cli = '<delete_report report_id="%s"/>' % report_id
  delete_report_cli_response = check_output(['omp',
                                             '--port=9390',
                                             '--host=localhost',
                                             '--username=%s' % openvas_user_username,
                                             '--password=%s' % openvas_user_password,
                                             '--xml=%s' % delete_report_cli]).decode()

  return delete_report_cli_response


def scanning(scan_list, openvas_user_username, openvas_user_password):
  target_id = None
  task_id = None
  task_name = None
  xml_report_id = None

  if type(scan_list) is dict:

    if scan_list['lsc_type'] == 'ssh':
      # create the targets to scan
      target_id = create_targets_with_ssh_lsc('initial ssh scan targets',
                                              openvas_user_username,
                                              openvas_user_password,
                                              scan_list['lsc_id'],
                                              scan_list['host_list'])
      task_name = 'scan using ssh'

    if scan_list['lsc_type'] == 'smb':
      # create the targets to scan
      target_id = create_targets_with_smb_lsc('initial smb scan targets',
                                              openvas_user_username,
                                              openvas_user_password,
                                              scan_list['lsc_id'],
                                              scan_list['host_list'])
      task_name = 'scan using smb'

  if type(scan_list) is list:
    # create the targets to scan
    target_id = create_targets('initial default scan targets',
                               openvas_user_username,
                               openvas_user_password,
                               scan_list)

    task_name = 'initial scan'

  # setup the task
  if target_id is not None:
    task_id = create_task(task_name, target_id, openvas_user_username, openvas_user_password)

  # run the task
  if task_id is not None:
    xml_report_id = start_task(task_id, openvas_user_username, openvas_user_password)

  # wait until the task is done
  while True:
    check_task_response = check_task(task_id, openvas_user_username, openvas_user_password)
    if check_task_response == 'Done' or check_task_response == 'Stopped':
      break
    print('still scanning')
    sleep(60)

  # download and parse the report
  if xml_report_id is not None:
    get_report(xml_report_id, openvas_user_username, openvas_user_password)
  '''
  # delete the task
  if task_id is not None:
    delete_task(task_id, openvas_user_username, openvas_user_password)

  # delete the targets
  if target_id is not None:
    delete_targets(target_id, openvas_user_username, openvas_user_password)

  # delete the report
  if xml_report_id is not None:
    delete_reports(xml_report_id, openvas_user_username, openvas_user_password)
  '''
