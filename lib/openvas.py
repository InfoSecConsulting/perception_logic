from re import match, search
from subprocess import check_output, CalledProcessError
from os import system, path
from OpenSSL import crypto
from models.db_tables import OpenvasAdmin
from lib.db_connector import connect

redis_conf = '/etc/redis/redis.conf'
port_regex = 's/^\(#.\)\?port.*$/port 0/'#compile(r'(^#.?port\s+)')
unixsocket_regex = 's/^\(#.\)\?unixsocket \/.*$/unixsocket \/var\/lib\/redis\/redis.sock/' #compile(r'(^#.?unixsocket\s+)')
unixsocketperm_regex = 's/^\(#.\)\?unixsocketperm.*$/unixsocketperm 700/'#compile(r'(^#.?unixsocketperm\s+)')
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
    system('openvas-nvt-sync && openvas-scapdata-sync && openvas-certdata-sync')
    test_clientcert_pem = path.isfile(clientcert_pem)
    test_clientkey_pem = path.isfile(clientkey_pem)

    if test_clientcert_pem and test_clientkey_pem is not True:
      system('openvas-mkcert-client -n -i')
    # verify CAfile client certs with OpenSSL
    clientcert_valid = verify_certificate_chain(clientcert_pem, cacert_pem)

    if clientcert_valid is not True:
      system('openvas-mkcert-client -n -i')

    # stop services and migrate database
    system('service openvas-manager stop && service openvas-scanner stop')
    system('openvassd && openvasmd --migrate && openvasmd --progress --rebuild')

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

    add_user = OpenvasAdmin(username='perception_admin',
                            password=new_user_passwd)

    session.add(add_user)
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
    trustedcert = crypto.load_certificate(crypto.FILETYPE_PEM, ca_cert.encode())

    #Create a certificate store and add your trusted certs
    store = crypto.X509Store()
    store.add_cert(trustedcert)

    # Create a certificate context using the store and the downloaded certificate
    store_ctx = crypto.X509StoreContext(store, certificate)

    # Verify the certificate, returns None if it can validate the certificate
    store_ctx.verify_certificate()
    return True
