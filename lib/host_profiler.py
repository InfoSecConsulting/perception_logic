from re import search
from models.db_tables import InventoryHost, InventorySvc, SmbUser, LinuxUser
from lib.wmic_parser import wmic_query
from lib.crypt import decrypt_string
from lib.db_connector import connect
from lib.ssh_to_host import check_creds
from lib.scapy_scanner import tcp_scan


"""Connect to the database"""
Session = connect()
session = Session()

win32_computersystem =  'select * from Win32_ComputerSystem'
win32_account =         'select * from Win32_Account'
win32_product =         'select * from Win32_Product'
win32_operatingsystem = 'select * from Win32_OperatingSystem'
win32_process =         'select * from Win32_Process'
win32_service =         'select * from Win32_Service'
win32_loggedonuser =    'select * from Win32_LoggedOnUser'
win32_logonsession =    'select * from Win32_LogonSession'
win32_useraccount =     'select * from Win32_UserAccount'


def match_creds_to_hosts(host_list):

  # build vars
  smb_hosts = list()
  ssh_hosts = list()

  # auth ports
  smb_port = 135
  ssh_port = 22

  # validate ports are open and add hosts to proper list
  for host in host_list:

    smb_check = tcp_scan(host, smb_port)
    ssh_check = tcp_scan(host, ssh_port)

    if smb_check:
      smb_hosts.append(host)

    if ssh_check:
      ssh_hosts.append(host)

  # validate smb login credentials
  if smb_hosts:

    # query database for smb credentials
    smb_svc_accounts = session.query(SmbUser).all()
    smb_accounts = list()

    if smb_svc_accounts:

      # build a dictionary of smb accounts
      for u in smb_svc_accounts:

        smb_dict = {'id': u.id,
                    'username': u.username,
                    'password': decrypt_string(str.encode(u.encrypted_password),
                                               str.encode(u.encrypted_password_salt)),
                    'domain_name': u.domain_name}

        smb_accounts.append(smb_dict)

      # validate credentials using WMI
      for h in smb_hosts:

        for u in smb_accounts:
              cs_query = wmic_query(u['domain_name'], u['username'], u['password'], h, win32_computersystem)

              failed_login = {'[librpc/rpc/dcerpc_connect.c:828:dcerpc_pipe_connect_b_recv()]'
                              ' failed NT status (c0000022) in dcerpc_pipe_connect_b_recv':
                              '[wmi/wmic.c:196:main()] ERROR: Loin to remote object.'}

              error_login = {'[librpc/rpc/dcerpc_connect.c:828:dcerpc_pipe_connect_b_recv()] '
                             'failed NT status (c0000017) in dcerpc_pipe_connect_b_recv':
                             '[wmi/wmic.c:196:main()] ERROR: Login to remote object.'}

              connection_refused = {'[librpc/rpc/dcerpc_connect.c:828:dcerpc_pipe_connect_b_recv()]'
                                    ' failed NT status (c0000236) in dcerpc_pipe_connect_b_recv':
                                    '[wmi/wmic.c:196:main()] ERROR: Login to remote object.'}

              if cs_query[0] == connection_refused:
                print('connection refused from %s' % h)

              if cs_query[0] == error_login:
                print('error logging into %s' % h)

              if cs_query[0] == failed_login:
                print('failed login for %s' % h)

              elif cs_query[0] != connection_refused and cs_query[0] != error_login and cs_query[0] != failed_login:
                add_inventory_host = InventoryHost(ipv4_addr=h,
                                                   smb_user_id=u['id'])
                session.add(add_inventory_host)
                session.commit()

  # validate ssh login credentials
  if ssh_hosts:

    # query database for ssh credentials
    linux_svc_accounts = session.query(LinuxUser).all()
    linux_accounts = list()

    if linux_svc_accounts:

      # build a dictionary of ssh accounts
      for u in linux_svc_accounts:

        linux_dict = {'id': u.id,
                      'username': u.username,
                      'password': decrypt_string(str.encode(u.encrypted_password),
                                                 str.encode(u.encrypted_password_salt)),
                      'enable_password': decrypt_string(str.encode(u.encrypted_enable_password),
                                                        str.encode(u.encrypted_enable_password_salt))}
        linux_accounts.append(linux_dict)

      for h in ssh_hosts:

        # validate credentials using ssh
        for u in linux_accounts:

          ssh_to_host = check_creds(h, u['username'], u['password'].decode("utf-8"))

          if ssh_to_host == 1:

            add_inventory_host = InventoryHost(ipv4_addr=h,
                                               linux_user_id=u['id'])
            session.add(add_inventory_host)
            session.commit()

          if ssh_to_host == 99:
            print('linux user not added to %s, bad ssh key' % h)
            add_inventory_host = InventoryHost(ipv4_addr=h,
                                               bad_ssh_key=True)
            session.add(add_inventory_host)
            session.commit()


def profile_windows_hosts(domain_name, username, password):

  hosts = session.query(InventoryHost).all()
  svcs = session.query(InventorySvc).all()
  windows_hosts = []

  for h in hosts:
    for s in svcs:
      host = s.host.ipv4_addr
      if host == h.ipv4_addr:
        protocol = s.protocol
        portid = s.portid
        try:
          svc_name = s.name
        except AttributeError:
          svc_name = 'unknown'
        try:
          svc_product = s.svc_product
        except AttributeError:
          svc_product = 'unknown'
        try:
          extrainfo = s.extrainfo
        except AttributeError:
          extrainfo = 'unknown'
        try:
          product_id = s.product_id
        except AttributeError:
          product_id = 'unknown'

        if svc_name == 'msrpc' or svc_name == 'ldap' or svc_name == 'globalcatLDAPssl':
          windows_hosts.append(h.ipv4_addr)

  win_host_set = set(windows_hosts)
  for h in win_host_set:
    print(h)

    cs_query = wmic_query(domain_name, username, password, h, win32_computersystem)
    #os_query = wmic_query(domain_name, username, password, h, win32_operatingsystem)
    product_query = wmic_query(domain_name, username, password, h, win32_product)
    #process_query = wmic_query(domain_name, username, password, h, win32_process)
    #logonsession_query = wmic_query(domain_name, username, password, h, win32_logonsession)
    #loggedonuser_query = wmic_query(domain_name, username, password, h, win32_loggedonuser)
    #useraccount_query = wmic_query(domain_name, username, password, h, win32_useraccount)

    failed_login = search(r'(failed NT status)', str(cs_query))
    error_login = search(r'(ERROR: Login to remote object)', str(cs_query))

    if failed_login:
      print('credentials are wrong or %s is not a Windows host' % h)
      print('\n')

    elif error_login:
      print('error logging in, possible timeout..')
      print('\n')

    else:
      for e in cs_query:
        print('Hostname: %s' % e['DNSHostName'])
        print('Primary Owner: %s' % e['PrimaryOwnerName'])
        print('Manufacturer: %s' % e['Manufacturer'])
        print('Number of Logical Processors: %s' % e['NumberOfLogicalProcessors'])
        print('System Type: %s' % e['SystemType'])
        print('\n')

      #for e in os_query:

      #  print('OS Name: %s' % e['Name'])
      #  print('Version: %s' % e['Version'])
      #  print('OS Type: %s' % e['OSType'])
      #  print('OS Build Number: %s' % e['BuildNumber'])
      #  print('CSD Version: %s' % e['CSDVersion'])
      #  print('Service Pack Minor Version: %s' % e['ServicePackMinorVersion'])
      #  print('OS Product Suite: %s' % e['OSProductSuite'])
      #  print('OS Architecture: %s' % e['OSArchitecture'])
      #  print('OS SKU: %s' % e['OperatingSystemSKU'])
      #  print('Data Execution Prevention for 32Bit Applications: %s' % e['DataExecutionPrevention_32BitApplications'])
      #  print('Data Execution Prevention Support Policy: %s' % e['DataExecutionPrevention_SupportPolicy'])
      #  print('\n')

      for e in product_query:
        print(e['Name'])
        print('\n')

      #for e in process_query:
      #  print(e['Name'])
      #  print(e['CommandLine'])
      #  print('\n')

      #for e in logonsession_query:
      #  print(e)

      #for e in loggedonuser_query:
      #  print('Username: %s' % e['Antecedent'])

      #for e in useraccount_query:
      #  print(e)
