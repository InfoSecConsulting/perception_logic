from re import search
from models.db_tables import InventoryHost, InventorySvc, SmbUser
from lib.wmic_parser import wmic_query
from lib.crypt import decrypt_string
from lib.db_connector import connect


win32_computersystem = 'select * from Win32_ComputerSystem'
win32_account = 'select * from Win32_Account'
win32_product = 'select * from Win32_Product'
win32_operatingsystem = 'select * from Win32_OperatingSystem'
win32_process = 'select * from Win32_Process'
win32_service = 'select * from Win32_Service'
win32_loggedonuser = 'select * from Win32_LoggedOnUser'
win32_logonsession = 'select * from Win32_LogonSession'
win32_useraccount = 'select * from Win32_UserAccount'


def profile_windows_hosts():
  hosts = db.session.query(InventoryHost).all()
  svcs = db.session.query(InventorySvc).all()
  windows_hosts = []

  for h_row in hosts:
    for s_row in svcs:
      host = s_row.host.ipv4_addr
      if host == h_row.ipv4_addr:
        protocol = s_row.protocol
        portid = s_row.portid
        try:
          svc_name = s_row.name
        except AttributeError:
          svc_name = 'unknown'
        try:
          svc_product = s_row.svc_product
        except AttributeError:
          svc_product = 'unknown'
        try:
          extrainfo = s_row.extrainfo
        except AttributeError:
          extrainfo = 'unknown'
        try:
          product_id = s_row.product_id
        except AttributeError:
          product_id = 'unknown'

        if svc_name == 'msrpc' or svc_name == 'ldap' or svc_name == 'globalcatLDAPssl':
          windows_hosts.append(h_row.ipv4_addr)

  win_host_set = set(windows_hosts)
  for h in win_host_set:
    print(h)

    cs_query = wmic_query(s_domain, s_username, s_password, h, win32_computersystem)
    #os_query = wmic_query(s_domain, s_username, s_password, h, win32_operatingsystem)
    product_query = wmic_query(s_domain, s_username, s_password, h, win32_product)
    #process_query = wmic_query(s_domain, s_username, s_password, h, win32_process)
    #logonsession_query = wmic_query(s_domain, s_username, s_password, h, win32_logonsession)
    #loggedonuser_query = wmic_query(s_domain, s_username, s_password, h, win32_loggedonuser)
    #useraccount_query = wmic_query(s_domain, s_username, s_password, h, win32_useraccount)

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
