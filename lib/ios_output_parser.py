from re import search, sub
from sqlalchemy.exc import IntegrityError
from models.db_tables import LocalNet, DiscoveryProtocolFinding, LocalHost, InventoryHost
from lib.db_connector import connect

"""Connect to the database"""
Session = connect()
session = Session()


def local_hosts(show_hosts_file):
  new_host_dict_list = []
  new_hosts = []
  database_hosts = session.query(LocalHost).all()
  current_db_hosts = []

  try:
    with open(show_hosts_file, 'r') as shosts_f:

      hosts_data = shosts_f.readlines()
      for element in hosts_data:
        ip_addrs = search(r'\b(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.'
                             r'(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.'
                             r'(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.'
                             r'(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b', element)

        mac_addrs = search(r'(([0-9A-Fa-f]{4}\.){2}[0-9A-Fa-f]{4})', element)
        try:
          host_dict = {'ip_addr': ip_addrs.group(0), 'mac_addr': mac_addrs.group(0)}
          new_host_dict_list.append(host_dict)
        except AttributeError:
          """Likely NoneType"""

    # build IP address lists
    for h in database_hosts:
      current_db_hosts.append(h.ip_addr)

    for h in new_host_dict_list:
      new_hosts.append(h['ip_addr'])

    # delete stale hosts
    for h in current_db_hosts:
      if h not in new_hosts:
        # try:
        session.query(LocalHost).filter(LocalHost.ip_addr == h).delete()
        session.commit()
        try:
          session.query(InventoryHost).filter(InventoryHost.ipv4_addr == h).delete()
          session.commit()
        except AttributeError as e:
          print(e)
          session.rollback()
        # except SOMEERROR:

    # update hosts if mac_addr is different, then add
    for h in new_host_dict_list:
      # try:

      host = session.query(LocalHost).filter(LocalHost.ip_addr == h['ip_addr']).first()
      m = h['mac_addr'].replace('.', '')
      macaddr = ':'.join(m[i:i + 2] for i in range(0, 12, 2))

      if host is not None:

        if host.mac_addr != macaddr:
          session.query(LocalHost).filter(LocalHost.mac_addr != h['mac_addr']).update({LocalHost.mac_addr: h['mac_addr']})
        else:
          try:
            session.add(LocalHost(ip_addr=h['ip_addr'], mac_addr=h['mac_addr']))
            session.commit()
          except IntegrityError:
            """Then I must exist"""
            session.rollback()

      else:
        try:
          session.add(LocalHost(ip_addr=h['ip_addr'], mac_addr=h['mac_addr']))
          session.commit()
        except IntegrityError:
          """Then I must exist"""
          session.rollback()

    shosts_f.close()
  except FileNotFoundError as e:
    print(e)


def local_connections(show_local_conn_file):

  session.query(LocalNet).delete()
  session.commit()

  net_list = []
  try:
    with open(show_local_conn_file, 'r') as slc_f:
      data = slc_f.readlines()
      for element in data:
        m = search(r'((?:[0-9]{1,3}\.){3}[0-9]{1,3}/\d+)', element)
        if m:
          net_list += [m.group(0)]
    for net in net_list:
      add_net_base = LocalNet(subnet=net)
      try:
        session.add(add_net_base)
        session.commit()
      except IntegrityError:
        """Then I must exist"""
        session.rollback()
    slc_f.close()
  except FileNotFoundError as e:
    print(e)


def ios_fqdn_detail(ios_show_fqdn_file):
  fqdn = []
  try:
    with open(ios_show_fqdn_file, 'r') as sfqdn_f:
      fqdn_data = sfqdn_f.readlines()
      for element in fqdn_data:
        reg_ip_domain_name = search(r'(ip domain-name\s+.+?)\n', element)
        reg_hostname = search(r'(hostname\s+.+?)\n', element)
        if reg_hostname:
          fqdn += reg_hostname.group(0).split(' ')[1].strip() + '.'
        if reg_ip_domain_name:
          fqdn += reg_ip_domain_name.group(0).split(' ')[2].strip()
    ios_fqdn = ''.join(fqdn)
    return ios_fqdn
  except FileNotFoundError as e:
    print(e)


def cdp_neighbors_detail(show_cdp_detail_file, ios_fqdn):

  session.query(DiscoveryProtocolFinding).filter(DiscoveryProtocolFinding.local_device_id == ios_fqdn).delete()
  session.commit()
  try:
    with open(show_cdp_detail_file, 'r') as scdp_f:
      data = scdp_f.read()
      data_list = str(data).split('-------------------------')
      for element in data_list:
        discovery_list = []
        reg_device_id = search(r'(Device ID:.+?)\n', element)
        try:
          discovery_list += [sub(r':\s+', ':', reg_device_id.group(0).strip())]
        except AttributeError:
          discovery_list.append('Device ID:')
        reg_entry_addrs = search(r'\b(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.'
                                    r'(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.'
                                    r'(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.'
                                    r'(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b', element)
        try:
          discovery_list.append('IP:%s' % str(reg_entry_addrs.group(0).strip('\n')))
        except AttributeError:
          discovery_list.append('IP:')
        reg_platform = search(r'(Platform:.+?)\n', element)
        try:
          platform_line = sub(r':\s+', ':', reg_platform.group(0).strip())
          platform_capabilities = platform_line.split(',  ')
          discovery_list.append(platform_capabilities[0])
          discovery_list.append(platform_capabilities[1])
        except AttributeError:
          discovery_list.append('Platform:')
          discovery_list.append('Capabilities:')
        reg_int = search(r'(Interface:.+?)\n', element)
        try:
          int_line = sub(r':\s+', ':', reg_int.group(0).strip())
          interface_port_id = int_line.split(',  ')
          discovery_list.append(interface_port_id[0])
          discovery_list.append(interface_port_id[1])
        except AttributeError:
          discovery_list.append('Interface:')
          discovery_list.append('Port ID (outgoing port):')
        reg_advertisment_ver = search(r'(advertisement version:.+?)\n', element)
        try:
          discovery_list += [sub(r':\s+', ':', reg_advertisment_ver.group(0).strip())]
        except AttributeError:
          discovery_list.append('advertisement version:')
        reg_protocol_hello = search(r'(Protocol Hello:.+?)\n', element)
        try:
          discovery_list += [sub(r':\s+', ':', reg_protocol_hello.group(0).strip())]
        except AttributeError:
          discovery_list.append('Protocol Hello:')
        reg_vtp_mgnt = search(r'(VTP Management Domain:.+?)\n', element)
        try:
          discovery_list += [sub(r':\s+', ':', reg_vtp_mgnt.group(0).strip())]
        except AttributeError:
          discovery_list.append('VTP Management Domain:')
        reg_native_vlan = search(r'(Native VLAN:.+?)\n', element)
        try:
          discovery_list += [sub(r':\s+', ':', reg_native_vlan.group(0).strip())]
        except AttributeError:
          discovery_list.append('Native VLAN:')
        reg_duplex = search(r'(Duplex:.+?)\n', element)
        try:
          discovery_list += [sub(r':\s+', ':', reg_duplex.group(0).strip())]
        except AttributeError:
          discovery_list.append('Duplex:')
        reg_power_drawn = search(r'(Power drawn:.+?)\n', element)
        try:
          discovery_list += [sub(r':\s+', ':', reg_power_drawn.group(0).strip())]
        except AttributeError:
          discovery_list.append('Power drawn:')

        discovery_dictionary = dict(map(str, x.split(':')) for x in discovery_list)

        for k, v in discovery_dictionary.items():
          if v is '':
            discovery_dictionary[k] = None

        if discovery_dictionary['Device ID'] is not None:
          add_cdp_data = DiscoveryProtocolFinding(local_device_id=ios_fqdn,
                                                  remote_device_id=discovery_dictionary['Device ID'],
                                                  ip_addr=discovery_dictionary['IP'],
                                                  platform=discovery_dictionary['Platform'],
                                                  capabilities=discovery_dictionary['Capabilities'],
                                                  interface=discovery_dictionary['Interface'],
                                                  port_id=discovery_dictionary['Port ID (outgoing port)'],
                                                  discovery_version=discovery_dictionary['advertisement version'],
                                                  protocol_hello=discovery_dictionary['Protocol Hello'],
                                                  vtp_domain = discovery_dictionary['VTP Management Domain'],
                                                  native_vlan=discovery_dictionary['Native VLAN'],
                                                  duplex=discovery_dictionary['Duplex'],
                                                  power_draw=discovery_dictionary['Power drawn'])
          session.add(add_cdp_data)
          session.commit()
    scdp_f.close()
  except FileNotFoundError as e:
    print(e)
