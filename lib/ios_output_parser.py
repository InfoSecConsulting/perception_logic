from re import search, sub
from sqlalchemy.exc import IntegrityError
from models.db_tables import LocalNet, DiscoveryProtocolFinding, LocalHost, InventoryHost
from lib.db_connector import connect

"""Connect to the database"""
Session = connect()
session = Session()


def local_hosts(show_hosts_file):

  # setup vars
  new_host_dict_list = []
  new_hosts = []
  database_hosts = session.query(LocalHost).all()
  current_db_hosts = []

  # open show hosts file
  try:
    with open(show_hosts_file, 'r') as shosts_f:

      # parse file for valid hosts
      hosts_data = shosts_f.readlines()
      for element in hosts_data:

        # search each line for ip addresses
        ip_addrs = search(r'\b(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.'
                          r'(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.'
                          r'(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.'
                          r'(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b', element)

        # and search each line for mac addresses
        mac_addrs = search(r'(([0-9A-Fa-f]{4}\.){2}[0-9A-Fa-f]{4})', element)
        try:

          # build the hosts dictionary  to add to the local_hosts table
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
    # TODO remove openvas results that match state hosts
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
        # except SOME_ERROR:

    # update hosts if mac_addr is different, then add
    for h in new_host_dict_list:

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

  # delete all local network information
  session.query(LocalNet).delete()
  session.commit()

  # build network list
  net_list = []

  # open show local connections file
  try:
    with open(show_local_conn_file, 'r') as slc_f:
      data = slc_f.readlines()

      for element in data:

        # search for networks
        m = search(r'((?:[0-9]{1,3}\.){3}[0-9]{1,3}/\d+)', element)
        if m:
          net_list += [m.group(0)]

    # add each network to the local_nets table
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

  # setup vars
  fqdn = []

  # open fqdn detail file
  try:
    with open(ios_show_fqdn_file, 'r') as sfqdn_f:

      # read each line
      fqdn_data = sfqdn_f.readlines()

      for element in fqdn_data:

        # search for line with the domain name
        reg_ip_domain_name = search(r'(ip domain-name\s+.+?)\n', element)

        # search for the line with the hostname
        reg_hostname = search(r'(hostname\s+.+?)\n', element)

        if reg_hostname:

          # pull the hostname from the line
          fqdn += reg_hostname.group(0).split(' ')[1].strip() + '.'

        if reg_ip_domain_name:

          # pull the domain name from the line
          fqdn += reg_ip_domain_name.group(0).split(' ')[2].strip()

    # put the together and reture it
    ios_fqdn = ''.join(fqdn)
    return ios_fqdn

  except FileNotFoundError as e:
    print(e)


def cdp_neighbors_detail(show_cdp_detail_file, ios_fqdn):

  # remove all cdp info from the discovery_protocol_findings table
  session.query(DiscoveryProtocolFinding).filter(DiscoveryProtocolFinding.local_device_id == ios_fqdn).delete()
  session.commit()

  # open and parse the show cdp detail file
  try:
    with open(show_cdp_detail_file, 'r') as scdp_f:

      # read the whole file
      data = scdp_f.read()

      # build a list of each entry
      data_list = str(data).split('-------------------------')

      for element in data_list:

        # empty discovery list
        discovery_list = []

        # search for the device id
        reg_device_id = search(r'(Device ID:.+?)\n', element)

        try:

          # add the device id to the list
          discovery_list += [sub(r':\s+', ':', reg_device_id.group(0).strip())]
        except AttributeError:
          discovery_list.append('Device ID:')

        # search for the ip address
        reg_entry_addrs = search(r'\b(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.'
                                 r'(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.'
                                 r'(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.'
                                 r'(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b', element)

        try:

          # add the ip  to the list
          discovery_list.append('IP:%s' % str(reg_entry_addrs.group(0).strip('\n')))
        except AttributeError:
          discovery_list.append('IP:')

        # search for the platform information
        reg_platform = search(r'(Platform:.+?)\n', element)

        try:

          # parse platform info and clean it up
          platform_line = sub(r':\s+', ':', reg_platform.group(0).strip())
          platform_capabilities = platform_line.split(',  ')

          # add the platform info to the list
          discovery_list.append(platform_capabilities[0])
          discovery_list.append(platform_capabilities[1])
        except AttributeError:
          discovery_list.append('Platform:')
          discovery_list.append('Capabilities:')

        # search for interface information
        reg_int = search(r'(Interface:.+?)\n', element)

        try:

          # parse interface info and clean it up
          int_line = sub(r':\s+', ':', reg_int.group(0).strip())
          interface_port_id = int_line.split(',  ')

          # add interface info to the list
          discovery_list.append(interface_port_id[0])
          discovery_list.append(interface_port_id[1])
        except AttributeError:
          discovery_list.append('Interface:')
          discovery_list.append('Port ID (outgoing port):')

        # search for advertisement info
        reg_advertisment_ver = search(r'(advertisement version:.+?)\n', element)

        try:

          # parse advertisement info and clean it up
          discovery_list += [sub(r':\s+', ':', reg_advertisment_ver.group(0).strip())]
        except AttributeError:
          discovery_list.append('advertisement version:')

        # search for protocol information
        reg_protocol_hello = search(r'(Protocol Hello:.+?)\n', element)

        try:

          # parse protocol info and clean it up
          discovery_list += [sub(r':\s+', ':', reg_protocol_hello.group(0).strip())]
        except AttributeError:
          discovery_list.append('Protocol Hello:')

        # search for vtp mgnt domain
        reg_vtp_mgnt = search(r'(VTP Management Domain:.+?)\n', element)

        try:

          # parse vtp mgnt info and clean it up
          discovery_list += [sub(r':\s+', ':', reg_vtp_mgnt.group(0).strip())]
        except AttributeError:
          discovery_list.append('VTP Management Domain:')

        # search for native vlan info
        reg_native_vlan = search(r'(Native VLAN:.+?)\n', element)

        try:

          # parse native vlan info and clean it up
          discovery_list += [sub(r':\s+', ':', reg_native_vlan.group(0).strip())]
        except AttributeError:
          discovery_list.append('Native VLAN:')

        # search for duplex info
        reg_duplex = search(r'(Duplex:.+?)\n', element)

        try:

          # parse duplex info and clean it up
          discovery_list += [sub(r':\s+', ':', reg_duplex.group(0).strip())]
        except AttributeError:
          discovery_list.append('Duplex:')

        # search for power info
        reg_power_drawn = search(r'(Power drawn:.+?)\n', element)

        try:

          # parse power info and clean it up
          discovery_list += [sub(r':\s+', ':', reg_power_drawn.group(0).strip())]
        except AttributeError:
          discovery_list.append('Power drawn:')

        # build the discovery protocol dictionary from the list
        discovery_dictionary = dict(map(str, x.split(':')) for x in discovery_list)

        # iterate the key, value pairs and change empty value to None
        for k, v in discovery_dictionary.items():
          if v is '':
            discovery_dictionary[k] = None

        if discovery_dictionary['Device ID'] is not None:

          # add cdp data to the discovery_protocol_findings table
          add_cdp_data = DiscoveryProtocolFinding(local_device_id=ios_fqdn,
                                                  remote_device_id=discovery_dictionary['Device ID'],
                                                  ip_addr=discovery_dictionary['IP'],
                                                  platform=discovery_dictionary['Platform'],
                                                  capabilities=discovery_dictionary['Capabilities'],
                                                  interface=discovery_dictionary['Interface'],
                                                  port_id=discovery_dictionary['Port ID (outgoing port)'],
                                                  discovery_version=discovery_dictionary['advertisement version'],
                                                  protocol_hello=discovery_dictionary['Protocol Hello'],
                                                  vtp_domain=discovery_dictionary['VTP Management Domain'],
                                                  native_vlan=discovery_dictionary['Native VLAN'],
                                                  duplex=discovery_dictionary['Duplex'],
                                                  power_draw=discovery_dictionary['Power drawn'])
          session.add(add_cdp_data)
          session.commit()
    scdp_f.close()
  except FileNotFoundError as e:
    print(e)
