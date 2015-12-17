import xml.etree.ElementTree as ET
from lib.db_connector import connect
from sqlalchemy.exc import IntegrityError
from models.db_tables import InventoryHost, MACVendor, Product, Vendor, InventorySvc, HostNseScript, SvcNseScript

"""Connect to the database"""
Session = connect()
session = Session()


def parse_seed_nmap_xml(nmap_xml):

  #  Set variables
  cpe = 'None'
  os_product = 'None'
  svc_cpe_product_type = 'None'

  # ports_info = []
  svc_nse_script_id_a = []
  svc_nse_script_output_a = []
  host_nse_script_id_a = []
  host_nse_script_output_a = []

  v4_addr = None
  v6_addr = None
  mac_addr = None
  mac_vendor = None
  ostype = None
  os_cpe = None
  host_name = None
  product_type = None
  product_vendor = None
  product_name = None
  product_version = None
  product_update = None
  product_edition = None
  product_language = None
  svc_cpe_product_vendor = None
  svc_cpe_product_name = None
  svc_cpe_product_version = None
  svc_cpe_product_update = None
  svc_cpe_product_edition = None
  svc_cpe_product_language = None
  # protocol = None
  # portid = None
  service_name = None
  ex_info = None
  service_product = None
  # host_nse_script_id = None
  # host_nse_script_output = None
  # svc_nse_script_id = None
  # svc_nse_script_output = None

  #  Parse the nmap xml files from this directory, and build the tree
  try:
      tree = ET.parse(nmap_xml)
      root = tree.getroot()
  except ET.ParseError:
      print('could not parse xml')
      return

  #  Find all the hosts in the nmap scan
  for host in root.findall('host'):

    #  Get the hosts state, and find all addresses
    state = host[0].get('state')

    if state == 'up':

      addresses = host.findall('address')
      for address in addresses:

        if address.attrib.get('addrtype') == 'ipv4':
          v4_addr = address.attrib.get('addr')

        if address.attrib.get('addrtype') == 'mac':
          mac_addr = address.attrib.get('addr')
          mac_vendor = address.attrib.get('vendor')

        if address.attrib.get('addrtype') == 'ipv6':
          v6_addr = address.attrib.get('addr')

      #  Get the hostname
      host_info = host.find('hostnames')
      hostname = host_info.find('hostname')
      try:
        host_name = hostname.get('name')
      except AttributeError:
        """Nothing found"""

      #  Get OS Info
      os_elm = host.find('os')
      try:
        osmatch_elm = os_elm.find('osmatch')
        osclass_elm = osmatch_elm.findall('osclass')
        ostype = osclass_elm[0].get('type')
        os_cpe = osclass_elm[0][0].text
      except:
        """Nothing found"""

      #  Get Host NSE Script Info
      try:
        find_host_nse_scripts = host.find('hostscript')

        for host_nse_script in find_host_nse_scripts:
          host_nse_script_id = host_nse_script.get('id')
          host_nse_script_output = host_nse_script.get('output')

          #  Build a dictionary of the NSE script names and output
          host_nse_script_id_a.append(host_nse_script_id)
          host_nse_script_output_a.append(host_nse_script_output)
      except TypeError:
        """Nothing found"""

      current_state = state
      name = host_name
      ipv4 = v4_addr
      ipv6 = v6_addr
      mac = mac_addr
      m_vendor = mac_vendor
      current_os = os_cpe

      #  Clean the slate
      try:
        session.query(InventoryHost).filter(InventoryHost.ipv4_addr == ipv4).update({InventoryHost.macaddr: None,
                                                                                     InventoryHost.ipv6_addr: None,
                                                                                     InventoryHost.host_name: None,
                                                                                     InventoryHost.mac_vendor_id: None,
                                                                                     InventoryHost.state: 'down',
                                                                                     InventoryHost.product_id: None})
        session.commit()
      except IntegrityError:
        session.rollback()

      #  Find Vendor for MAC address
      add_mac_vendor = MACVendor(name=m_vendor)

      try:
        session.add(add_mac_vendor)
        session.commit()
        select_mac = session.query(MACVendor).filter_by(name=m_vendor).first()
      except IntegrityError:
        session.rollback()
        select_mac = session.query(MACVendor).filter_by(name=m_vendor).first()

      # Build product info for host OS
      try:
        os_product = current_os.split(':')
      except AttributeError:
        """Nothing Found"""
      try:
        product_type = os_product[1]
      except IndexError:
        """Nothing Found"""
      try:
        product_vendor = os_product[2]
      except IndexError:
        """Nothing Found"""
      try:
        product_name = os_product[3]
      except IndexError:
        """Nothing Found"""
      try:
        product_version = os_product[4]
      except IndexError:
        """Nothing Found"""
      try:
        product_update = os_product[5]
      except IndexError:
        """Nothing Found"""
      try:
        product_edition = os_product[6]
      except IndexError:
        """Nothing Found"""
      try:
        product_language = os_product[6]
      except IndexError:
        """Nothing Found"""

      #  Add the OS Vendor to the database
      add_prod_vendor = Vendor(name=product_vendor)

      try:
        session.add(add_prod_vendor)
        session.commit()

        # Get vendor.id for product info
        select_prod_vendor = session.query(Vendor).filter_by(name=product_vendor).first()
      except IntegrityError:

        #  Vendor exists
        session.rollback()

        #  Get vendor.id for product info
        select_prod_vendor = session.query(Vendor).filter_by(name=product_vendor).first()

      #  Get the OS product.id if it exists
      os_product = session.query(Product).filter_by(product_type=product_type.replace('/', ''),
                                                    vendor_id=select_prod_vendor.id,
                                                    name=product_name,
                                                    version=product_version,
                                                    product_update=product_update,
                                                    edition=product_edition,
                                                    language=product_language).first()

      #  Add the OS product to the database
      add_product = Product(product_type=product_type.replace('/', ''),
                            vendor_id=select_prod_vendor.id,
                            name=product_name,
                            version=product_version,
                            product_update=product_update,
                            edition=product_edition,
                            language=product_language)

      #  If the OS product does not exist, add it
      if os_product is None:
        try:
          session.add(add_product)
          session.commit()

          #  Get the OS product.id
          os_product = session.query(Product).filter_by(product_type=product_type.replace('/', ''),
                                                        vendor_id=select_prod_vendor.id,
                                                        name=product_name,
                                                        version=product_version,
                                                        product_update=product_update,
                                                        edition=product_edition,
                                                        language=product_language).first()
        except IntegrityError:

          #  This should not happen, but if it does..
          session.rollback()

      #  Add host info to database
      add_inventory_host = InventoryHost(ipv4_addr=ipv4,
                                         ipv6_addr=ipv6,
                                         macaddr=mac,
                                         host_type=ostype,
                                         host_name=name,
                                         mac_vendor_id=select_mac.id,
                                         state=current_state,
                                         product_id=os_product.id)

      try:
        session.add(add_inventory_host)
        session.commit()
      except IntegrityError:

        #  I exist, update me instead
        session.rollback()
        session.query(InventoryHost).filter(InventoryHost.ipv4_addr == ipv4)\
                                    .update({InventoryHost.macaddr: mac, InventoryHost.ipv6_addr: ipv6,
                                             InventoryHost.host_name: name,
                                             InventoryHost.host_type: ostype,
                                             InventoryHost.mac_vendor_id: select_mac.id,
                                             InventoryHost.state: current_state,
                                             InventoryHost.product_id: os_product.id})
        session.commit()

      #  Get the inventory_hosts.id for this host
      inventory_hosts = session.query(InventoryHost).filter_by(ipv4_addr=ipv4).first()

      #  Clean out the old HostNseScript
      session.query(HostNseScript).filter(HostNseScript.inventory_host_id == inventory_hosts.id).delete()
      session.commit()

      #  Add the new HostNseScripts
      host_nse_script_keys = host_nse_script_id_a
      host_nse_script_values = host_nse_script_output_a

      host_nse_scripts_dict = dict(zip(host_nse_script_keys, host_nse_script_values))

      for k, v in host_nse_scripts_dict.items():
        add_nse_script_op = HostNseScript(inventory_host_id=inventory_hosts.id,
                                          name=k,
                                          output=v)
        session.add(add_nse_script_op)
        session.commit()

      #  Find all port Info
      port_info = host.findall('ports')

      #  Clean out the old Inventory_svcs
      session.query(InventorySvc).filter(InventorySvc.inventory_host_id == inventory_hosts.id).delete()
      session.commit()
      for ports in port_info:
        # inventory_svcs_id_list = []
        p = ports.findall('port')
        for each_port in p:
          protocol = each_port.get('protocol')
          portid = each_port.get('portid')
          service_info = each_port.find('service')
          findall_cpe = service_info.findall('cpe')
          try:
            cpe = findall_cpe[0].text
          except IndexError:
            """Nothing Found"""
          try:
            ex_info = service_info.get('extrainfo')
          except IndexError:
            """Nothing Found"""

          #  Get the NSE script info
          findall_svc_nse_scripts = each_port.findall('script')
          try:
            svc_nse_scripts = findall_svc_nse_scripts
            for svc_nse_script in svc_nse_scripts:
              svc_nse_script_id = svc_nse_script.get('id')
              svc_nse_script_output = svc_nse_script.get('output')

              #  Build a dictionary of the NSE script names and output
              svc_nse_script_id_a.append(svc_nse_script_id)
              svc_nse_script_output_a.append(svc_nse_script_output)
          except IndexError:
            """Nothing Found"""
            service_name = service_info.get('name')
            service_product = service_info.get('product')

            #  Build product info for SVC CPE
          try:
            svc_cpe_product = cpe.split(':')
          except AttributeError:
            """Nothing Found"""
          try:
            svc_cpe_product_type = svc_cpe_product[1]
          except IndexError:
            """Nothing Found"""
          try:
            svc_cpe_product_vendor = svc_cpe_product[2]
          except IndexError:
            """Nothing Found"""
          try:
            svc_cpe_product_name = svc_cpe_product[3]
          except IndexError:
            """Nothing Found"""
          try:
            svc_cpe_product_version = svc_cpe_product[4]
          except IndexError:
            """Nothing Found"""
          try:
            svc_cpe_product_update = svc_cpe_product[5]
          except IndexError:
            """Nothing Found"""
          try:
            svc_cpe_product_edition = svc_cpe_product[6]
          except IndexError:
            """Nothing Found"""
          try:
            svc_cpe_product_language = svc_cpe_product[6]
          except IndexError:
            """Nothing Found"""

          #  Add SVC and CPE info to database
          if 'cpe:' in cpe:

            #  Add CPE Vendor info to the database
            add_svc_cpe_prod_vendor = Vendor(name=svc_cpe_product_vendor)

            try:
              session.add(add_svc_cpe_prod_vendor)
              session.commit()

              #  Get the CPE vendor.id
              select_cpe_prod_vendor = session.query(Vendor).filter_by(name=svc_cpe_product_vendor).first()
            except IntegrityError:

              #  You must already exist, just get the CPE vendor.id
              session.rollback()
              select_cpe_prod_vendor = session.query(Vendor).filter_by(name=svc_cpe_product_vendor).first()
            finally:

              #  What ever you do, make sure you get the CPE vendor.id!
              select_cpe_prod_vendor = session.query(Vendor).filter_by(name=svc_cpe_product_vendor).first()

              #  Add SVC CPE Product info to database
            try:

              #  Get the products.id
              svc_product = session.query(Product)\
                                   .filter_by(product_type=svc_cpe_product_type.replace('/', ''),
                                              vendor_id=select_cpe_prod_vendor.id,
                                              name=svc_cpe_product_name,
                                              version=svc_cpe_product_version,
                                              product_update=svc_cpe_product_update,
                                              edition=svc_cpe_product_edition,
                                              language=svc_cpe_product_language).first()
            except AttributeError:
              """Nothing Found"""

            try:

              #  Add the new Product to the database
              add_svc_product = Product(product_type=svc_cpe_product_type.replace('/', ''),
                                        vendor_id=select_cpe_prod_vendor.id,
                                        name=svc_cpe_product_name,
                                        version=svc_cpe_product_version,
                                        product_update=svc_cpe_product_update,
                                        edition=svc_cpe_product_edition,
                                        language=svc_cpe_product_language)
            except AttributeError:
              """Nothing Found"""

            #  If the product does not exist, add it
            if svc_product is None:
              try:
                session.add(add_svc_product)
                session.commit()

                #  Get the products.id of the Product you just added
                svc_product = session.query(Product)\
                                     .filter_by(product_type=svc_cpe_product_type.replace('/', ''),
                                                vendor_id=select_cpe_prod_vendor.id,
                                                name=svc_cpe_product_name,
                                                version=svc_cpe_product_version,
                                                product_update=svc_cpe_product_update,
                                                edition=svc_cpe_product_edition,
                                                language=svc_cpe_product_language).first()
              except IntegrityError:

                #  Then you must already exist
                session.rollback()

            #  Add the new inventory_svc
            add_inventory_svcs = InventorySvc(inventory_host_id=inventory_hosts.id,
                                              protocol=protocol,
                                              portid=portid,
                                              name=service_name,
                                              svc_product=service_product,
                                              product_id=svc_product.id,
                                              extra_info=ex_info)

            try:
              session.add(add_inventory_svcs)
              session.commit()

              #  Get the inventory_svcs.id
              svc = session.query(InventorySvc).filter_by(inventory_host_id=inventory_hosts.id,
                                                          protocol=protocol,
                                                          portid=portid,
                                                          name=service_name,
                                                          svc_product=service_product,
                                                          product_id=svc_product.id,
                                                          extra_info=ex_info).first()

              #  Add the new SvcNseScripts
              svc_nse_script_keys = svc_nse_script_id_a
              svc_nse_script_values = svc_nse_script_output_a

              #  Put the two NSE id and output lists together as a dictionary
              svc_nse_scripts_dict = dict(zip(svc_nse_script_keys, svc_nse_script_values))

              for k, v in svc_nse_scripts_dict.items():
                add_nse_script_op = SvcNseScript(inventory_svc_id=svc.id,
                                                 name=k,
                                                 output=v)
                session.add(add_nse_script_op)
                session.commit()

            except IntegrityError:
              #  Then I must exist, but I can't...
              session.rollback()

          #  Add SVC only info to database
          else:
            add_inventory_svcs = InventorySvc(inventory_host_id=inventory_hosts.id,
                                              protocol=protocol,
                                              portid=portid,
                                              name=service_name,
                                              svc_product=service_product,
                                              extra_info=ex_info)
            try:
              session.add(add_inventory_svcs)
              session.commit()

              #  Get the inventory_svcs.id
              inventory_svcs = session.query(InventorySvc).filter_by(inventory_host_id=inventory_hosts.id,
                                                                     protocol=protocol,
                                                                     portid=portid,
                                                                     name=service_name,
                                                                     svc_product=service_product,
                                                                     extra_info=ex_info).first()
            except IntegrityError:

              #  Then I must exist, but I can't...
              session.rollback()

            session.commit()

            #  Add the new SvcNseScripts
            svc_nse_script_keys = svc_nse_script_id_a
            svc_nse_script_values = svc_nse_script_output_a

            svc_nse_scripts_dict = dict(zip(svc_nse_script_keys, svc_nse_script_values))

            for k, v in svc_nse_scripts_dict.items():
              add_nse_script_op = SvcNseScript(inventory_svc_id=inventory_svcs.id,
                                               name=k,
                                               output=v)
              session.add(add_nse_script_op)
              session.commit()
  session.close()
