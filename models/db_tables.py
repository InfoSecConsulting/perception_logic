from sqlalchemy import Column, Integer, Text, ForeignKey, Sequence, TIMESTAMP, String
from sqlalchemy.orm import relationship
from sqlalchemy.dialects import postgresql
from sqlalchemy.ext.declarative import declarative_base
from lib.crypt import encrypt_string
import datetime

Base = declarative_base()


def _get_date():
    return datetime.datetime.now()


class Vendor(Base):
  __tablename__ = 'vendors'

  id = Column(Integer, Sequence('vendors_id_seq'), primary_key=True, nullable=False)
  name = Column(Text, unique=True, nullable=False)
  created_at = Column(TIMESTAMP(timezone=False), default=_get_date)
  updated_at = Column(TIMESTAMP(timezone=False), default=_get_date)


class Product(Base):
  __tablename__ = 'products'

  id = Column(Integer, Sequence('products_id_seq'), primary_key=True, nullable=False)

  product_type = Column(Text, nullable=False)

  """Relation to tie vendors to products"""
  vendor_id = Column(Integer, ForeignKey('vendors.id'), nullable=False)
  vendor = relationship('Vendor', backref='products', order_by=id)

  name = Column(Text, nullable=False)
  version = Column(Text)
  product_update = Column(Text)
  edition = Column(Text)
  language = Column(Text)
  created_at = Column(TIMESTAMP(timezone=False), default=_get_date)
  updated_at = Column(TIMESTAMP(timezone=False), default=_get_date)


class NvdVulnSource(Base):
  __tablename__ = 'nvd_vuln_sources'

  id = Column(Integer, Sequence('nvd_vuln_sources_id_seq'), primary_key=True, nullable=False)
  name = Column(Text)


class NvdVulnReference(Base):
  __tablename__ = 'nvd_vuln_references'

  id = Column(Integer, Sequence('nvd_vuln_references_id_seq'), primary_key=True, nullable=False)

  """Relation to tie vulnerability source disclosure to NVD vulnerabilities"""
  nvd_vuln_source_id = Column(Integer, ForeignKey('nvd_vuln_sources.id'), nullable=False)
  nvd_vuln_source = relationship('NvdVulnSource', backref='nvd_vuln_references', order_by=id)

  nvd_ref_type = Column(Text)
  href = Column(Text)
  created_at = Column(TIMESTAMP(timezone=False), default=_get_date)
  updated_at = Column(TIMESTAMP(timezone=False), default=_get_date)


class NvdVuln(Base):
  __tablename__ = 'nvd_vulns'

  id = Column(Integer, Sequence('nvd_vulns_id_seq'), primary_key=True, nullable=False)
  name = Column(Text, unique=True, nullable=False)

  """Relation to tie products to vulnerabilities from the NVD"""
  product_id = Column(Integer, ForeignKey('products.id'), nullable=False)
  product = relationship('Product', backref='nvd_vulns', order_by=id)

  cveid = Column(Text, nullable=False)
  vuln_published = Column(Text)
  vuln_updated = Column(Text)
  cvss = Column(Text)
  cweid = Column(Text)

  """Relation to tie references to vulnerabilities from the NVD"""
  nvd_vuln_reference_id = Column(Integer, ForeignKey('nvd_vuln_references.id'))
  nvd_vuln_reference = relationship('NvdVulnReference', backref='nvd_vulns', order_by=id)

  summary = Column(Text)
  created_at = Column(TIMESTAMP(timezone=False))
  updated_at = Column(TIMESTAMP(timezone=False))


class MACVendor(Base):
  __tablename__ = 'mac_vendors'

  id = Column(Integer, Sequence('mac_vendors_id_seq'), primary_key=True, nullable=False)
  name = Column(Text, unique=True)


class SmbUser(Base):
  __tablename__ = 'smb_users'

  id = Column(Integer, primary_key=True, nullable=False)
  username = Column(String, nullable=False, unique=True)
  encrypted_password = Column(String, nullable=False)
  encrypted_password_salt = Column(String, nullable=False)
  description = Column(String)

  created_at = Column(TIMESTAMP(timezone=False), default=_get_date)
  updated_at = Column(TIMESTAMP(timezone=False), onupdate=_get_date)

  def __init__(self,
               username=None,
               password=None,
               description=None):

    if description:
      self.description = description

    if username:
      self.username = username

    if password:
      password_tup = encrypt_string(str.encode(password))
      self.encrypted_password = password_tup[0].decode("utf-8")
      self.encrypted_password_salt = password_tup[1].decode("utf-8")


class LinuxUser(Base):
  __tablename__ = 'linux_users'

  id = Column(Integer, primary_key=True, nullable=False)
  username = Column(String, nullable=False, unique=True)
  encrypted_password = Column(String, nullable=False)
  encrypted_password_salt = Column(String, nullable=False)
  encrypted_enable_password = Column(String)
  encrypted_enable_password_salt = Column(String)
  description = Column(String)

  created_at = Column(TIMESTAMP(timezone=False), default=_get_date)
  updated_at = Column(TIMESTAMP(timezone=False), onupdate=_get_date)

  def __init__(self,
               username=None,
               password=None,
               enable_password=None,
               description=None):
    if description:
      self.description = description

    if username:
      self.username = username

    if password:
      password_tup = encrypt_string(str.encode(password))
      self.encrypted_password = password_tup[0].decode("utf-8")
      self.encrypted_password_salt = password_tup[1].decode("utf-8")

    if enable_password:
      enable_password_tup = encrypt_string(str.encode(enable_password))
      self.encrypted_enable_password = enable_password_tup[0].decode('utf-8')
      self.encrypted_enable_password_salt = enable_password_tup[1].decode('utf-8')


class InventoryHost(Base):
  __tablename__ = 'inventory_hosts'

  id = Column(Integer, Sequence('inventory_hosts_id_seq'), primary_key=True, nullable=False)
  ipv4_addr = Column(postgresql.INET, unique=True)
  ipv6_addr = Column(postgresql.INET)
  macaddr = Column(postgresql.MACADDR)
  host_type = Column(Text)

  """Relation to tie mac address vendors to inventory hosts"""
  mac_vendor_id = Column(Integer, ForeignKey('mac_vendors.id'))
  mac_vendor = relationship('MACVendor', backref='inventory_hosts', order_by=id)

  state = Column(Text)
  host_name = Column(Text)

  """Relation to tie an OS inventory hosts"""
  product_id = Column(Integer, ForeignKey('products.id'))
  product = relationship('Product', backref='inventory_hosts', order_by=id)

  arch = Column(Text)

  """Relation to tie users to inventory hosts"""
  smb_user_id = Column(Integer, ForeignKey('smb_users.id'))
  smb_user = relationship('SmbUser', backref='inventory_hosts', order_by=id)

  linux_user_id = Column(Integer, ForeignKey('linux_users.id'))
  linux_user = relationship('LinuxUser', backref='inventory_hosts', order_by=id)

  info = Column(Text)
  comments = Column(Text)

  """Relation to tie NVD vulnerabilities to inventory hosts"""
  nvd_vuln_id = Column(Integer, ForeignKey('nvd_vulns.id'))
  nvd_vuln = relationship('NvdVuln', backref='inventory_hosts', order_by=id)

  created_at = Column(TIMESTAMP(timezone=False), default=_get_date)
  updated_at = Column(TIMESTAMP(timezone=False), onupdate=_get_date)


class HostNseScript(Base):
  __tablename__ = 'host_nse_scripts'

  id = Column(Integer, Sequence('host_nse_scripts_id_seq'), primary_key=True, nullable=False)

  """Relation to host"""
  inventory_host_id = Column(Integer, ForeignKey('inventory_hosts.id', ondelete='cascade'))
  inventory_host = relationship('InventoryHost', backref='host_nse_scripts', order_by=id)

  name = Column(Text, nullable=False)
  output = Column(Text, nullable=False)
  created_at = Column(TIMESTAMP(timezone=False), default=_get_date)
  updated_at = Column(TIMESTAMP(timezone=False), default=_get_date)


class InventorySvc(Base):
  __tablename__ = 'inventory_svcs'

  id = Column(Integer, Sequence('inventory_svcs_id_seq'), primary_key=True, nullable=False)

  """Relation to inventory inventory_host"""
  inventory_host_id = Column(Integer, ForeignKey('inventory_hosts.id', ondelete='cascade'))
  inventory_host = relationship('InventoryHost', backref='inventory_svcs', order_by=id)

  protocol = Column(Text)
  portid = Column(Integer)
  name = Column(Text)
  svc_product = Column(Text)
  extra_info = Column(Text)

  """Relation to tie products to inventory services"""
  product_id = Column(Integer, ForeignKey('products.id'))
  product = relationship('Product', backref='inventory_svcs', order_by=id)

  created_at = Column(TIMESTAMP(timezone=False), default=_get_date)
  updated_at = Column(TIMESTAMP(timezone=False), default=_get_date)

class SvcNseScript(Base):
  __tablename__ = 'svc_nse_scripts'

  id = Column(Integer, Sequence('svc_nse_scripts_id_seq'), primary_key=True, nullable=False)

  """Relation to inventory_svc"""
  inventory_svc_id = Column(Integer, ForeignKey('inventory_svcs.id', ondelete='cascade'))
  inventory_svc = relationship('InventorySvc', backref='svc_nse_scripts', order_by=id)

  name = Column(Text, nullable=False)
  output = Column(Text, nullable=False)


class LocalNet(Base):
  __tablename__ = 'local_nets'

  id = Column(Integer, primary_key=True, nullable=False)
  subnet = Column(postgresql.CIDR, unique=True)
  created_at = Column(TIMESTAMP(timezone=False), default=_get_date)


class DiscoveryProtocolFinding(Base):
  __tablename__ = 'discovery_protocol_findings'

  id = Column(Integer, primary_key=True, nullable=False)
  local_device_id = Column(Text, nullable=False)
  remote_device_id = Column(Text, nullable=False)
  ip_addr = Column(postgresql.INET)
  platform = Column(Text)
  capabilities = Column(Text)
  interface = Column(Text)
  port_id = Column(Text)
  discovery_version = Column(Integer)
  protocol_hello = Column(Text)
  vtp_domain = Column(Text)
  native_vlan = Column(Integer)
  duplex = Column(Text)
  power_draw = Column(Text)
  created_at = Column(TIMESTAMP(timezone=False), default=_get_date)
  updated_at = Column(TIMESTAMP(timezone=False), default=_get_date)


class LocalHost(Base):
  __tablename__ = 'local_hosts'

  id = Column(Integer, primary_key=True, nullable=False)
  ip_addr = Column(postgresql.INET, unique=True, nullable=False)
  mac_addr = Column(postgresql.MACADDR, unique=True, nullable=False)
  created_at = Column(TIMESTAMP(timezone=False), default=_get_date)
  updated_at = Column(TIMESTAMP(timezone=False), default=_get_date)


class CoreRouter(Base):
  __tablename__ = 'core_routers'

  id = Column(Integer, Sequence('core_routers_id_seq'), primary_key=True, nullable=False)
  ip_addr = Column(postgresql.INET, unique=True, nullable=False)
  host_name = Column(Text, unique=True)

  """Relation to linux_user"""
  linux_user_id = Column(Integer, ForeignKey('linux_users.id', ondelete='cascade'))
  linux_users = relationship('LinuxUser', backref='core_routers', order_by=id)

  created_at = Column(TIMESTAMP(timezone=False), default=_get_date)
  updated_at = Column(TIMESTAMP(timezone=False), default=_get_date)

  def __init__(self, linux_user_id,
               ip_addr,
               host_name=None):

    self.linux_user_id = linux_user_id
    self.ip_addr = ip_addr

    if host_name:
      self.host_name = host_name


class SnmpString(Base):
  __tablename__ = 'snmp_strings'

  id = Column(Integer, Sequence('snmp_strings_id_seq'), primary_key=True, nullable=False)
  community_string_encrypted = Column(String)
  community_string_encrypted_salt = Column(String)
  snmp_user_encrypted = Column(String)
  snmp_user_encrypted_salt = Column(String)
  snmp_group_encrypted = Column(String)
  snmp_group_encrypted_salt = Column(String)

  created_at = Column(TIMESTAMP(timezone=False), default=_get_date)
  updated_at = Column(TIMESTAMP(timezone=False), default=_get_date)

  def __init__(self,
               community_string=None,
               snmp_user=None,
               snmp_group=None):

    if community_string:
      community_string_tup = encrypt_string(str.encode(community_string))
      self.community_string_encrypted = community_string_tup[0].decode("utf-8")
      self.community_string_encrypted_salt = community_string_tup[1].decode("utf-8")

    if snmp_user:
      snmp_user_tup = encrypt_string(str.encode(snmp_user))
      self.snmp_user_encrypted = snmp_user_tup[0].decode('utf-8')
      self.snmp_user_encrypted_salt = snmp_user_tup[1].decode('utf-8')

    if snmp_group:
      snmp_group_tup = encrypt_string(str.encode(snmp_group))
      self.snmp_group_encrypted = snmp_group_tup[0].decode('utf-8')
      self.snmp_group_encrypted_salt = snmp_group_tup[1].decode('utf-8')
