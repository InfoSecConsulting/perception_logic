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


class OpenvasAdmin(Base):
  __tablename__ = 'openvas_admin'

  id = Column(Integer, Sequence('openvas_admin_id_seq'), primary_key=True, nullable=False)
  username = Column(Text, unique=True, nullable=False)
  password = Column(postgresql.UUID, nullable=False)
  created_at = Column(TIMESTAMP(timezone=False), default=_get_date)
  updated_at = Column(TIMESTAMP(timezone=False), onupdate=_get_date)


class MACVendor(Base):
  __tablename__ = 'mac_vendors'

  id = Column(Integer, Sequence('mac_vendors_id_seq'), primary_key=True, nullable=False)
  name = Column(Text, unique=True)


class SmbUser(Base):
  __tablename__ = 'smb_users'

  id = Column(Integer, primary_key=True, nullable=False)
  username = Column(String, nullable=False, unique=True)
  openvas_lsc_id = Column(postgresql.UUID)
  encrypted_password = Column(String, nullable=False)
  encrypted_password_salt = Column(String, nullable=False)
  domain_name = Column(String, nullable=False)
  description = Column(String)

  created_at = Column(TIMESTAMP(timezone=False), default=_get_date)
  updated_at = Column(TIMESTAMP(timezone=False), onupdate=_get_date)

  def __init__(self,
               username=None,
               password=None,
               domain_name=None,
               description=None,
               openvas_lsc_id=None):

    if domain_name:
      self.domain_name = domain_name

    if description:
      self.description = description

    if username:
      self.username = username

    if password:
      password_tup = encrypt_string(str.encode(password))
      self.encrypted_password = password_tup[0].decode("utf-8")
      self.encrypted_password_salt = password_tup[1].decode("utf-8")

    if openvas_lsc_id:
      self.openvas_lsc_id = openvas_lsc_id


class LinuxUser(Base):
  __tablename__ = 'linux_users'

  id = Column(Integer, primary_key=True, nullable=False)
  username = Column(String, nullable=False, unique=True)
  openvas_lsc_id = Column(postgresql.UUID)
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
               description=None,
               openvas_lsc_id=None):

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

    if openvas_lsc_id:
      self.openvas_lsc_id = openvas_lsc_id


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
  bad_ssh_key = Column(postgresql.BOOLEAN)
  last_openvas_scan = Column(TIMESTAMP(timezone=False))
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


class OpenvasLastUpdate(Base):
  __tablename__ = 'openvas_last_updates'

  id = Column(Integer, Sequence('openvas_last_updates_id_seq'), primary_key=True, nullable=False)
  updated_at = Column(TIMESTAMP(timezone=False), nullable=False)


class Target(Base):
  __tablename__ = 'targets'

  id = Column(Integer, Sequence('targets_id_seq'), primary_key=True, nullable=False)
  ip_addr = Column(postgresql.INET, unique=True)
  subnet = Column(postgresql.CIDR, unique=True)
  created_at = Column(TIMESTAMP(timezone=False), default=_get_date)
  updated_at = Column(TIMESTAMP(timezone=False), onupdate=_get_date)

  def __init__(self,
               ipd_addr=None,
               subnet=None):

    if ipd_addr:
      self.ip_addr = ipd_addr

    if subnet:
      self.subnet = subnet


class DayOfTheWeek(Base):
  __tablename__ = 'days_of_the_week'

  id = Column(Integer, Sequence('days_of_the_week_id_seq'), primary_key=True, nullable=False)
  name = Column(Text, nullable=False, unique=True)
  created_at = Column(TIMESTAMP(timezone=False), default=_get_date)


class ScheduleType(Base):
  __tablename__ = 'schedule_types'

  id = Column(Integer, Sequence('schedule_types_id_seq'), primary_key=True, nullable=False)
  name = Column(Text, nullable=False, unique=True)
  created_at = Column(TIMESTAMP(timezone=False), default=_get_date)


class Schedule(Base):
  __tablename__ = 'schedules'

  id = Column(Integer, Sequence('schedules_id_seq'), primary_key=True, nullable=False)
  name = Column(Text, nullable=False)

  schedule_type_id = Column(Integer, ForeignKey('schedule_types.id'))
  schedule_types = relationship('ScheduleType', backref='schedules', order_by=id)

  start_date = Column(TIMESTAMP(timezone=False))
  created_at = Column(TIMESTAMP(timezone=False), default=_get_date)
  updated_at = Column(TIMESTAMP(timezone=False), onupdate=_get_date)


class DailySchedule(Base):
  __tablename__ = 'daily_schedules'

  id = Column(Integer, Sequence('daily_schedules_id_seq'), primary_key=True, nullable=False)

  """Relation to schedules"""
  schedule_id = Column(Integer, ForeignKey('schedules.id'), nullable=False)
  schedules = relationship('Schedule', backref='daily_schedules', order_by=id)

  """Relation to days_of_the_week"""
  day_of_week_id = Column(Integer, ForeignKey('days_of_the_week.id'), nullable=False)
  days_of_week = relationship('DayOfTheWeek', backref='daily_schedules', order_by=id)

  time_of_day = Column(postgresql.TIME, nullable=False)
  start_date = Column(TIMESTAMP(timezone=False), nullable=False)
  end_date = Column(TIMESTAMP(timezone=False))
  recurrence = Column(Integer, nullable=False)
  created_at = Column(TIMESTAMP(timezone=False), default=_get_date)
  updated_at = Column(TIMESTAMP(timezone=False), onupdate=_get_date)


class WeeklySchedule(Base):
  __tablename__ = 'weekly_schedules'

  id = Column(Integer, Sequence('daily_schedules_id_seq'), primary_key=True, nullable=False)

  """Relation to schedules"""
  schedule_id = Column(Integer, ForeignKey('schedules.id'), nullable=False)
  schedules = relationship('Schedule', backref='weekly_schedules', order_by=id)

  """Relation to days_of_the_week"""
  day_of_week_id = Column(Integer, ForeignKey('days_of_the_week.id'), nullable=False)
  days_of_week = relationship('DayOfTheWeek', backref='weekly_schedules', order_by=id)

  time_of_day = Column(postgresql.TIME, nullable=False)
  start_date = Column(TIMESTAMP(timezone=False), nullable=False)
  end_date = Column(TIMESTAMP(timezone=False))
  recurrence = Column(Integer, nullable=False)
  created_at = Column(TIMESTAMP(timezone=False), default=_get_date)
  updated_at = Column(TIMESTAMP(timezone=False), onupdate=_get_date)


class MonthlySchedule(Base):
  __tablename__ = 'monthly_schedules'

  id = Column(Integer, Sequence('monthly_schedules_id_seq'), primary_key=True, nullable=False)

  """Relation to schedules"""
  schedule_id = Column(Integer, ForeignKey('schedules.id'), nullable=False)
  schedules = relationship('Schedule', backref='monthly_schedules', order_by=id)

  day_of_month = Column(Integer, nullable=False)
  time_of_day = Column(postgresql.TIME, nullable=False)
  created_at = Column(TIMESTAMP(timezone=False), default=_get_date)
  updated_at = Column(TIMESTAMP(timezone=False), onupdate=_get_date)


class OneTimeSchedule(Base):
  __tablename__ = 'one_time_schedules'

  id = Column(Integer, Sequence('one_time_schedules_id_seq'), primary_key=True, nullable=False)

  """Relation to schedules"""
  schedule_id = Column(Integer, ForeignKey('schedules.id'), nullable=False)
  schedules = relationship('Schedule', backref='one_time_schedules', order_by=id)

  start_date = Column(TIMESTAMP(timezone=False), nullable=False)
  created_at = Column(TIMESTAMP(timezone=False), default=_get_date)
  updated_at = Column(TIMESTAMP(timezone=False), onupdate=_get_date)


class Task(Base):
  __tablename__ = 'tasks'

  id = Column(Integer, Sequence('tasks_id_seq'), primary_key=True, nullable=False)

  """Relation to schedules"""
  schedule_id = Column(Integer, ForeignKey('schedules.id'), nullable=False)
  schedules = relationship('Schedule', backref='tasks', order_by=id)

  run_date = Column(TIMESTAMP(timezone=False), nullable=False)
  created_at = Column(TIMESTAMP(timezone=False), default=_get_date)
  updated_at = Column(TIMESTAMP(timezone=False), onupdate=_get_date)


class Vulnerability(Base):
  __tablename__ = 'vulnerabilities'

  id = Column(Integer, primary_key=True, nullable=False)
  name = Column(Text, nullable=False)
  cvss_score = Column(postgresql.FLOAT, nullable=False)
  bug_id = Column(Text)
  family = Column(Text)
  cve_id = Column(Text)

  """Relation to inventory_hosts"""
  inventory_host_id = Column(Integer, ForeignKey('inventory_hosts.id', ondelete='cascade'))
  inventory_host = relationship('InventoryHost', backref='vulnerabilities', order_by=id)

  port = Column(Text)
  threat_score = Column(Text)
  severity_score = Column(postgresql.FLOAT)
  xrefs = Column(Text)
  tags = Column(Text)
  validated = Column(postgresql.BOOLEAN)
  created_at = Column(TIMESTAMP(timezone=False), default=_get_date)


class ScheduleIndex(Base):
  __tablename__ = 'schedules_index'

  id = Column(Integer, primary_key=True, nullable=False)

  """Relation to schedules"""
  schedule_id = Column(Integer, ForeignKey('schedules.id'), nullable=False)
  schedules = relationship('Schedule', backref='schedule_index', order_by=id)

  """Relation to targets"""
  target_id = Column(Integer, ForeignKey('targets.id', ondelete='cascade'))
  target = relationship('Target', backref='schedule_index', order_by=id)
