from lib.db_connector import connect
from models.db_tables import LocalHost, InventoryHost
from datetime import datetime, timedelta

# Connect to the database
Session = connect()
session = Session()


def get_hosts():

  # build empty lists
  inventory = list()
  scan_list = list()

  # query the database for the latest local hosts
  now = datetime.now()
  five_minutes_ago = str(datetime.now() - timedelta(minutes=5))
  five_min_query = session.query(LocalHost).filter(LocalHost.updated_at.between(five_minutes_ago, now))

  # compare the all local hosts to the current inventory
  all_local_hosts = session.query(LocalHost).all()
  all_inventory_hosts = session.query(InventoryHost).all()

  # append current inventory to the inventory list
  for inventory_host in all_inventory_hosts:
    inventory.append(inventory_host.ipv4_addr)

  # if any local hosts are not in the inventory add it to the scan list
  for local_host in all_local_hosts:
    if local_host.ip_addr not in inventory:
      scan_list.append(local_host.ip_addr)

  # the latest local hosts are not in the scan list add them
  for current_local_host in five_min_query:
    if current_local_host.ip_addr not in scan_list:
      scan_list.append(current_local_host.ip_addr)

  return scan_list
