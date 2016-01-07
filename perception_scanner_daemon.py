from lib.host_profiler import match_creds_to_hosts
from lib.db_connector import connect
from lib.openvas import create_task, create_targets, delete_targets, delete_task, delete_reports, check_task, update_openvas_db, start_task, get_report
from models.db_tables import OpenvasAdmin, OpenvasLastUpdate
from datetime import datetime, timedelta
from time import sleep
from lib.latest_hosts_query import get_hosts
from os import system


# Connect to the database
Session = connect()
session = Session()


# Get openvas user information
openvas_user = session.query(OpenvasAdmin).first()


# make user user is configured
if not openvas_user:
  print('It appears that there is not a current OpenVAS admin in the database, please make sure seed daemon is running.')
  quit()


openvas_user_username = openvas_user.username
openvas_user_password = openvas_user.password
tmp_dir = '/tmp/perception_logic'


def main():
  while True:

    # get current local hosts
    scan_list = get_hosts()

    # validate credentials
    match_creds_to_hosts(scan_list)

    # update openvas NVT's, CERT data, and CPE's
    one_day_ago = datetime.now() - timedelta(hours=24)
    check_last_update = session.query(OpenvasLastUpdate).order_by(OpenvasLastUpdate.id.desc()).first()

    if check_last_update is None or check_last_update.updated_at <= one_day_ago:
      update_openvas_db()
      system('openvassd && openvasmd --migrate && openvasmd --progress --rebuild')
      add_update_info = OpenvasLastUpdate(updated_at=datetime.now())
      session.add(add_update_info)
      session.commit()

    # create the targets to scan
    target_id = create_targets('initial scan targets',
                               openvas_user_username,
                               openvas_user_password,
                               scan_list)

    # setup the task
    task_id = create_task(target_id, openvas_user_username, openvas_user_password)

    # run the task
    xml_report_id = start_task(task_id, openvas_user_username, openvas_user_password)

    # wait until the task is done
    while True:
      check_task_response = check_task(task_id, openvas_user_username, openvas_user_password)
      if check_task_response == 'Done':
        break
      print('still scanning')
      sleep(60)

    # download and parse the report
    get_report(xml_report_id, openvas_user_username, openvas_user_password)

    # delete the task
    delete_task(task_id, openvas_user_username, openvas_user_password)

    # delete the targets
    delete_targets(target_id, openvas_user_username, openvas_user_password)

    # delete the report
    delete_reports(xml_report_id, openvas_user_username, openvas_user_password)

    print('sleeping')
    sleep(300)


if __name__ == '__main__':
  try:
    main()
  except (IOError, SystemExit):
    raise
  except KeyboardInterrupt:
    print('Crtl+C Pressed. Shutting down.')
