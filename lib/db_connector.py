from sys import exit as sys_exit
from lib.yml_parser import db_info
from sqlalchemy import create_engine, exc
from sqlalchemy.orm import sessionmaker
from sqlalchemy.engine.url import URL


Session = sessionmaker()


def connect():
  db_yml = 'etc/database.yml'
  dbinfo = db_info(db_yml)
  cursor = None

  try:

    Session = sessionmaker()
    engine = create_engine(URL(**dbinfo), pool_size=20)
    Session.configure(bind=engine)
    return Session

  except exc.OperationalError as e:
    print(e)
    sys_exit(1)

  finally:
    if cursor:
      cursor.close()
