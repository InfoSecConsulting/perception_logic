import os
import sys
import lib.yml_parser as parse_yml


try:
    import sqlalchemy
    from sqlalchemy import Column, String, Text, Integer, ForeignKey, Sequence, create_engine, MetaData
    from sqlalchemy.orm import relationship, sessionmaker
    from sqlalchemy.ext.declarative import declarative_base
    from sqlalchemy.engine.url import URL
except ImportError:
    print('Installing SQLAlchemy..')
    os.system('pip3 install SQLAlchemy')
    import sqlalchemy
    from sqlalchemy import Column, String, Text, Integer, ForeignKey, Sequence, create_engine, MetaData
    from sqlalchemy.orm import relationship, sessionmaker
    from sqlalchemy.ext.declarative import declarative_base
    from sqlalchemy.engine.url import URL

Session = sessionmaker()


def connect():
  db_yml = 'config/database.yml'
  db_info = parse_yml.db_info(db_yml)
  cursor = None

  try:
    Session = sessionmaker()
    engine = create_engine(URL(**db_info), pool_size=20)
    Session.configure(bind=engine)
    return Session
  except sqlalchemy.exc.OperationalError as e:
    print(e)
    sys.exit(1)
  finally:
    if cursor:
      cursor.close()
