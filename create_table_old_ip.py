import datetime

import mysql.connector
from mysql.connector import errorcode
from os import listdir
from os.path import isfile, join
from mysql.connector.constants import ClientFlag
import secrets

config = {
  'user': secrets.mysql_u,
  'password': secrets.mysql_pw,
  'host': '127.0.0.1',
  'database': 'CSV_DB',
  'raise_on_warnings': True,
  'allow_local_infile':True
}


def usedb(cursor,DB_NAME):
  try:
    cursor.execute("USE {}".format(DB_NAME))
  except mysql.connector.Error as err:
    print("Database {} does not exists.".format(DB_NAME))
    if err.errno == errorcode.ER_BAD_DB_ERROR:
      print(err)
      exit(1)
    else:
      print(err)
      exit(1)

def main(history_table):
  cnx = mysql.connector.connect(**config)
  cursor = cnx.cursor()

  DB_NAME = "CSV_DB"
  usedb(cursor,DB_NAME)

  LOADS = {}

  table="ip"
  LOADS["create_a_table_from_another"]="CREATE TABLE "+history_table+" SELECT * FROM "+table+";"

  for l in LOADS:
    table_description = LOADS[l]
    try:
      cursor.execute(table_description)
    except mysql.connector.Error as err:
      print(err.msg)
    else:
      print("OK")

  cnx.commit()
  cursor.close()
  cnx.close()

if __name__=="__main__":
  history_table="ip_" + datetime.datetime.now().strftime("%Y%m%d")
  main(history_table)





