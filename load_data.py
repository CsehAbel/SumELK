import mysql.connector
from mysql.connector import errorcode
from os import listdir
from os.path import isfile, join
from mysql.connector.constants import ClientFlag
import secrets

option_files_path = r"/mnt/c/ProgramData/MySQL/MySQL Server 8.0/Uploads/option_folder/option.cnf"

config = {
  'user': secrets.mysql_u,
  'password': secrets.mysql_pw,
  'host': '127.0.0.1',
  'database': 'CSV_DB',
  'raise_on_warnings': True,
  'allow_local_infile':True
  #'option_files': option_files_path
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

def createtable(cursor,TABLES):
  for table_name in TABLES:
    table_description = TABLES[table_name]
    try:
      print("Creating table {}: ".format(table_name), end='')
      cursor.execute(table_description)
    except mysql.connector.Error as err:
      if err.errno == errorcode.ER_TABLE_EXISTS_ERROR:
        print("already exists.")
      else:
        print(err.msg)
    else:
      print("OK")

def list_files(path):
    onlyfiles=[]
    for f in listdir(path):
      if (isfile(join(path, f))):
        onlyfiles.append(f)
    return onlyfiles

def main():
  cnx = mysql.connector.connect(**config)
  cursor = cnx.cursor()

  DB_NAME = "CSV_DB"
  usedb(cursor,DB_NAME)

  TABLES = {}
  TABLES['ip'] = (
    "CREATE TABLE `ip` ("
    "  `id` INT,"
    "  `src_ip` INT UNSIGNED NOT NULL,"
    "  `dst_ip` date NOT NULL,"
    "  PRIMARY KEY (`id`)"
    ") ENGINE=InnoDB")

  createtable(cursor,TABLES)

  path = r"/mnt/c/ProgramData/MySQL/MySQL Server 8.0/Uploads"
  lf = list_files(path)
  LOADS = {}

  table="ip"

  for f in lf:
    LOADS[f]="LOAD DATA LOCAL INFILE '{}' ".format(join(path, f)) + \
      " IGNORE INTO TABLE {} ".format(table) + \
    "FIELDS TERMINATED BY ','  LINES TERMINATED BY '\\n' IGNORE 1 LINES"

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
  main()





