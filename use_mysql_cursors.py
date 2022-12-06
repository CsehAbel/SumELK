import datetime

import mysql.connector
from mysql.connector import errorcode
from os import listdir
from os.path import isfile, join
from mysql.connector.constants import ClientFlag
import secrets



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

def main(history_table, db_name):
  config = {
        'user': secrets.mysql_u,
        'password': secrets.mysql_pw,
        'host': '127.0.0.1',
        'database': db_name,
        'raise_on_warnings': True,
        'allow_local_infile': True
    }


  cnx = mysql.connector.connect(**config)
  cursor = cnx.cursor()

  usedb(cursor,db_name)

  LOADS = {}

  table="ip"
  #create a new table with the name of the current date
  create_table="CREATE TABLE "+history_table+" SELECT * FROM "+table+";"

  #try to execute the query, create a new table with the name of the current date
  try:
        cursor.execute(create_table)
  except mysql.connector.Error as err:
        print(err.msg)
  else:
        print("Table {} created.".format(history_table))

  cnx.commit()
  cursor.close()
  cnx.close()

#function similar to main() but instead of creating a new table, return the number of rows in darwin_white_apps table
def get_row_count(table,db_name):
    config = {
        'user': secrets.mysql_u,
        'password': secrets.mysql_pw,
        'host': '127.0.0.1',
        'database': db_name,
        'raise_on_warnings': True,
        'allow_local_infile': True
    }

    cnx = mysql.connector.connect(**config)
    cursor = cnx.cursor()

    usedb(cursor,db_name)

    #store "count_rows" in a variable
    count_rows = "SELECT COUNT(*) FROM "+table+";"
    #try to execute the query, return the number of rows in darwin_white_apps table
    rows=0
    try:
        cursor.execute(count_rows)
        #store the result in a variable containing an integer
        rows = cursor.fetchone()[0]
    except mysql.connector.Error as err:
        print(err.msg)
    else:
        #print the number of rows in table
        print("Table {} has {} rows.".format(table,rows))


    cnx.commit()
    cursor.close()
    cnx.close()

    return rows

def load_csv_to_mysql(table,db_name,path_string='/path/to/my/file'):
  #query to load the csv file into the table will be stored in a variable
  #query = "LOAD DATA LOCAL INFILE '%s' IGNORE INTO TABLE %s FIELDS TERMINATED BY ',' ENCLOSED BY '' LINES TERMINATED BY '\\n'" % (path_string,table)
  #above string definition but in multiple lines
  query = ("LOAD DATA LOCAL INFILE '%s' IGNORE INTO TABLE %s "
            "FIELDS TERMINATED BY ',' ENCLOSED BY '' "
            "LINES TERMINATED BY '\\n'" % (path_string,table))

  option_files_path = r"/mnt/c/ProgramData/MySQL/MySQL Server 8.0/Uploads/option_folder/option.cnf"
  config = {
        'user': secrets.mysql_u,
        'password': secrets.mysql_pw,
        'host': '127.0.0.1',
        'database': db_name,
        'raise_on_warnings': True,
        'allow_local_infile': True
        ,'option_files': option_files_path
    }
    #connect to the database
  cnx = mysql.connector.connect(**config)
  cursor = cnx.cursor()
  #use the database
  usedb(cursor,db_name)
  #try to execute the query
  try:
        cursor.execute(query)
  except mysql.connector.Error as err:
        print(err.msg)
  else:
        print("Table {} loaded.".format(table))

  


