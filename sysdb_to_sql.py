from sqlalchemy import create_engine
import secrets
import pandas

file = "sysdb_2022-02-07.gz"
df_sysdb = pandas.read_csv(file, sep=';', encoding="utf-8", dtype='str')
#df_sysdb = df_sysdb[["ip", "dns"]]

sqlEngine = create_engine('mysql+pymysql://%s:%s@%s/%s' %(secrets.mysql_u,secrets.mysql_pw,"127.0.0.1","CSV_DB"), pool_recycle=3600)
dbConnection = sqlEngine.connect()
df_sysdb.to_sql("sysdb", dbConnection,if_exists='replace', index=True)