from pymysqlreplication import BinLogStreamReader

mysql_settings = {'host': 'www.gsteps.cn', 'port': 3306, 'user': 'root', 'passwd': 'gsteps2016!'}

stream = BinLogStreamReader(connection_settings=mysql_settings, server_id=100)

for binlogevent in stream:
    for row in binlogevent.dump():
        print '=' * 50
        print row
        print row['event']

stream.close()
