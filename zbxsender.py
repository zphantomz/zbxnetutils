import subprocess

sender = {'zbxsender': '/usr/bin/zabbix_sender',
          'zbxserver': '10.97.17.1',
          'zbxserverport': '10051'
          }


def zbxsender(zbxhost, data):
    """
    Sending data to Zabbix server via zabbix_sender utility.
    :param zbxhost: HostName as zabbix server configuration
    :param data: array of [[zabbix item, value], [zabbix item, value]]
    :return:
       return output from zabbix_sender command
    """
    cmd = [sender['zbxsender'], '-z', sender['zbxserver'], '-p', sender['zbxserverport'],
           '-r', '-i', '-']
    fmt = "{host} {key} {value}"
    values_list = [fmt.format(host=zbxhost, key=v[0], value=v[1]) for v in data]
    values = "\n".join(values_list)
    # print(values)
    p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out = p.communicate(input=values.encode('utf8'))[0]
    # print(out)
    return out.decode('utf8')
