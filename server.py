import tornado.ioloop
import tornado.web

from tornado.options import parse_config_file, options, define
from tornado.concurrent import run_on_executor
from concurrent.futures import ThreadPoolExecutor

import json
from snmputils import Host
from zbxsender import zbxsender

import os, sys

MAX_WORKERS = 4


class MainHandler(tornado.web.RequestHandler):
    def get(self):
        self.set_header('Content-Type', 'application/json')
        host = Host(hostname="10.97.16.200")
        ret = host.vlan_static_ports()
        self.write(json.dumps(ret))


class TrunkPortsHandler(tornado.web.RequestHandler):
    """
    Call the get_trunk_interfaces() function of snmputils module to retrieve the list of ifIndex of trunk ports, static
    or LACP.
    Read get_trunk_interfaces() for a description of method.
    Return a json string compatible with zabbix discovery item

    Require parameter in the GET Request:
    host: Ip Address of switch/router
    community: snmp community string, default public

    The call is make async by the tornado coroutine utilities
    """
    executor = ThreadPoolExecutor(max_workers=MAX_WORKERS)

    @run_on_executor
    def task(self, **kwargs):
        """
        execute call in async way
        """
        host = Host(**kwargs)
        return host.get_trunk_interfaces()

    @tornado.gen.coroutine
    def get(self):
        snmp_host = self.get_argument("host", default=None)
        snmp_community = self.get_argument("community", default="public")
        if snmp_host:
            ret = yield self.task(hostname=snmp_host,
                                  community=snmp_community
                                  )
        out = [{'{#IFINDEX}': idx['ifIndex'], '{#IFNAME}': idx['ifName']} for idx in ret]
        self.set_header('Content-Type', 'application/json')
        self.write(json.dumps({'data': out}))


class VLANHandler(tornado.web.RequestHandler):
    """
    Call the vlan_static_port function of snmputils module to retrieve the vlan static port assignment, if called
    without zbxhost param it return a json reply of configured VLANs and ports/trunk assigned.
    If zbxhost param is present it call the zbxsender function to send ports configuration to zabbix server, and return
    the output of the zabbix_sender subprocess call.

    Require parameter in the GET Request:
    host: Ip Address of switch/router
    community: snmp community string, default public
    zbxhost: hostname configured on zabbix server

    The call is make async by the tornado coroutine utilities
    """
    executor = ThreadPoolExecutor(max_workers=MAX_WORKERS)

    @run_on_executor
    def task(self, **kwargs):
        """
        execute call in async way
        """
        host = Host(**kwargs)
        return host.vlan_static_ports()

    @tornado.gen.coroutine
    def get(self):
        snmp_host = self.get_argument("host", default=None)
        snmp_community = self.get_argument("community", default="public")
        zbx_host = self.get_argument("zbxhost", default=None)
        if snmp_host:
            ret = yield self.task(hostname=snmp_host,
                                  community=snmp_community
                                  )
            if zbx_host:
                data = []
                zbxitem = ("VLANStaticUntaggedPorts[{vlanId}]",
                           "VLANStaticUntaggedTrunks[{vlanId}]",
                           "VLANStaticTaggedPorts[{vlanId}]",
                           "VLANStaticTaggedTrunks[{vlanId}]")
                for vlanId, ports in ret.items():
                    data.append([zbxitem[0].format(vlanId=vlanId), ", ".join(ports["access_ports"]) if
                                 len(ports["access_ports"]) > 0 else "None"])
                    data.append([zbxitem[1].format(vlanId=vlanId), ", ".join(ports["access_trunks"]) if
                                 len(ports["access_trunks"]) > 0 else "None"])
                    data.append([zbxitem[2].format(vlanId=vlanId), ", ".join(ports["tagged_ports"]) if
                                 len(ports["tagged_ports"]) > 0 else "None"])
                    data.append([zbxitem[3].format(vlanId=vlanId), ", ".join(ports["tagged_trunks"]) if
                                 len(ports["tagged_trunks"]) > 0 else "None"])
                # print(data)
                out = zbxsender(zbx_host, data)
                ret = {'zbxsender': out}

        else:
            ret = {'error': 'must set host variables'}
        self.set_header('Content-Type', 'application/json')
        self.write(json.dumps(ret))


def make_app():
    return tornado.web.Application([
        (r"/", MainHandler),
        (r"/trunkports", TrunkPortsHandler),
        (r"/staticvlans", VLANHandler),
    ])

if __name__ == "__main__":
    """
    Start a Tornado server loading config from server.cfg
    """
    define("port", default="8888")
    define("host", default="127.0.0.1")
    define("log_file_prefix",
           default=os.path.join(os.path.abspath(os.path.dirname(sys.argv[0])), 'server.log'),
           help="log file prefix")
    cfgfile = os.path.join(os.path.abspath(os.path.dirname(sys.argv[0])), 'server.cfg')
    print("Loading config file: %s" % cfgfile)
    parse_config_file(cfgfile)
    app = make_app()
    app.listen(port=options.port, address=options.host)
    tornado.ioloop.IOLoop.current().start()
