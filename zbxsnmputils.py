import asyncio
import json
from aiohttp import web
from pysnmp.hlapi.asyncio import *

from zbxsender import zbxsender

import pprint

OID = {'ifName': '.1.3.6.1.2.1.31.1.1.1.1',
       'ifType': '.1.3.6.1.2.1.2.2.1.3',
       'dot1dBasePortIfIndex': '.1.3.6.1.2.1.17.1.4.1.2',
       'dot1qVlanStaticName': '.1.3.6.1.2.1.17.7.1.4.3.1.1',
       'dot1qVlanStaticEgressPorts': '.1.3.6.1.2.1.17.7.1.4.3.1.2',
       'dot1qVlanStaticUntaggedPorts': '.1.3.6.1.2.1.17.7.1.4.3.1.4',
       }

RES_CACHE = {}
RES_CACHE_TIMEOUT = 3600
@asyncio.coroutine
def asnmp_query(svarbind, host="127.0.0.1", community="public", use_cache=True):
    if "{}-{}".format(svarbind,host) in RES_CACHE.keys() and use_cache:
        return RES_CACHE["{}-{}".format(svarbind,host)]
    snmpEngine = SnmpEngine()
    c = True
    snmpdata = dict() 
    varBinds = ObjectType(ObjectIdentity(svarbind))
    startoid = varBinds
    while c:
        errorIndication, errorStatus, errorIndex, varBindTable = yield from bulkCmd(
            snmpEngine,
            CommunityData(community, mpModel=1),
            # UsmUserData('usr-none-none'),
            UdpTransportTarget((host, 161)),
            ContextData(),
            0, 50,
            varBinds
            )

        if errorIndication:
            print(errorIndication)
            break
        elif errorStatus:
            print('%s at %s' % (
                errorStatus.prettyPrint(),
                errorIndex and varBinds[int(errorIndex) - 1][0] or '?'))
        else:
            # uso il reqoid per capire quando sono uscito dalla table snmp cambiando bloccando
            # il ciclo while
            for varBindRow in varBindTable:
                reqoid = tuple(startoid[0])
                getoid = tuple(varBindRow[0][0])
                if reqoid == getoid[:len(reqoid)]:
                    snmpdata[getoid[len(reqoid):][0]] = varBindRow[0][1].prettyPrint()
                    #print("Oid chiesto   ", reqoid)
                    #print("Oid analizzato", getoid)
                    #print("Indice:       ",getoid[len(reqoid):])
                    #print("Analisi:       ",getoid[:len(reqoid)])
                    #print('oid: {} - idx:{} - value: {} '.format(varBindRow[0][0].prettyPrint(),
                    #                                             getoid[len(reqoid):][0],
                    #                                             varBindRow[0][1].prettyPrint(),
                    #                                             ))
                else:
                    c = False
                    break
        varBinds = varBindTable[-1][0]

    snmpEngine.transportDispatcher.closeDispatcher()
    RES_CACHE["{}-{}".format(svarbind,host)] = snmpdata
    return snmpdata

@asyncio.coroutine
def trunkports_handle(request):
    """
    Return ifIndex of trunk interfaces
    This type of interfaces are calculated from the ifType oid and bridgeIndex, it assume that
    interfaces presents in bridgeindex that are not ethernet interfaces are trunks
    :return:
    """
    host = request.GET.get('host', '127.0.0.1')
    community = request.GET.get('community', 'public')
    ifnameidx = yield from asnmp_query(OID['ifName'],
                                      host, community)
    iftypeidx = yield from asnmp_query(OID['ifType'],
                                      host, community)
    bridgeidx = yield from asnmp_query(OID['dot1dBasePortIfIndex'],
                                      host, community)
    bridgeidx = {k: int(v) for k,v in bridgeidx.items()}
    snmpdata = [{'ifIndex': v, 'ifName': ifnameidx[v]} for k, v in bridgeidx.items()
                 if not iftypeidx[v] == "6"]
    body = json.dumps(snmpdata).encode('utf8')
    content_type = "application/json"
    return web.Response(body=body, content_type=content_type)

@asyncio.coroutine
def staticvlans_handle(request):
    """Retrieve Access and Tagged port for every vlan_static_port
    NonStandard:
    the oid_index is not correcly returned from easysnmp, need to calculated from base oid

    Return:
    Dict:
       vlanId1:
             name: 'vlan name'
             access_ports: ['ifName1', 'ifName2'...]
             tagged_ports: ['ifName1', 'ifName2'...]
       vlanId2:
             name: 'vlan name'
             access_ports: ['ifName1', 'ifName2'...]
             tagged_ports: ['ifName1', 'ifName2'...]

    How it works:
    the vlan table returned from dot1qVlanStatic oid contain the name, and the ports assigned to the vlan
    the index of oid is the vlan Id
    the dot1qVlanStaticEgressPorts and dot1qVlanStaticUntaggedPorts mibs return an hex string with a binary map
    of the assigned ports as the example:
    ports sequence     : 1 2 3 4   5 6 7 8 ....
    include/not include: 0 0 0 1   1 0 0 0 (0 not in vlan, 1 in vlan)
    hex value          :    18
    ..Need to convert from hex to bin to map assigned and non assigned ports..

    * to have the tagged ports we need to check if a ports is egress in a vlan, and not access in the same vlan,
    every access ports is always a egress port to.

    the port index returned from binary map is not the ifIndex OID but the BridgeIndex, from the dot1 mibs, we need
    to use the dot1dBasePortIfIndex to map bridgeIndex to ifIndex and use the last index to query the ifName and ifType

    """
    host = request.GET.get('host', '127.0.0.1')
    community = request.GET.get('community', 'public')
    zbxhost = request.GET.get('zbxhost', None)
    vlans_info = dict()
    asnmp_functions = [asnmp_query(OID['dot1qVlanStaticName'], host, community, False),
                       asnmp_query(OID['dot1qVlanStaticEgressPorts'], host, community, False),
                       asnmp_query(OID['dot1qVlanStaticUntaggedPorts'], host, community, False),
                       asnmp_query(OID['dot1dBasePortIfIndex'], host, community),
                       asnmp_query(OID['ifName'], host, community),
                       asnmp_query(OID['ifType'], host, community),
                       ]
    asnmp_functions_res = yield from asyncio.gather(*asnmp_functions)
    vlans_name = asnmp_functions_res[0]
    vlans_egress_ports = asnmp_functions_res[1]
    vlans_untagged_ports = asnmp_functions_res[2]
    bridgeIdx_to_ifIdx = {k: int(v) for k,v in asnmp_functions_res[3].items()}
    ifName = asnmp_functions_res[4]
    ifType = asnmp_functions_res[5]
    """
    vlans_name = yield from asnmp_query(OID['dot1qVlanStaticName'],
                                        host, community)
    vlans_egress_ports = yield from asnmp_query(OID['dot1qVlanStaticEgressPorts'],
                                                host, community)    
    vlans_untagged_ports = yield from asnmp_query(OID['dot1qVlanStaticUntaggedPorts'],
                                                  host, community)  
    bridgeIdx_to_ifIdx = yield from asnmp_query(OID['dot1dBasePortIfIndex'],
                                                host, community)  
    bridgeIdx_to_ifIdx = {k: int(v) for k,v in bridgeIdx_to_ifIdx.items()}
    ifName = yield from asnmp_query(OID['ifName'], host, community)
    ifType = yield from asnmp_query(OID['ifType'], host, community)
    """
    for vlan_id, vlan in vlans_name.items():
        vlans_info[vlan_id] = dict()
        # And now the magic!, from a OctetString to a maps of ports
        vlan_egress_map = ""
        vlan_access_map = ""
        for i in range(2, len(vlans_egress_ports[vlan_id]), 2):
            vlan_egress_map += '{:08b}'.format(int(vlans_egress_ports[vlan_id][i:i+2],16))
            vlan_access_map += '{:08b}'.format(int(vlans_untagged_ports[vlan_id][i:i+2],16))

        vlan_access_port_list = [n + 1 for n, i in enumerate(vlan_access_map)
                                 if i == '1' and n < len(bridgeIdx_to_ifIdx)]
        vlan_tagged_port_list = [n + 1 for n, i in enumerate(vlan_egress_map)
                                 if i == '1' and vlan_access_map[n] == '0' and n < len(bridgeIdx_to_ifIdx)]
        vlans_info[vlan_id]['name'] = vlan

        # Filtered on ifType=6 (ethernet) no trunks
        vlans_info[vlan_id]['access_ports'] = [ifName[bridgeIdx_to_ifIdx[portnum]]
                                               for portnum in vlan_access_port_list
                                               if ifType[bridgeIdx_to_ifIdx[portnum]] == '6'
                                               ]
        vlans_info[vlan_id]['access_trunks'] = [ifName[bridgeIdx_to_ifIdx[portnum]]
                                               for portnum in vlan_access_port_list
                                               if not ifType[bridgeIdx_to_ifIdx[portnum]] == '6'
                                               ]
        # filtered on non-ethernet interfaces
        vlans_info[vlan_id]['tagged_ports'] = [ifName[bridgeIdx_to_ifIdx[portnum]]
                                               for portnum in vlan_tagged_port_list
                                               if ifType[bridgeIdx_to_ifIdx[portnum]] == '6'
                                               ]
        vlans_info[vlan_id]['tagged_trunks'] = [ifName[bridgeIdx_to_ifIdx[portnum]]
                                               for portnum in vlan_tagged_port_list
                                               if not ifType[bridgeIdx_to_ifIdx[portnum]] == '6'
                                               ]    
    if zbxhost:
        data = []
        zbxitem = ("VLANStaticUntaggedPorts[{vlanId}]",
                   "VLANStaticUntaggedTrunks[{vlanId}]",
                   "VLANStaticTaggedPorts[{vlanId}]",
                   "VLANStaticTaggedTrunks[{vlanId}]")
        for vlanId, ports in vlans_info.items():
            data.append([zbxitem[0].format(vlanId=vlanId), ", ".join(ports["access_ports"]) if
                         len(ports["access_ports"]) > 0 else "None"])
            data.append([zbxitem[1].format(vlanId=vlanId), ", ".join(ports["access_trunks"]) if
                         len(ports["access_trunks"]) > 0 else "None"])
            data.append([zbxitem[2].format(vlanId=vlanId), ", ".join(ports["tagged_ports"]) if
                         len(ports["tagged_ports"]) > 0 else "None"])
            data.append([zbxitem[3].format(vlanId=vlanId), ", ".join(ports["tagged_trunks"]) if
                         len(ports["tagged_trunks"]) > 0 else "None"])
        # print(data)
        out = zbxsender(zbxhost, data)
        ret = {'zbxsender': out}
    else:
        ret = vlans_info

    body = json.dumps(ret).encode('utf8')
    content_type = "application/json"
    return web.Response(body=body, content_type=content_type)


app = web.Application()
app.router.add_route('GET', '/trunkports', trunkports_handle)
app.router.add_route('GET', '/staticvlans', staticvlans_handle)

web.run_app(app)

