
OID = {'ifName': '.1.3.6.1.2.1.31.1.1.1.1',
       'ifType': '.1.3.6.1.2.1.2.2.1.3',
       'dot1dBasePortIfIndex': '.1.3.6.1.2.1.17.1.4.1.2',
       'dot1qVlanStaticName': '.1.3.6.1.2.1.17.7.1.4.3.1.1',
       'dot1qVlanStaticEgressPorts': '.1.3.6.1.2.1.17.7.1.4.3.1.2',
       'dot1qVlanStaticUntaggedPorts': '.1.3.6.1.2.1.17.7.1.4.3.1.4',
       }


class Host:
    def __init__(self, hostname="127.0.0.1", community="public", version=2):
        from easysnmp import Session
        self.hostname = hostname
        self.community = community
        self.version = version
        self.session = Session(hostname=hostname,
                               community=community,
                               version=version)

    def get_ifName(self):
        """Return a dict:
           { ifIndex: IfName,
           }
        """
        ret = self.session.walk(OID['ifName'])
        return {i.oid_index: i.value for i in ret}

    def get_ifType(self):
        """Return a dict:
           { ifIndex: IfType,
           }
        """
        ret = self.session.walk(OID['ifType'])
        return {i.oid_index: i.value for i in ret}

    def get_dot1q_idx(self):
        """Return the association between bridge index and ifIndex
        NonStandard:
        easysnmp not return index correcly, need to calculate from oid via split
           { bridgeidx: ifIndex,
           }
        """
        ret = self.session.walk(OID['dot1dBasePortIfIndex'])
        # print([i.value for i in ret])
        return {int(i.oid.split('.')[-1]): i.value for i in ret}

    def get_trunk_interfaces(self):
        """
        Return ifIndex of trunk interfaces
        This type of interfaces are calculated from the ifType oid and bridgeIndex, it assume that interfaces presents
        in bridgeindex that are not ethernet interfaces are trunks
        :return:
        """
        bridgeidx = self.get_dot1q_idx()
        iftypeidx = self.get_ifType()
        ifnameidx = self.get_ifName()
        return [{'ifIndex': v, 'ifName': ifnameidx[v]} for k, v in bridgeidx.items() if not iftypeidx[v] == '6']

    def vlan_static_ports(self):
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
        vlans_info = dict()
        vlans_name = self.session.walk(OID['dot1qVlanStaticName'])
        vlans_egress_ports = self.session.walk(OID['dot1qVlanStaticEgressPorts'])
        vlans_untagged_ports = self.session.walk(OID['dot1qVlanStaticUntaggedPorts'])
        bridgeIdx_to_ifIdx = self.get_dot1q_idx()
        ifName_dict = self.get_ifName()
        ifType_dict = self.get_ifType()
        for idx, vlan in enumerate(vlans_name):
            vlan_id = vlan.oid.split('.')[-1]
            vlans_info[vlan_id] = dict()
            vlan_egress_map = ''.join('{:08b}'.format(ord(x)) for x in vlans_egress_ports[idx].value)
            vlan_access_map = ''.join('{:08b}'.format(ord(x)) for x in vlans_untagged_ports[idx].value)
            vlan_access_port_list = [n + 1 for n, i in enumerate(vlan_access_map)
                                     if i == '1' and n < len(bridgeIdx_to_ifIdx)]
            vlan_tagged_port_list = [n + 1 for n, i in enumerate(vlan_egress_map)
                                     if i == '1' and vlan_access_map[n] == '0' and n < len(bridgeIdx_to_ifIdx)]

            vlans_info[vlan_id]['name'] = vlan.value
            # Filtered on ifType=6 (ethernet) no trunks
            vlans_info[vlan_id]['access_ports'] = [ifName_dict[bridgeIdx_to_ifIdx[portnum]]
                                                   for portnum in vlan_access_port_list
                                                   if ifType_dict[bridgeIdx_to_ifIdx[portnum]] == '6'
                                                   ]
            vlans_info[vlan_id]['access_trunks'] = [ifName_dict[bridgeIdx_to_ifIdx[portnum]]
                                                   for portnum in vlan_access_port_list
                                                   if not ifType_dict[bridgeIdx_to_ifIdx[portnum]] == '6'
                                                   ]
            # filtered on non-ethernet interfaces
            vlans_info[vlan_id]['tagged_ports'] = [ifName_dict[bridgeIdx_to_ifIdx[portnum]]
                                                   for portnum in vlan_tagged_port_list
                                                   if ifType_dict[bridgeIdx_to_ifIdx[portnum]] == '6'
                                                   ]
            vlans_info[vlan_id]['tagged_trunks'] = [ifName_dict[bridgeIdx_to_ifIdx[portnum]]
                                                   for portnum in vlan_tagged_port_list
                                                   if not ifType_dict[bridgeIdx_to_ifIdx[portnum]] == '6'
                                                   ]
        return vlans_info


if __name__ == "__main__":
    import argparse
    from pprint import pprint
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", help="Ip address or hostname of network equipment")
    parser.add_argument("--community", help="SNMP Community", default="public", action="store_true")
    parser.add_argument("--querytype", help="Type of query", action="store_true")

    args = parser.parse_args()
    HOST = args.host
    COMMUNITY = args.community
    # ToDo make compatible with v3
    SNMP_VERSION = 2
    # pprint(vlan_static_ports())