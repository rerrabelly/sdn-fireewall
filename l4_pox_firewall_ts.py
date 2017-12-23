# This program is to implement a firewall i.e, access control 
# based on the Layer 3 IP addresses and also TCP port numbers
# It checks the Layer 3 IP addersses and TCP port number of the arrived packet and compares with the IP addresses in 
# policy document. In this program, i have only blocking the HTTP traffice. 
#In Openflow 1.0, inorder to match the rules on Layer 3 addresses , we should mention Ethernet type and Network protocol i.e., dl_type= 0x800 , nw_proto=6 
#Then Flow will be sent accordingly

import os
import pox.openflow.libopenflow_01 as of
from csv import DictReader
from pox.core import core
from pox.lib.revent import *
from pox.lib.util import dpidToStr
from pox.lib.addresses import EthAddr
from pox.lib.addresses import IPAddr
from collections import namedtuple


log = core.getLogger()

#policy provides a source and destination MAC addresses for which the communication should be blocked
Policy = namedtuple('Policy', ('nw_src', 'nw_dst'))


class l4_firewall (EventMixin):

    def __init__ (self):
        self.listenTo(core.openflow)
    
    
    def l4_policy_read (self,file_policy):
        with open(file_policy, 'rb') as f:
            reader = DictReader(f, delimiter = ",")
            l4_fw_policies = {}
            for row in reader:
                l4_fw_policies[row['id']] = Policy(IPAddr(row['ip_0']), IPAddr(row['ip_1']))
        return l4_fw_policies

    def _handle_ConnectionUp (self, event):
        l4_policies = self.l4_policy_read("/home/rana/pox/pox/misc/l4_firewall-policies.csv")
        for policy in l4_policies.itervalues():
 	    
	   # Creats a table flow entry and assign a priroty of 20	    
            s1_flow = of.ofp_flow_mod()
            s1_flow.priority = 20
            s1_flow.actions.append(of.ofp_action_output(port=of.OFPP_NONE))           

            # This flow table entry is to block communication from source to destination 
	    match = of.ofp_match()
	    match.nw_proto = 6
	    match.dl_type=0x800
            match.nw_src = policy.nw_src
            match.nw_dst = policy.nw_dst
	    match.tp_src = 80
            s1_flow.match = match
            event.connection.send(s1_flow)

            # This flow table entry is to block communication from destination to source
	    match.nw_proto = 6
	    match.dl_type=0x800
            match.nw_src = policy.nw_dst
            match.nw_dst = policy.nw_src
	    match.tp_src = 80
            s1_flow.match = match
            event.connection.send(s1_flow)

def launch ():
    core.registerNew(l4_firewall)
