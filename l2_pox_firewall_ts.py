# This program is to implement a firewall i.e, access control 
# based on the Layer 2 MAC address.
# It basically Checks the Layer 2 Ethernet addersses of the arrived packet and compares with the MAC addresses in 
# policy document. Then Flow will be sent accordingly

import os
import pox.openflow.libopenflow_01 as of
from pox.core import core
from pox.lib.revent import *
from pox.lib.util import dpidToStr
from pox.lib.addresses import EthAddr
from collections import namedtuple
from csv import DictReader

log = core.getLogger()


#policy provides a source and destination MAC addresses for which the communication should be blocked
Policy = namedtuple('Policy', ('dl_src', 'dl_dst'))


class l2_firewall (EventMixin):

    def __init__ (self):
        self.listenTo(core.openflow)
    
    
    def l2_policy_read (self,file_policy):
        with open(file_policy, 'rb') as f:
            reader = DictReader(f, delimiter = ",")
            l2_fw_policies = {}
            for row in reader:
                l2_fw_policies[row['id']] = Policy(EthAddr(row['mac_0']), EthAddr(row['mac_1']))
        return l2_fw_policies

    def _handle_ConnectionUp (self, event):
        l2_policies = self.l2_policy_read("/home/rana/pox/pox/misc/l2_firewall-policies.csv")
        for policy in l2_policies.itervalues():
 	    
	   # Creats a table flow entry and assign a priroty of 20
	   #
	    
            s1_flow = of.ofp_flow_mod()
            s1_flow.priority = 20
            s1_flow.actions.append(of.ofp_action_output(port=of.OFPP_NONE))           

            # This flow table entry is to block communication from source to destination 
	    match = of.ofp_match()
            match.dl_src = policy.dl_src
            match.dl_dst = policy.dl_dst
            s1_flow.match = match
            event.connection.send(s1_flow)

            # This flow table entry is to block communication from destination to source 
            match.dl_src = policy.dl_dst
            match.dl_dst = policy.dl_src
            s1_flow.match = match
            event.connection.send(s1_flow)

def launch ():
    core.registerNew(l2_firewall)
