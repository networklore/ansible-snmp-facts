#!/usr/bin/python

# This file is part of Networklore's snmp library for Ansible
#
# The module is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# The module is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Ansible.  If not, see <http://www.gnu.org/licenses/>.


DOCUMENTATION = '''
---
module: snmp_facts
author: Patrick Ogenstad (@networklore)
notes:
    - Version 0.5
short_description: Retrive facts for a device using SNMP.
description:
    - Retrieve facts for a device using SNMP, the facts will be
      inserted to the ansible_facts key.
requirements:
    - pysnmp
options:
    host:
        description:
            - Set to {{ inventory_hostname }}}
        required: true
    version:
        description:
            - SNMP Version to use, v2/v2c or v3
        choices: [ 'v2', 'v2c', 'v3' ]
        required: true
    community:
        description:
            - The SNMP community string, required if version is v2/v2c
        required: false
    level:
        description:
            - Authentication level, required if version is v3
        choices: [ 'authPriv', 'authNoPriv' ]
        required: false
    username:
        description:
            - Username for SNMPv3, required if version is v3
        required: false
    integrity:
        description:
            - Hashing algoritm, required if version is v3
        choices: [ 'md5', 'sha' ]
        required: false
    authkey:
        description:
            - Authentication key, required if version is v3
        required: false
    privacy:
        description:
            - Encryption algoritm, required if level is authPriv
        choices: [ 'des', 'aes' ]
        required: false
    privkey:
        description:
            - Encryption key, required if version is authPriv
        required: false
'''

EXAMPLES = '''
# Gather facts with SNMP version 2
- snmp_facts: host={{ inventory_hostname }} version=2c community=public

# Gather facts using SNMP version 3
- snmp_facts:
    host={{ inventory_hostname }}
    version=v3
    level=authPriv
    integrity=sha
    privacy=aes
    username=snmp-user
    authkey=abc12345
    privkey=def6789
'''

import json
import sys

from collections import defaultdict

def decode_hex(hexstring):
 
    if len(hexstring) < 3:
        return hexstring
    if hexstring[:2] == "0x":
        return hexstring[2:].decode("hex")
    else:
        return hexstring

def decode_mac(hexstring):

    if len(hexstring) != 14:
        return hexstring
    if hexstring[:2] == "0x":
        return hexstring[2:]
    else:
        return hexstring

def lookup_adminstatus(int_adminstatus):
    if int_adminstatus == 1:
        return "up"
    elif int_adminstatus == 2:
        return "down"
    elif int_adminstatus == 3:
        return "testing"

def lookup_operstatus(int_operstatus):
    if int_operstatus == 1:
        return "up"
    elif int_operstatus == 2:
        return "down"
    elif int_operstatus == 3:
        return "testing"
    elif int_operstatus == 4:
        return "unknown"
    elif int_operstatus == 5:
        return "dormant"
    elif int_operstatus == 6:
        return "notPresent"
    elif int_operstatus == 7:
        return "lowerLayerDown"

def main():
    module = AnsibleModule(
        argument_spec=dict(
            host=dict(required=True),
            version=dict(required=True, choices=['v2', 'v2c', 'v3']),
            community=dict(required=False, default=False),
            username=dict(required=False),
            level=dict(required=False, choices=['authNoPriv', 'authPriv']),
            integrity=dict(required=False, choices=['md5', 'sha']),
            privacy=dict(required=False, choices=['des', 'aes']),
            authkey=dict(required=False),
            privkey=dict(required=False),

            removeplaceholder=dict(required=False)),
            required_together = ( ['username','level','integrity','authkey'],['privacy','privkey'],),
        supports_check_mode=False)

    m_args = module.params

    from pysnmp.entity.rfc3413.oneliner import cmdgen

    cmdGen = cmdgen.CommandGenerator()

    # Verify that we receive a community when using snmp v2
    if m_args['version'] == "v2" or m_args['version'] == "v2c":
        if m_args['community'] == False:
            print json.dumps({
                "failed" : True,
                "msg"    : "Community not set when using snmp version 2"
            })
            sys.exit(1)            

    if m_args['version'] == "v3":
        if m_args['username'] == None:
            print json.dumps({
                "failed" : True,
                "msg"    : "Username not set when using snmp version 3"
            })
            sys.exit(1)


        if m_args['level'] == "authPriv" and m_args['privacy'] == None:
            print json.dumps({
                "failed" : True,
                "msg"    : "Privacy algorithm not set when using authPriv"
            })
            sys.exit(1)

        if m_args['integrity'] == "sha":
            INTEGRITY_PROTO = cmdgen.usmHMACSHAAuthProtocol
        elif m_args['integrity'] == "md5":
            INTEGRITY_PROTO = cmdgen.usmHMACMD5AuthProtocol

        if m_args['privacy'] == "aes":
            PRIVACY_PROTO = cmdgen.usmAesCfb128Protocol
        elif m_args['privacy'] == "des":
            PRIVACY_PROTO = cmdgen.usmDESPrivProtocol
    
    # Use SNMP Version 2
    if m_args['version'] == "v2" or m_args['version'] == "v2c":
        SNMP_AUTH = cmdgen.CommunityData(m_args['community'])

    # Use SNMP Version 3 with authNoPriv
    elif m_args['level'] == "authNoPriv":
        SNMP_AUTH = cmdgen.UsmUserData(m_args['username'], authKey=m_args['authkey'], authProtocol=INTEGRITY_PROTO)

    # Use SNMP Version 3 with authPriv
    else:
        SNMP_AUTH = cmdgen.UsmUserData(m_args['username'], authKey=m_args['authkey'], privKey=m_args['privkey'], authProtocol=INTEGRITY_PROTO, privProtocol=PRIVACY_PROTO)

            
    errorIndication, errorStatus, errorIndex, varBinds = cmdGen.getCmd(
        SNMP_AUTH,
        cmdgen.UdpTransportTarget((m_args['host'], 161)),
        cmdgen.MibVariable('.1.3.6.1.2.1.1.1.0',), # sysDescr
        cmdgen.MibVariable('.1.3.6.1.2.1.1.2.0',), # sysObjectId
        cmdgen.MibVariable('.1.3.6.1.2.1.1.3.0',), # sysUpTime
        cmdgen.MibVariable('.1.3.6.1.2.1.1.4.0',), # sysContact 
        cmdgen.MibVariable('.1.3.6.1.2.1.1.5.0',), # sysName 
        cmdgen.MibVariable('.1.3.6.1.2.1.1.6.0',), # sysLocation
    )


    if errorIndication:
        print json.dumps({
            "failed" : True,
            "msg"    : str(errorIndication)
        })
        sys.exit(1)        

    for oid, val in varBinds:
        current_oid = oid.prettyPrint()
        current_val = val.prettyPrint()
        if current_oid == "1.3.6.1.2.1.1.1.0":
            sysDescr = current_val
        elif current_oid == "1.3.6.1.2.1.1.2.0":
            sysObjectId = current_val
        elif current_oid == "1.3.6.1.2.1.1.3.0":
            sysUpTime = current_val
        elif current_oid == "1.3.6.1.2.1.1.3.0":
            sysUpTime = current_val
        elif current_oid == "1.3.6.1.2.1.1.4.0":
            sysContact = current_val
        elif current_oid == "1.3.6.1.2.1.1.5.0":
            sysName = current_val
        elif current_oid == "1.3.6.1.2.1.1.6.0":
            sysLocation = current_val

    Tree = lambda: defaultdict(Tree)
    snmp_result = Tree()                               

    
    snmp_result['ansible_facts']['ansible_sysdescr'] = decode_hex(sysDescr)
    snmp_result['ansible_facts']['ansible_sysobjectid'] = sysObjectId
    snmp_result['ansible_facts']['ansible_sysuptime'] = sysUpTime
    snmp_result['ansible_facts']['ansible_syscontact'] = sysContact
    snmp_result['ansible_facts']['ansible_sysname'] = sysName
    snmp_result['ansible_facts']['ansible_syslocation'] = sysLocation


    errorIndication, errorStatus, errorIndex, varTable = cmdGen.nextCmd(
        SNMP_AUTH,
        cmdgen.UdpTransportTarget((m_args['host'], 161)), 
        cmdgen.MibVariable('.1.3.6.1.2.1.2.2.1.1',), # ifIndex
        cmdgen.MibVariable('.1.3.6.1.2.1.2.2.1.2',), # ifDescr
        cmdgen.MibVariable('.1.3.6.1.2.1.2.2.1.4',), # ifMtu
        cmdgen.MibVariable('.1.3.6.1.2.1.2.2.1.5',), # ifSpeed
        cmdgen.MibVariable('.1.3.6.1.2.1.2.2.1.6',), # ifPhysAddress
        cmdgen.MibVariable('.1.3.6.1.2.1.2.2.1.7',), # ifAdminStatus
        cmdgen.MibVariable('.1.3.6.1.2.1.2.2.1.8',), # ifOperStatus
        cmdgen.MibVariable('.1.3.6.1.2.1.4.20.1.1',), # ipAdEntAddr
        cmdgen.MibVariable('.1.3.6.1.2.1.31.1.1.1.18',), # ifAlias
    )


    if errorIndication:
        print json.dumps({
            "failed" : True,
            "msg"    : str(errorIndication)
        })
        sys.exit(1)        

    interface_indexes = []
    
    all_ipv4_addresses = []
    

    for varBinds in varTable:
        for oid, val in varBinds:
            current_oid = oid.prettyPrint()
            current_val = val.prettyPrint()
            if "1.3.6.1.2.1.2.2.1.1" in current_oid: # ifIndex
                ifIndex = int(current_oid.rsplit('.', 1)[-1])
                snmp_result['ansible_facts']['ansible_interfaces'][ifIndex]['ifindex'] = current_val
                interface_indexes.append(ifIndex)
            if "1.3.6.1.2.1.2.2.1.2" in current_oid: # ifDescr
                ifIndex = int(current_oid.rsplit('.', 1)[-1])
                snmp_result['ansible_facts']['ansible_interfaces'][ifIndex]['name'] = current_val
            if "1.3.6.1.2.1.2.2.1.4" in current_oid: # ifMtu
                ifIndex = int(current_oid.rsplit('.', 1)[-1])
                snmp_result['ansible_facts']['ansible_interfaces'][ifIndex]['mtu'] = current_val
            if "1.3.6.1.2.1.2.2.1.5" in current_oid: # ifSpeed
                ifIndex = int(current_oid.rsplit('.', 1)[-1])
                snmp_result['ansible_facts']['ansible_interfaces'][ifIndex]['speed'] = current_val
            if "1.3.6.1.2.1.2.2.1.6" in current_oid: # ifPhysAddress
                ifIndex = int(current_oid.rsplit('.', 1)[-1])
                snmp_result['ansible_facts']['ansible_interfaces'][ifIndex]['mac'] = decode_mac(current_val)
            if "1.3.6.1.2.1.2.2.1.7" in current_oid: # ifAdminStatus
                ifIndex = int(current_oid.rsplit('.', 1)[-1])
                snmp_result['ansible_facts']['ansible_interfaces'][ifIndex]['adminstatus'] = lookup_adminstatus(int(current_val))
            if "1.3.6.1.2.1.2.2.1.8" in current_oid: # ifOperStatus
                ifIndex = int(current_oid.rsplit('.', 1)[-1])
                snmp_result['ansible_facts']['ansible_interfaces'][ifIndex]['operstatus'] = lookup_operstatus(int(current_val))
            if "1.3.6.1.2.1.4.20.1.1" in current_oid: # ipAdEntAddr
                ipIndex = int(current_oid.rsplit('.', 1)[-1])
                all_ipv4_addresses.append(current_val)


            if "1.3.6.1.2.1.31.1.1.1.18" in current_oid: # ifAlias
                ifIndex = int(current_oid.rsplit('.', 1)[-1])
                snmp_result['ansible_facts']['ansible_interfaces'][ifIndex]['description'] = current_val

                

    snmp_result['ansible_facts']['ansible_all_ipv4_addresses'] = all_ipv4_addresses
 
    module.exit_json(**snmp_result)
    


from ansible.module_utils.basic import *

main()

