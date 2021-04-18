#!/usr/bin/python3
import openstack
import sys
import json
import os

#при использовании взять свои параметры из файла /config/config.boot
config_version = '\n// vyos-config-version: "bgp@1:broadcast-relay@1:cluster@1:config-management@1:conntrack@2:conntrack-sync@1:dhcp-relay@2:dhcp-server@5:dhcpv6-server@1:dns-forwarding@3:firewall@5:https@2:interfaces@20:ipoe-server@1:ipsec@5:isis@1:l2tp@3:lldp@1:mdns@1:nat@5:nat66@1:ntp@1:pppoe-server@5:pptp@2:qos@1:quagga@9:rpki@1:salt@1:snmp@2:ssh@2:sstp@3:system@20:vrf@2:vrrp@2:vyos-accel-ppp@2:wanloadbalance@3:webproxy@2:zone-policy@1"'
vyos_version = '\n// Release version: 1.4-rolling-202104132216'
#результат - result.txt - файл конфигурации файрвола vyos, установка производится командой # merge result.txt 


fixed_name = None

rule_cnt_ipv4_in = 0
rule_cnt_ipv6_in = 0
rule_cnt_ipv4_out = 0
rule_cnt_ipv6_out = 0
 
def create_index(ethertype, direction, name):
    global rule_cnt_ipv4_in
    global rule_cnt_ipv6_in
    global rule_cnt_ipv4_out
    global rule_cnt_ipv6_out
    if ethertype == 'IPv4':
        if direction == 'ingress':
            index = 'name ' + 'in_'+ 'IPv4_' + name
            rule_cnt_ipv4_in += 1
            rule_cnt = rule_cnt_ipv4_in
        if direction == 'egress':
            index = 'name ' + 'out_'+ 'IPv4_' + name
            rule_cnt_ipv4_out += 1
            rule_cnt = rule_cnt_ipv4_out
    elif ethertype == 'IPv6':
        if direction == 'ingress':
            index = 'ipv6-name ' + 'in_'+ 'IPv6_' + name
            rule_cnt_ipv6_in += 1
            rule_cnt = rule_cnt_ipv6_in
        if direction == 'egress':
            index = 'ipv6-name ' + 'out_'+ 'IPv6_' + name
            rule_cnt_ipv6_out += 1
            rule_cnt = rule_cnt_ipv6_out
    return rule_cnt, index
    
def set_ip(remote_ip_prefix, firewall, index, rule_index, direction):
    if remote_ip_prefix != None:
        if direction == 'egress':
            try:
                firewall[index][rule_index]['destination']['address'] = remote_ip_prefix
            except:
                firewall[index][rule_index]['destination'] = {}
                firewall[index][rule_index]['destination']['address'] = remote_ip_prefix
        elif direction == 'ingress':
            try:
                firewall[index][rule_index]['source']['address'] = remote_ip_prefix
            except:
                firewall[index][rule_index]['source'] = {}
                firewall[index][rule_index]['source']['address'] = remote_ip_prefix

def set_ports(port_range_min, port_range_max, protocol, firewall, index, rule_index, direction):
    if protocol == 'udp' or protocol == 'tcp':
        if port_range_min != None and port_range_max != None:
            if port_range_min == port_range_max:
                port = port_range_min
                if direction == 'egress':
                    try:
                        firewall[index][rule_index]['destination']['port'] = str(port)
                    except:
                        firewall[index][rule_index]['destination'] = {}
                        firewall[index][rule_index]['destination']['port'] = str(port)
                elif direction == 'ingress':
                    try:
                        firewall[index][rule_index]['source']['port'] = str(port)
                    except:
                        firewall[index][rule_index]['source'] = {}
                        firewall[index][rule_index]['source']['port'] = str(port)
            else:
                if direction == 'egress':
                    try:
                        firewall[index][rule_index]['destination']['port'] = str(port_range_min) + '-' + str(port_range_max)
                    except:
                        firewall[index][rule_index]['destination'] = {}
                        firewall[index][rule_index]['destination']['port'] = str(port_range_min) + '-' + str(port_range_max)
                elif direction == 'ingress':
                    try:
                        firewall[index][rule_index]['source']['port'] = str(port_range_min) + '-' + str(port_range_max)
                    except:
                        firewall[index][rule_index]['source'] = {}
                        firewall[index][rule_index]['source']['port'] = str(port_range_min) + '-' + str(port_range_max)
                        
def set_protocol(protocol, firewall, index, rule_index):
    if protocol != None:
        firewall[index][rule_index]['protocol'] = protocol
    else:
        firewall[index][rule_index]['protocol'] = 'all'
        
def set_description(description, firewall, index, rule_index, name):
    if description != None:
        firewall[index][rule_index]['description'] = '"' + description + 'from ' + name + '"'

def process(conn, search_name = None, search_id = None, search_flag = False, old_rule = None, old_group = None, old_firewall = None):
    global fixed_name
    flag = False
    for group in conn.network.security_groups():
        name = group.name
        group_id = group.id
        if search_flag == False:
            if name != search_name:
                continue
            print('Name discovered!')
        else:
            if group_id != search_id:
                continue
        flag = True
        name = name[0:15]
        if search_flag == False:
            firewall = {'ipv6-name ' + 'in_' + 'IPv6_' + name:{'default-action':'drop'},
            'name ' + 'in_' + 'IPv4_' + name:{'default-action':'drop'},
            'ipv6-name ' + 'out_' + 'IPv6_' + name:{'default-action':'drop'},
            'name ' + 'out_' + 'IPv4_' + name:{'default-action':'drop'}}
        if old_group != None and group_id == old_group.id:
            continue
        description = group.description
        security_group_rules = group.security_group_rules
        for rule in security_group_rules:
            rule_id = rule['id']
            if old_rule != None and rule_id == old_rule['id']:
                continue
            direction = rule['direction']
            ethertype = rule['ethertype']
            protocol = rule['protocol']
            port_range_min = rule['port_range_min']
            port_range_max = rule['port_range_max']
            remote_ip_prefix = rule['remote_ip_prefix']
            remote_group_id = rule['remote_group_id']
            description = rule['description']
            if remote_group_id == group_id:
                continue
            if remote_group_id != None:
                firewall = process(conn, name, search_id = remote_group_id, search_flag = True, old_rule = rule, old_group = group, old_firewall = firewall)
                continue
            if search_flag == False or (direction == old_rule['direction'] and ethertype == old_rule['ethertype'] and remote_group_id == None):
                if search_flag == True:
                    res_port_range_min = None
                    res_port_range_max = None
                    res_remote_ip_prefix = None
                    res_protocol = None
                    if old_rule['protocol'] == None:
                        res_protocol = protocol
                    elif protocol == old_rule['protocol'] or protocol == None:
                        res_protocol = old_rule['protocol']
                    else:
                        continue
                    if old_rule['port_range_min'] == None and old_rule['port_range_max'] == None:
                        res_port_range_min = port_range_min
                        res_port_range_max = port_range_max
                        res_remote_ip_prefix = remote_ip_prefix
                    elif port_range_min == None and port_range_max == None:
                        res_remote_ip_prefix = remote_ip_prefix
                        res_port_range_min = old_rule['port_range_min']
                        res_port_range_max = old_rule['port_range_max']
                    elif old_rule['port_range_min'] >= port_range_min and old_rule['port_range_max'] <= port_range_max:
                        res_remote_ip_prefix = remote_ip_prefix
                        res_port_range_min = old_rule['port_range_min']
                        res_port_range_max = old_rule['port_range_max']
                    else:
                        continue
                    protocol = res_protocol
                    remote_ip_prefix = res_remote_ip_prefix
                    port_range_min = res_port_range_min 
                    port_range_max = res_port_range_max
                fixed_name = fixed_name[0:15]
                rule_cnt, index = create_index(ethertype, direction, fixed_name)
                rule_index = 'rule ' + str(rule_cnt)
                if search_flag == True:
                    firewall = old_firewall
                firewall[index][rule_index] = {}
                firewall[index][rule_index]['action'] = 'accept'
                set_ports(port_range_min, port_range_max, protocol, firewall, index, rule_index, direction)
                set_ip(remote_ip_prefix, firewall, index, rule_index, direction)
                set_protocol(protocol, firewall, index, rule_index)
                set_description(description, firewall, index, rule_index, name)
        break
    if flag == False:
        print('Entered bad name!')
        sys.exit(1)
    return firewall
    
def main():
    global fixed_name
    openstack.enable_logging(debug=False)
    try:
        conn = openstack.connect(cloud='openstack')
        print("Connected!")
    except: 
        print("Error!")
        sys.exit(1)
    
    flag = False
    print('Please enter name of security group:')
    search_name = input()
    fixed_name = search_name
    firewall = process(conn, search_name)
    line = 'firewall ' + str(json.dumps(firewall, indent = 4))
    line = line.replace(':', '')
    line = line.replace('"', '')
    line = line.replace('\\', '"')
    line = line.replace(',', '')
    with open("result.txt", "w") as result_file:
        result_file.write(line)
        result_file.write(config_version)
        result_file.write(vyos_version)
    print('Done!')
        
if __name__ == '__main__':
    main()
