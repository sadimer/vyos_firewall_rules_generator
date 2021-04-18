#!/usr/bin/python3
import openstack
import sys
import json

def main():
    openstack.enable_logging(debug=False)
    try:
        conn = openstack.connect(cloud='openstack')
        print("Connected!")
    except: 
        print("Error!")
        sys.exit(1)
    
    flag = False
    print('Please enter name of security group:')
    search_name = input();
    for group in conn.network.security_groups():
        name = group.name
        if name != search_name:
            continue
        print('Name discovered!')
        flag = True
        firewall = {'ipv6-name IPv6_' + name:{'default-action':'drop'}, 'name IPv4_' + name:{'default-action':'drop'}}
        group_id = group.id
        description = group.description
        security_group_rules = group.security_group_rules
        rule_cnt_ipv4 = 0
        rule_cnt_ipv6 = 0
        for rule in security_group_rules:
            rule_id = rule['id']
            direction = rule['direction']
            ethertype = rule['ethertype']
            protocol = rule['protocol']
            port_range_min = rule['port_range_min']
            port_range_max = rule['port_range_max']
            remote_ip_prefix = rule['remote_ip_prefix']
            remote_group_id = rule['remote_group_id']
            description = rule['description']
            tags = rule['tags']
            created_at = rule['created_at']
            updated_at = rule['updated_at']
            revision_number = rule['revision_number']
            if remote_group_id != None:
                new_flag = False
                for group in conn.network.security_groups():
                    new_name = group.name
                    new_group_id = group.id
                    if new_group_id != remote_group_id:
                        continue
                    new_flag = True
                    new_description = group.description
                    new_security_group_rules = group.security_group_rules
                    for rule in new_security_group_rules:
                        new_rule_id = rule['id']
                        if new_rule_id == rule_id:
                            continue
                        new_direction = rule['direction']
                        new_ethertype = rule['ethertype']
                        new_protocol = rule['protocol']
                        new_port_range_min = rule['port_range_min']
                        new_port_range_max = rule['port_range_max']
                        new_remote_ip_prefix = rule['remote_ip_prefix']
                        new_remote_group_id = rule['remote_group_id']
                        new_description = rule['description']
                        new_tags = rule['tags']
                        new_created_at = rule['created_at']
                        new_updated_at = rule['updated_at']
                        new_revision_number = rule['revision_number']
                        if new_direction == direction and new_ethertype == ethertype and new_remote_group_id == None and (new_protocol == protocol or new_protocol == None):
                            res_port_range_min = None
                            res_port_range_max = None
                            res_remote_ip_prefix = None
                            if port_range_min == None and port_range_max == None:
                                res_port_range_min = new_port_range_min
                                res_port_range_max = new_port_range_max
                                res_remote_ip_prefix = new_remote_ip_prefix
                            elif new_port_range_min == None and new_port_range_max == None:
                                res_remote_ip_prefix = new_remote_ip_prefix
                                res_port_range_min = port_range_min
                                res_port_range_max = port_range_max
                            elif port_range_min >= new_port_range_min and port_range_max <= new_port_range_max:
                                res_remote_ip_prefix = new_remote_ip_prefix
                                res_port_range_min = port_range_min
                                res_port_range_max = port_range_max
                            if ethertype == 'IPv4':
                                rule_cnt_ipv4 += 1
                                rule_cnt = rule_cnt_ipv4
                                index = 'name IPv4_' + name
                            elif ethertype == 'IPv6':
                                rule_cnt_ipv6 += 1
                                rule_cnt = rule_cnt_ipv6
                                index = 'ipv6-name IPv6_' + name
                            rule_index = 'rule ' + str(rule_cnt)
                            firewall[index][rule_index] = {}
                            firewall[index][rule_index]['action'] = 'accept'
                            if res_remote_ip_prefix != None:
                                if direction == 'egress':
                                    try:
                                        firewall[index][rule_index]['destination']['address'] = res_remote_ip_prefix
                                    except:
                                        firewall[index][rule_index]['destination'] = {}
                                        firewall[index][rule_index]['destination']['address'] = res_remote_ip_prefix
                                elif direction == 'ingress':
                                    try:
                                        firewall[index][rule_index]['source']['address'] = res_remote_ip_prefix
                                    except:
                                        firewall[index][rule_index]['source'] = {}
                                        firewall[index][rule_index]['source']['address'] = res_remote_ip_prefix
                            if description != None:
                                firewall[index][rule_index]['description'] = '"' + description + '"'
                            if protocol != None:
                                firewall[index][rule_index]['protocol'] = protocol
                            else:
                                firewall[index][rule_index]['protocol'] = 'all'
                            if protocol == 'udp' or protocol == 'tcp':
                                if res_port_range_min != None and res_port_range_max != None:
                                    if res_port_range_min == res_port_range_max:
                                        port = res_port_range_min
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
                                                firewall[index][rule_index]['destination']['port'] = str(res_port_range_min) + '-' + str(res_port_range_max)
                                            except:
                                                firewall[index][rule_index]['destination'] = {}
                                                firewall[index][rule_index]['destination']['port'] = str(res_port_range_min) + '-' + str(res_port_range_max)
                                        elif direction == 'ingress':
                                            try:
                                                firewall[index][rule_index]['source']['port'] = str(res_port_range_min) + '-' + str(res_port_range_max)
                                            except:
                                                firewall[index][rule_index]['source'] = {}
                                                firewall[index][rule_index]['source']['port'] = str(res_port_range_min) + '-' + str(res_port_range_max)
                if new_flag == False:
                    sys.exit(1)
                else:
                    continue
            if ethertype == 'IPv4':
                rule_cnt_ipv4 += 1
                rule_cnt = rule_cnt_ipv4
                index = 'name IPv4_' + name
            elif ethertype == 'IPv6':
                rule_cnt_ipv6 += 1
                rule_cnt = rule_cnt_ipv6
                index = 'ipv6-name IPv6_' + name
            rule_index = 'rule ' + str(rule_cnt)
            firewall[index][rule_index] = {}
            firewall[index][rule_index]['action'] = 'accept'
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
            if protocol != None:
                firewall[index][rule_index]['protocol'] = protocol
            else:
                firewall[index][rule_index]['protocol'] = 'all'
            if description != None:
                firewall[index][rule_index]['description'] = '"' + description + '"'
        break
        
    if flag == False:
        print('Entered bad name!')
        sys.exit(1)
    line = 'firewall ' + str(json.dumps(firewall, indent = 4))
    line = line.replace(':', '')
    line = line.replace('"', '')
    line = line.replace('\\', '"')
    line = line.replace(',', '')
    #print(line)
    with open("result.txt", "w") as result_file:
        with open("migration_details.txt", "r") as add_file:
            result_file.write(line + '\n')
            for line in add_file:
                result_file.write(line)
    print('Done!')
        
if __name__ == '__main__':
    main()
