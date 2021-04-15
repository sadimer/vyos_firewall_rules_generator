#!/usr/bin/python3
import openstack
import sys
import json

def main():
    import openstack
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
        firewall = {'firewall':{'ipv6-name IPv6_' + name:{'default-action':'drop'}, 'name IPv4_' + name:{'default-action':'drop'}}}
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
            if ethertype == 'IPv4':
                rule_cnt_ipv4 += 1
                rule_cnt = rule_cnt_ipv4
                index = 'name IPv4_' + name
                rule_index = 'rule ' + str(rule_cnt)
            elif ethertype == 'IPv6':
                rule_cnt_ipv6 += 1
                rule_cnt = rule_cnt_ipv6
                index = 'ipv6-name IPv6_' + name
                rule_index = 'rule ' + str(rule_cnt)
            firewall['firewall'][index][rule_index] = {}
            if protocol == 'udp' or protocol == 'tcp':
                if port_range_min != None and port_range_max != None:
                    if port_range_min == port_range_max:
                        port = port_range_min
                        if direction == 'ingress':
                            firewall['firewall'][index][rule_index]['destination port'] = str(port)
                        elif direction == 'egress':
                            firewall['firewall'][index][rule_index]['source port'] = str(port)
                    else:
                        if direction == 'ingress':
                            firewall['firewall'][index][rule_index]['destination port'] = str(port_range_min) + '-' + str(port_range_max)
                        elif direction == 'egress':
                            firewall['firewall'][index][rule_index]['source port'] = str(port_range_min) + '-' + str(port_range_max)
            if remote_ip_prefix != None:
                if direction == 'ingress':
                    firewall['firewall'][index][rule_index]['destination address'] = remote_ip_prefix
                elif direction == 'egress':
                    firewall['firewall'][index][rule_index]['source address'] = remote_ip_prefix
            if protocol != None:
                firewall['firewall'][index][rule_index]['protocol'] = protocol
            else:
                firewall['firewall'][index][rule_index]['protocol'] = 'all'
            if description != None:
                firewall['firewall'][index][rule_index]['description'] = '"' + description + '"'
        break
    if flag == False:
        print('Entered bad name!')
        sys.exit(1)
    with open("config.json", "w") as write_file:
        json.dump(firewall, write_file)
    with open("config.json", "r") as read_file:
        line = str(json.load(read_file))
        line = line.replace(':', '')
        line = line.replace("'", '')
        line = line.replace(',', '')
        line = line.replace('{', '', 1)
        line = line[::-1]
        line = line.replace('}', '', 1)
        line = line[::-1]
    with open("result.txt", "w") as result_file:
        result_file.write(line)
    print('Done!')
        
if __name__ == '__main__':
    main()
