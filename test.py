#!/usr/bin/python3
import openstack
import sys

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
        with open('result.txt', 'w') as f:
            f.write('del firewall name IPv4_' + name + '\n')
            f.write('set firewall name IPv4_' + name + ' default-action ' + "'" + 'drop' + "'" +' \n')
            f.write('del firewall ipv6-name IPv6_' + name + '\n')
            f.write('set firewall ipv6-name IPv6_' + name + ' default-action ' + "'" + 'drop' + "'" +' \n')
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
            with open('result.txt', 'a') as f:
                if ethertype == 'IPv4':
                    rule_cnt_ipv4 += 1
                    rule_cnt = rule_cnt_ipv4
                    tmp = 'set firewall name IPv4_' + name + ' rule ' + str(rule_cnt)
                elif ethertype == 'IPv6':
                    rule_cnt_ipv6 += 1
                    rule_cnt = rule_cnt_ipv6
                    tmp = 'set firewall ipv6-name IPv6_' + name + ' rule ' + str(rule_cnt)
                f.write(tmp + ' action ' + "'" + 'accept' + "'" + '\n')
                if port_range_min != None and port_range_max != None:
                    if port_range_min == port_range_max:
                        port = port_range_min
                        if direction == 'ingress':
                            f.write(tmp + ' destination port ' + "'" + str(port) + "'" + '\n')
                        elif direction == 'egress':
                            f.write(tmp + ' source port ' + "'" + str(port) + "'" + '\n')
                    else:
                        if direction == 'ingress':
                            f.write(tmp + ' destination port ' + "'" + str(port_range_min) + '-' + str(port_range_max) + "'" + '\n')
                        elif direction == 'egress':
                            f.write(tmp + ' source port ' + "'" + str(port_range_min) + '-' + str(port_range_max) + "'" + '\n')
                if remote_ip_prefix != None:
                    if direction == 'ingress':
                        f.write(tmp + ' destination address ' + "'" + remote_ip_prefix + "'" + '\n')
                    elif direction == 'egress':
                        f.write(tmp + ' source address ' + "'" + remote_ip_prefix + "'" + '\n' )
                if protocol != None:
                    f.write(tmp + ' protocol ' + "'" + protocol + "'" + '\n')
                else:
                    f.write(tmp + ' protocol ' + "'" + 'all' + "'" + '\n')
                if description != None:
                    f.write(tmp + ' description ' + "'" + description + "'" + '\n')
                    
        break
    if flag == False:
        print('Entered bad name!')
        
if __name__ == '__main__':
    main()
