#!/usr/bin/python3
import openstack
import sys
import json
import os
import yaml


def main():
    openstack.enable_logging(debug=False)
    try:
        conn = openstack.connect(cloud='openstack')
        print("Connected!")
    except: 
        print("Error!")
        sys.exit(1)
    
    with open("test.txt", "r") as f:
        with open("new.txt", "w") as wf:
            for line in f:
                line = line.replace('{', ':')
                line = line.replace('/*', '#')
                line = line.replace('*/', '')
                line = line[::-1]
                line = line.replace('   ', ' - ', 1)
                line = line[::-1]
                if line.find('}') == -1:
                    wf.write(line)
    with open('new.txt') as f:
        config = yaml.safe_load(f)

    #print('Please enter name of security group:')
    #security_group = input()
    print('Please enter floating ip:')
    floating_ip = input()
    
    for ip in conn.list_floating_ips():
        if ip.floating_ip_address == floating_ip:
            res_port_id = ip.port_id
            break
    for port in conn.network.ports():
        if port.id == res_port_id:
            fixed_ip = port.fixed_ips[0]['ip_address']
            print(fixed_ip)
            break
    for eth in config['interfaces']:
        for key, val in eth.items():
            if val != None:
                if val[0].find(fixed_ip) != -1:
                    for name in config['firewall']:
                        for rule, val in name.items():
                            if rule.find('in_') != -1:
                                print('set interfaces ' + key + ' firewall in ' + rule)
                            if rule.find('out_') != -1:
                                print('set interfaces ' + key + ' firewall out ' + rule)
                    break
    line = str(json.dumps(config, indent = 4))
    line = line.replace(':', '')
    line = line.replace('"', '')
    line = line.replace('\\', '"')
    line = line.replace(',', '')
    #print(line)
    print('Done!')

if __name__ == '__main__':
    main()
