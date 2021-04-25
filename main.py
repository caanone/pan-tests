import csv
import panos
from panos import firewall
from panos import objects
from panos import panorama
from panos import policies

from creds import *
##### creds.py ####
# import requests
# from urllib3.exceptions import InsecureRequestWarning
# PAN_CERT_VALID = False
#
# if not PAN_CERT_VALID:
#     requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)
# hosts = {'FIREWALL1':
#          {'IP_ADDR':'x.x.x.x',
#           'API_KEY':'XXXXXXXXX',
#           'DEVICE':'firewall'
#           },
#     'PANORAMA':
#          {'IP_ADDR':'x.x.x.x',
#           'API_KEY':'XXXXXXXXX',
#           'DEVICE':'panorama'
#           }
#          }
###########################################


def create_bulk_fw_rules(device: firewall.Firewall):
    rulebase = policies.Rulebase()
    device.add(rulebase)
    candidate_rules = []
    csv_reader = csv.reader(open('rules.csv', 'r'))
    tagg = objects.Tag(name='risky')
    for row in csv_reader:
        rule_name = row[0]
        source_zone = row[1].split(' ')
        source_ip = row[2].split(' ')
        destination_zone = row[3].split(' ')
        destination_ip = row[4].split(' ')
        application = row[5].split(' ')
        service = row[6].split(' ')
        action = row[7]
        candidate_rules.append(policies.SecurityRule(
            name=rule_name,
            fromzone=source_zone,
            source=source_ip,
            tozone=destination_zone,
            destination=destination_ip,
            application=application,
            service=service,
            action=action,
            tag=tagg
        ))
    rulebase.extend(candidate_rules)
    rulebase.find(str(candidate_rules[0])).create_similar()
    device.commit()


def get_local_policies_from_fw(fw):
    local_policies = []
    rule_base = fw.add(policies.Rulebase())
    fw_local_policies = policies.SecurityRule.refreshall(rule_base)
    for pol in fw_local_policies:
        local_policies.append(pol.about())
    return local_policies


def get_predefined_services(device: firewall.Firewall):
    # https://pan-os-python.readthedocs.io/en/latest/module-predefined.html
    pass


def find_fw_on_pan(_panorama):
    pan_devs = _panorama.refresh_devices(include_device_groups=False, expand_vsys=False)
    for p_dev in pan_devs:
        for x in devices:
            if x[1] == p_dev.about()['serial']:
                p_dev = x[0]
    return p_dev


def create_dev_obj(hosts):
    dev_objs = []
    for host in hosts:
        dev, active = '', False
        if hosts[host]['DEVICE'] == "panorama":
            dev = panorama.Panorama(hostname=hosts[host]['IP_ADDR'], api_key=hosts[host]['API_KEY'])
        elif hosts[host]['DEVICE'] == "firewall":
            dev = firewall.Firewall(hostname=hosts[host]['IP_ADDR'], api_key=hosts[host]['API_KEY'])
        else:
            print('unexpected device type', host)
        try:
            active = dev.is_active()
        except (panos.firewall.err.PanDeviceXapiError, panos.firewall.err.PanURLError) as e:
            print(dev, "not reachable ", e)
        if active:
            dev_objs.append([dev, dev.show_system_info()['system']['serial']])
    return dev_objs


if __name__ == '__main__':
    devices = create_dev_obj(hosts)
    for dev, serial in devices:
        if isinstance(dev, panorama.Panorama):
            p_dev = find_fw_on_pan(dev)
            for x in get_local_policies_from_fw(p_dev):
                print(f"name: {x['name']}, app: {x['application']}, service: {x['service']}, action: {x['action']}")

            print(dev_sys_info['serial'], "\t", dev_sys_info['ip-address'])
        elif isinstance(dev, firewall.Firewall):
            dev_sys_info = dev.show_system_info()['system']
            print(dev_sys_info['serial'], "\t", dev_sys_info['ip-address'])
        # except (panorama.err.PanURLError, pan.xapi.PanXapiError) as e:
        #     print(f'Connection error: {e}')
