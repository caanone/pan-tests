import csv
import logging
import colorlog
from panos import firewall
from panos import panorama
from panos import policies
from panos import predefined
from panos.errors import PanXapiError
from panos.panorama import DeviceGroup


def init_logger(dunder_name, debug_mode=True):
    log_format = (
        '%(asctime)s - '
        # '%(name)s - '
        '%(funcName)s - '
        '%(lineno)d - '
        # '%(levelname)s - '
        '%(message)s'
    )
    bold_seq = '\033[1m'
    colorlog_format = (
        f'{bold_seq} '
        '%(log_color)s '
        f'{log_format}'
    )
    colorlog.basicConfig(format=colorlog_format)
    logger = logging.getLogger(dunder_name)
    formatter = logging.Formatter(log_format)

    if debug_mode:
        logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.INFO)

    # # Output full log
    # fh = logging.FileHandler('app.log')
    # fh.setLevel(logging.DEBUG)
    # fh.setFormatter(formatter)
    # # logger.addHandler(fh)
    #
    # # Output warning log
    # fh = logging.FileHandler('app.warning.log')
    # fh.setLevel(logging.WARNING)
    # fh.setFormatter(formatter)
    # # logger.addHandler(fh)
    #
    # # Output error log
    # fh = logging.FileHandler('app.error.log')
    # fh.setLevel(logging.ERROR)
    # fh.setFormatter(formatter)
    # # logger.addHandler(fh)

    return logger


from requests.packages import urllib3
PAN_CERT_VALID = False

if not PAN_CERT_VALID:
    urllib3.disable_warnings(category=urllib3.exceptions.InsecureRequestWarning)
HOSTS = {'SN':
         {'IP_ADDR':'x.x.x.x',
          'API_KEY':'',
          'DEVICE':'firewall',
          'API_USERNAME': 'api-admin',
          'API_PASSWORD': 'xxx'
          },
    'SN-1':
         {'IP_ADDR':'x.x.x.x',
          'API_KEY':'',
          'DEVICE':'panorama',
          'API_USERNAME': 'api-admin',
          'API_PASSWORD': 'xxx'
          }
         }

log = init_logger(__name__)


def create_bulk_fw_test_rules(device: firewall.Firewall):
    rulebase = policies.Rulebase()
    device.add(rulebase)
    candidate_rules = []
    csv_reader = csv.reader(open('rules.csv', 'r'))
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
            action=action
        ))
    rulebase.extend(candidate_rules)
    rulebase.find(str(candidate_rules[0])).create_similar()
    device.commit()


def generate_api_key(device: firewall.Firewall):
    if device._api_key is None:
        try:
            device_xapi = device.generate_xapi()
            device_xapi.api_username = device.api_username
            device_xapi.api_password = device.api_password
            device_xapi.hostname = device.hostname
            device_xapi.keygen()
            device._api_key = device_xapi.api_key
            HOSTS[device.serial]['API_KEY'] = device_xapi.api_key
            log.info(f"Device: {device.hostname} API key created or updated")
        except PanXapiError as e:
            log.error(e)
    else:
        log.debug(f'Already have api key')


def get_local_policies_from_fw(fw):
    local_policies = []
    rule_base = fw.add(policies.Rulebase())
    fw_local_policies = policies.SecurityRule.refreshall(rule_base)
    for pol in fw_local_policies:
        local_policies.append(pol.about())
    return local_policies


def get_post_rules_from_Firewall(firewall):
    post_rules = []
    rule_base = firewall.add(policies.PostRulebase())
    fw_post_rules = policies.SecurityRule.refreshall(rule_base)
    for rule in fw_post_rules:
        post_rules.append(rule.about())
    return post_rules


def get_post_rules_from_DeviceGroup(devGrp: DeviceGroup, type="All"):
    rules = []
    rule_base = devGrp.add(policies.PostRulebase())
    devGrp_rules = policies.SecurityRule.refreshall(rule_base)
    for rule in devGrp_rules:
        rules.append(rule.about())
    return rules


def get_predefined_services(device):
    _predefined = predefined.Predefined(device)
    # https://pan-os-python.readthedocs.io/en/latest/module-predefined.html
    return _predefined


def find_fw_and_devgrp(_panorama: panorama.Panorama) -> {DeviceGroup: [firewall.Firewall]}:
    pan_devs = _panorama.refresh_devices(include_device_groups=True, expand_vsys=False)
    list_pan_devs = {}
    for pan_dev in pan_devs:
        if isinstance(pan_dev, DeviceGroup) and len(pan_dev.__dict__['children']):
            for child_fw in pan_dev.__dict__['children']:
                if child_fw.serial in HOSTS.keys():
                    child_fw._api_key = HOSTS[child_fw.serial]['API_KEY']
                    child_fw.hostname = HOSTS[child_fw.serial]['IP_ADDR']
                    child_fw.api_username = HOSTS[child_fw.serial]['API_USERNAME']
                    child_fw._api_username = HOSTS[child_fw.serial]['API_USERNAME']
                    child_fw.api_password = HOSTS[child_fw.serial]['API_PASSWORD']
                    child_fw._api_password = HOSTS[child_fw.serial]['API_PASSWORD']
            list_pan_devs.update({pan_dev: pan_dev.__dict__['children']})
    return list_pan_devs


def create_dev_obj(_hosts):
    dev_objs = []
    for host in _hosts:
        dev, active = '', False
        if _hosts[host]['DEVICE'] == "panorama":
            dev = panorama.Panorama(hostname=_hosts[host]['IP_ADDR'], api_key=_hosts[host]['API_KEY'],
                                    api_username=_hosts[host]['API_USERNAME'],
                                    api_password=_hosts[host]['API_PASSWORD'])
        elif _hosts[host]['DEVICE'] == "firewall":
            dev = firewall.Firewall(hostname=_hosts[host]['IP_ADDR'], api_key=_hosts[host]['API_KEY'])
        else:
            print('unexpected device type ', host)
        try:
            active = dev.is_active()
        except (firewall.err.PanDeviceXapiError, firewall.err.PanURLError) as e:
            print(dev, "not reachable ", e)
        if active:
            dev_objs.append([dev, dev.show_system_info()['system']['serial']])
    return dev_objs


if __name__ == '__main__':
    devices = create_dev_obj(HOSTS)
    for dev, serial in devices:
        dev_sys_info = dev.show_system_info()['system']
        if isinstance(dev, panorama.Panorama):
            # _predfnd = predefined.Predefined.refreshall(dev.predefined())

            # print(dev.predefined.services(names=['service-http'])[0].about())
            p_dev = find_fw_and_devgrp(dev)
            for dev_grp, fw in p_dev.items():
                fw = fw[0]
                generate_api_key(fw)
                # devGrpPostRules = get_post_rules_from_DeviceGroup(dev_grp)
                # log.info(*get_post_rules_from_DeviceGroup(dev_grp))
                # log.info(get_post_rules_from_Firewall(fw))


        elif isinstance(dev, firewall.Firewall):
            pass
            # print(dev_sys_info['serial'], "\t", dev_sys_info['ip-address'])
