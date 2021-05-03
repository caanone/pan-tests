import csv
import logging
import colorlog
import requests
from panos import device
from panos import errors
from panos import firewall
from panos import panorama
from panos import policies
from panos import predefined
from panos.panorama import DeviceGroup


def init_logger(dunder_name, debug_mode=True):
    log_format = (
        '%(asctime)s - '
        # '%(name)s - '
        '%(lineno)d - '
        '%(funcName)s - '
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
             {'IP_ADDR': '',
              'API_KEY': '',
              'DEVICE': 'firewall',
              'API_USERNAME': '',
              'API_PASSWORD': ''
              },
         'SN-1':
             {'IP_ADDR': '',
              'API_KEY': '',
              'DEVICE': 'panorama',
              'API_USERNAME': '',
              'API_PASSWORD': ''
              }
         }

log = init_logger(__name__)
log.setLevel(logging.DEBUG)


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
    if device._api_key in ("", None):
        api_key = None
        try:
            device_xapi = device.generate_xapi()
            if isinstance(device, panorama.Panorama):
                device_xapi = device.generate_xapi()
                device_xapi.api_username = device._api_username
                device_xapi.api_password = device._api_password
                device_xapi.hostname = device.hostname
                device_xapi.keygen()
                device._api_key = device_xapi.api_key
                api_key = device_xapi.api_key
                log.info(f"{device.serial} Generated API KEY : {api_key} ")
            elif isinstance(device, firewall.Firewall):
                # panxapi = PanXapi(api_username=device._api_username, api_password=device._api_password, hostname=device.hostname)
                req = requests.get(
                    f"https://{device.hostname}/api/?type=keygen&user={device._api_username}&password={device._api_password}",
                    verify=False)
                log.critical(req)
                api_key = req
                log.info(f"{device.serial} Generated API KEY : {api_key} ")
            else:
                log.error("Couldnt find device type for api key request")
            HOSTS[device.serial]['API_KEY'] = api_key
            log.info(f"Device: {device.hostname} API key created or updated")
        except errors.PanXapiError as e:
            log.error(e)
    else:
        log.debug(f'Device: {device.hostname} Already have api key')


def get_local_policies_from_fw(fw):
    local_rules = []
    rule_base = fw.add(policies.Rulebase())
    fw_local_policies = policies.SecurityRule.refreshall(rule_base)
    for pol in fw_local_policies:
        local_rules.append(pol.about())
    return local_rules


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


def get_DeviceGroup_with_FirewallChildren(_panorama: panorama.Panorama, returnDeviceGroups=True):
    pan_devs = _panorama.refresh_devices(include_device_groups=True, expand_vsys=False, add=True)
    _dev_grp = ""
    for pan_dev in pan_devs:
        if isinstance(pan_dev, DeviceGroup) and len(pan_dev.children):
            for child_fw in pan_dev.children:
                if child_fw.serial in HOSTS.keys():
                    child_fw._api_key = HOSTS[child_fw.serial]['API_KEY']
                    child_fw.hostname = HOSTS[child_fw.serial]['IP_ADDR']
                    child_fw.api_username = HOSTS[child_fw.serial]['API_USERNAME']
                    child_fw._api_username = HOSTS[child_fw.serial]['API_USERNAME']
                    child_fw.api_password = HOSTS[child_fw.serial]['API_PASSWORD']
                    child_fw._api_password = HOSTS[child_fw.serial]['API_PASSWORD']
                else:
                    log.error(f"{child_fw.serial} not found in HOSTS. Please add it.")
    if returnDeviceGroups:
        return [x for x in pan_devs if isinstance(x, DeviceGroup)]
    else:
        return pan_devs


def check_connectivity(_device: device.PanObject):
    try:
        _device.op(cmd="show ntp", xml=True)
        return True
    except (errors.PanXapiError, errors.PanURLError) as e:
        log.error(f"Device: {_device.hostname} not reachable, error_msg: {e}")
        return False


def create_dev_obj(_hosts):
    dev_objs = []
    for host in _hosts:
        dev, active = None, False
        if _hosts[host]['DEVICE'] == "panorama":

            dev = panorama.Panorama(hostname=_hosts[host]['IP_ADDR'], api_key=_hosts[host]['API_KEY'],
                                    api_username=_hosts[host]['API_USERNAME'],
                                    api_password=_hosts[host]['API_PASSWORD'])

            dev._api_key = _hosts[host]['API_KEY']
            # generate_api_key(dev)
        elif _hosts[host]['DEVICE'] == "firewall":
            dev = firewall.Firewall(hostname=_hosts[host]['IP_ADDR'], api_key=_hosts[host]['API_KEY'],
                                    api_username=_hosts[host]['API_USERNAME'],
                                    api_password=_hosts[host]['API_PASSWORD'],
                                    serial=_hosts[host])
            dev._api_key = _hosts[host]['API_KEY']
            # generate_api_key(dev)
        else:
            log.error(f'Unexpected device type  {host}')
        if check_connectivity(dev):
            dev_objs.append([dev, dev.serial])
            log.debug(f'{host} - {_hosts[host]["IP_ADDR"]}  added successfully to host list')
        else:
            log.info(f'{host} - {_hosts[host]["IP_ADDR"]} not added to host list')

    return dev_objs


def compare_running_configs_in_DeviceGroups(_deviceGroupList):
    # Get firewall list from DeviceGroup
    results = []
    for _devgrp in _deviceGroupList:
        _fw_List = [x for x in _devgrp.children if isinstance(x, firewall.Firewall)]
        # TODO: change to gt 1
        if len(_fw_List) > 0:
            try:
                # TODO: Need to change second fw's index. Like, if both fw are HA pair, "_fw_List[0] == _fw_List[0].ha_peer()"
                # TODO: Use find() method for specific comparison
                firewall_A = _fw_List[0].show_system_info()
                firewall_B = _fw_List[0].show_system_info()
                if firewall_A == firewall_B:
                    results.append(f"DeviceGroup \'{_devgrp}\'. \'{_fw_List[0]}\' and \'{_fw_List[0]}\' synced peers ")
                else:
                    results.append(
                        f"DeviceGroup \'{_devgrp}\'. \'{_fw_List[0]}\' and \'{_fw_List[0]}\' not synced, check peers configurations")
            except (errors.PanXapiError, errors.PanURLError) as e:
                log.error(f"Comparing: {_fw_List} ,failed error_msg: {e}")
        else:
            log.info(f"Only {len(_fw_List)} firewalls in {_devgrp}")
    return results


if __name__ == '__main__':
    devices = create_dev_obj(HOSTS)
    for dev, serial in devices:
        if isinstance(dev, panorama.Panorama):

            x = get_DeviceGroup_with_FirewallChildren(dev)
            log.info(compare_running_configs_in_DeviceGroups(x))
