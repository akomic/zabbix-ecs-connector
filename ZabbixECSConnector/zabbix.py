import sys
import time
import logging

from pyzabbix import ZabbixAPI


class Zabbix(object):
    def __init__(self, payload, Config, default_group='ECS'):
        self.payload = payload
        self.Config = Config
        self.cluster2proxy = Config['cluster2proxy']
        self.cluster2proxyId = {}
        self.default_group = default_group

        self.data = {'groups': None, 'hosts': None,
                     'proxies': None, 'templates': None}

        self.runningInstances = []
        self.instanceGroups = {}
        self.instanceTemplates = []

        self.log = logging.getLogger(__name__)
        self.log.setLevel(logging.DEBUG)
        ch = logging.StreamHandler()
        self.log.addHandler(ch)

        self.stats = {
            'created_hosts': 0,
            'deleted_hosts': 0,
            'created_groups': 0,
            'clusters': 0,
            'running_instances': 0
        }

        self.zapi = self.api_connect()

    def api_connect(self):
        while True:
            try:
                zapi = ZabbixAPI(self.Config['Zabbix']['url'])

                zapi.session.verify = True
                zapi.timeout = 5
                zapi.login(self.Config['Zabbix']['user'],
                           self.Config['Zabbix']['pass'])
                self.log.debug("Connected to Zabbix API Version %s" %
                               zapi.api_version())
                return zapi
            except Exception as e:
                self.log.warning("ERROR connecting to Zabbix API: {0}".
                                 format(e))
                time.sleep(300)
                pass

    def get_state(self):
        self.data['groups'] = self.zapi.hostgroup.get(output='extend')
        self.data['hosts'] = self.zapi.host.get(
            output='extend',
            selectGroups='extend',
            selectParentTemplates='extend'
        )
        self.data['proxies'] = self.zapi.proxy.get(output='extend')
        proxies = {p['host']: p['proxyid'] for p in self.data['proxies']}
        for clusterName, proxyName in self.cluster2proxy.items():
            self.cluster2proxyId[clusterName] = proxies[proxyName]

        self.data['templates'] = self.zapi.template.get(output='extend')
        self.instanceTemplates = [
            {'templateid': t['templateid']} for t in self.data['templates']
            if t['host'] in self.Config['Zabbix']['instanceTemplates']
        ]

    def housekeeping(self):
        self.get_state()
        if 'hosts' in self.data:
            for host in self.data['hosts']:
                memberOfGroups = [g['name'] for g in host['groups']]
                if self.default_group not in memberOfGroups:
                    continue

                if host['host'] not in self.runningInstances:
                    self.log.debug("Deleting host {}".format(host['host']))
                    try:
                        self.zapi.host.delete(host['hostid'])
                        self.stats['deleted_hosts'] += 1
                    except Exception as e:
                        self.log.warning("ERROR deleting host: {} {}".
                                         format(host['host'], e))

    def group_exists(self, groupName):
        ret = [g['groupid'] for g in self.data['groups']
               if g['name'] == groupName]
        if len(ret) == 0:
            return False
        else:
            return ret[0]

    def create_group(self, groupName):
        groupid = self.group_exists(groupName)
        if not groupid:
            self.log.debug("Creating group {}".format(groupName))
            try:
                resp = self.zapi.hostgroup.create(name=groupName)
            except Exception as e:
                self.log.warning("ERROR creating proxied host: {} {}".
                                 format(groupName, e))
                return {}
            else:
                self.log.debug("Created group {}".format(groupName))
                self.data['groups'].append({
                    "groupid": resp['groupids'][0],
                    "name": groupName,
                    "internal": "0",
                    "flags": "0"
                })
                self.stats['created_groups'] += 1
                return {'groupid': resp['groupids'][0]}
        else:
            return {'groupid': groupid}

    def create_groups(self, groupNames):
        groupNames.append(self.default_group)
        groupNames = list(set(groupNames))
        groupIds = []
        for groupName in groupNames:
            groupid = self.create_group(groupName)
            groupIds.append(groupid)
        return groupIds

    def host_exists(self, ec2InstanceId):
        matching_hosts = [h['hostid'] for h in self.data['hosts']
                          if h['host'] == ec2InstanceId]
        return matching_hosts[0] if len(matching_hosts) > 0 else None

    def create_proxied_instance(self, ec2InstanceId, instance, proxyId):
        hostID = self.host_exists(ec2InstanceId)
        if hostID is None:
            try:
                self.zapi.host.create(
                    host=ec2InstanceId,
                    interfaces=[{
                        'type': 1,
                        'main': 1,
                        'useip': 1,
                        'ip': instance['PrivateIpAddress'],
                        'dns': '',
                        'port': 10050
                    }],
                    groups=self.instanceGroups[ec2InstanceId],
                    proxy_hostid=proxyId,
                    templates=self.instanceTemplates
                )
            except Exception as e:
                self.log.warning("ERROR creating proxied host: {} {}".
                                 format(ec2InstanceId, e))
            else:
                groups = [g['groupid']
                          for g in self.instanceGroups[ec2InstanceId]]
                self.log.debug("Created proxied host {}"
                               " groups: {}"
                               " proxyid: {}"
                               " ip: {}".format(
                                   ec2InstanceId,
                                   ','.join(groups),
                                   proxyId,
                                   instance['PrivateIpAddress']
                               ))
                self.stats['created_hosts'] += 1
        else:
            try:
                self.zapi.host.update(
                    hostid=hostID,
                    groups=self.instanceGroups[ec2InstanceId],
                    templates=self.instanceTemplates
                )
            except Exception as e:
                self.log.warning("ERROR updating host: {} {}".
                                 format(ec2InstanceId, e))
            else:
                groups = [g['groupid']
                          for g in self.instanceGroups[ec2InstanceId]]
                self.log.debug("Updated host {}"
                               " groups: {}"
                               " ip: {}".format(
                                   ec2InstanceId,
                                   ','.join(groups),
                                   instance['PrivateIpAddress']
                               ))

    def create_instance(self, ec2InstanceId, instance):
        hostID = self.host_exists(ec2InstanceId)
        if hostID is None:
            try:
                self.zapi.host.create(
                    host=ec2InstanceId,
                    interfaces=[{
                        'type': 1,
                        'main': 1,
                        'useip': 1,
                        'ip': instance['PrivateIpAddress'],
                        'dns': '',
                        'port': 10050
                    }],
                    groups=self.instanceGroups[ec2InstanceId],
                    templates=self.instanceTemplates
                )
            except Exception as e:
                self.log.warning("ERROR creating host: {} {}".
                                 format(ec2InstanceId, e))
            else:
                groups = [g['groupid']
                          for g in self.instanceGroups[ec2InstanceId]]
                self.log.debug("Created host {}"
                               " groups: {}"
                               " ip: {}".format(
                                   ec2InstanceId,
                                   ','.join(groups),
                                   instance['PrivateIpAddress']
                               ))
                self.stats['created_hosts'] += 1
        else:
            try:
                self.zapi.host.update(
                    hostid=hostID,
                    groups=self.instanceGroups[ec2InstanceId],
                    templates=self.instanceTemplates
                )
            except Exception as e:
                self.log.warning("ERROR updating host: {} {}".
                                 format(ec2InstanceId, e))
            else:
                groups = [g['groupid']
                          for g in self.instanceGroups[ec2InstanceId]]
                self.log.debug("Updated host {}"
                               " groups: {}"
                               " ip: {}".format(
                                   ec2InstanceId,
                                   ','.join(groups),
                                   instance['PrivateIpAddress']
                               ))

    def run(self):
        self.get_state()
        for accountName, account in self.payload.items():
            for clusterArn, cluster in account.items():
                self.stats['clusters'] += 1
                for ec2InstanceId, instance in cluster['instances'].items():
                    self.stats['running_instances'] += 1
                    self.runningInstances.append(ec2InstanceId)
                    self.instanceGroups[ec2InstanceId] = self.create_groups(
                        instance['Groups'])
                    if cluster['name'] in self.cluster2proxyId:
                        self.create_proxied_instance(
                            ec2InstanceId, instance,
                            self.cluster2proxyId[cluster['name']])
                    else:
                        self.create_instance(ec2InstanceId, instance)

        self.log.info("{}".format(self.stats))
        self.housekeeping()
