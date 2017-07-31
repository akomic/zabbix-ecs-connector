# import json
import boto3


class AWSECS(object):
    def __init__(self, Config):
        self.AWSAccounts = Config['AWSAccounts']
        self.ecs = {}
        self.ec2 = {}
        self.clusters = {}

        self.groupTags = Config['groupTags']

        for awsAccountName in self.AWSAccounts:
            ref = self.AWSAccounts[awsAccountName]
            self.ecs[awsAccountName] = boto3.client(
                'ecs',
                aws_access_key_id=ref['key'],
                aws_secret_access_key=ref['secret']
            )
            self.ec2[awsAccountName] = boto3.client(
                'ec2',
                aws_access_key_id=ref['key'],
                aws_secret_access_key=ref['secret']
            )

    def discover_instances(self):
        for account in self.AWSAccounts:
            self.clusters[account] = {}
            ref = self.clusters[account]
            clusterArns = self.ecs[account].list_clusters()['clusterArns']
            for c in self.ecs[account].describe_clusters(
                    clusters=clusterArns)['clusters']:
                ref[c['clusterArn']] = {
                    'name': c['clusterName'],
                    'instances': {}
                }

                instArns = self.ecs[account].list_container_instances(
                    cluster=c['clusterArn']
                )['containerInstanceArns']

                instDetails = self.ecs[account].describe_container_instances(
                    cluster=c['clusterArn'],
                    containerInstances=instArns
                )

                instances = {}
                for i in instDetails['containerInstances']:
                    instances[i['ec2InstanceId']] = {
                        'ec2InstanceId': i['ec2InstanceId'],
                        'containerInstanceArn': i['containerInstanceArn']
                    }

                ec2InstDetails = self.ec2[account].describe_instances(
                    InstanceIds=list(instances.keys())
                )

                for r in ec2InstDetails['Reservations']:
                    for i in r['Instances']:
                        groups = [t['Value'] for t in i['Tags']
                                  if t['Key'] in self.groupTags]
                        groups.append(c['clusterName'])
                        ref[c['clusterArn']]['instances'][i['InstanceId']] = {
                            'PrivateDnsName': i['PrivateDnsName'],
                            'PrivateIpAddress': i['PrivateIpAddress'],
                            'PublicDnsName': i['PublicDnsName'],
                            'PublicIpAddress': i['PublicIpAddress'],
                            'Groups': groups
                        }

        return self.clusters
