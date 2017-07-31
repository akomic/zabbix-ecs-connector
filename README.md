# Zabbix-ECS-Connector

Zabbix AWS ECS Connector.
- Discovers ECS instances
- Creates groups (ECS is the default one. It's also creating groups from EC2 instance tags specified in config.json)
- adds/removes hosts to Zabbix
- attaches "Template OS Linux ECS Instance" template to each instance when adding.

## Install

The latest version [is available on PyPI](https://pypi.python.org/pypi/zabbix-ecs-connector).

With `pip`:

    pip3 install zabbix-ecs-connector


## Usage
Copy config.json.example to config.json and edit it.

```shell
zabbixECSConnectord
```
