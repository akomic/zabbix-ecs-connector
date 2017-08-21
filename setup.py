#!/usr/bin/env python

from setuptools import setup

setup(
    # Application name:
    name="zabbix-ecs-connector",

    # Version number (initial):
    version="0.0.2",

    # Application author details:
    author="Alen Komic",
    author_email="akomic@gmail.com",

    # Packages
    packages=["ZabbixECSConnector"],

    # Scripts
    scripts=['zabbixECSConnectord'],

    # Include additional files into the package
    include_package_data=True,

    # Details
    url="https://github.com/akomic/zabbix-ecs-connector",

    description='Implementation of Zabbix AWS ECS connector',
    long_description=(
        'This module implements'
        ' AWS ECS connector.\n'
    ),

    keywords=['monitoring', 'zabbix', 'AWS', 'ECS'],

    # Dependent packages (distributions)
    install_requires=['boto3==1.4.4', 'pyzabbix==0.7.4',],
)
