# --------------------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# --------------------------------------------------------------------------------------------

import os
import unittest
import time
import json

from azure_devtools.scenario_tests import AllowLargeResponse
from azure.cli.testsdk import (ScenarioTest, ResourceGroupPreparer, record_only)


TEST_DIR = os.path.abspath(os.path.join(os.path.abspath(__file__), '..'))


@record_only()
class CustomlocationsScenarioTest(ScenarioTest):
    @ResourceGroupPreparer(random_name_length=17, name_prefix='clitest', location='westus')
    def test_customlocation(self, resource_group, resource_group_location):
        self.kwargs.update({
            'name': self.create_random_name(prefix='customlocations-cli', length=24),
            'cassandraoperator': '/subscriptions/a5015e1c-867f-4533-8541-85cd470d0cfb/resourceGroups/e2e-testing-rg/providers/Microsoft.Kubernetes/connectedClusters/cle2edfkapconnectedcluster/providers/Microsoft.KubernetesConfiguration/extensions/cli-test-operator',
            'ansible_operator': '/subscriptions/a5015e1c-867f-4533-8541-85cd470d0cfb/resourceGroups/e2e-testing-rg/providers/Microsoft.Kubernetes/connectedClusters/cle2edfkapconnectedcluster/providers/Microsoft.KubernetesConfiguration/extensions/cli-test-operator-ansible',
            'namespace': 'cli-operator-namespace',
            'host_resource_id': '/subscriptions/a5015e1c-867f-4533-8541-85cd470d0cfb/resourceGroups/e2e-testing-rg/providers/Microsoft.Kubernetes/connectedClusters/cle2edfkapconnectedcluster',
            'loc': resource_group_location,
            'resource_group': resource_group,
            'clusterextids': '/subscriptions/a5015e1c-867f-4533-8541-85cd470d0cfb/resourceGroups/e2e-testing-rg/providers/Microsoft.Kubernetes/connectedClusters/cle2edfkapconnectedcluster/providers/Microsoft.KubernetesConfiguration/extensions/cli-test-operator-ansible\', \'/subscriptions/a5015e1c-867f-4533-8541-85cd470d0cfb/resourceGroups/e2e-testing-rg/providers/Microsoft.Kubernetes/connectedClusters/cle2edfkapconnectedcluster/providers/Microsoft.KubernetesConfiguration/extensions/cli-test-operator',
            'tagskey': 'testkey',
            'tagsvalue': 'testvalue',
            'SystemAssigned': 'SystemAssigned',
            'None': 'None'
        })

        # check if test resource group was successfully created
        self.cmd('az group show -n {resource_group}', checks=[
            self.check('name', '{resource_group}'),
            self.check('location', '{loc}'),
            self.check('properties.provisioningState', 'Succeeded')
        ])

        # Creating a customlocation
        self.cmd('customlocation create -g {resource_group} -n {name} -c {cassandraoperator} --namespace {namespace} --host-resource-id {host_resource_id} --location {loc} --tags {tagskey}={tagsvalue} --assign-identity {SystemAssigned}', checks=[
            self.check('name', '{name}'),
            self.check('provisioningState', 'Succeeded'),
            self.check('namespace', '{namespace}'),
            self.check('resourceGroup', '{resource_group}')
        ])

        # Get the custom location
        self.cmd('customlocation show -g {resource_group} -n {name} ', checks=[
            self.check('name', '{name}'),
            self.check('provisioningState', 'Succeeded'),
            self.check('namespace', '{namespace}'),
            self.check('resourceGroup', '{resource_group}'),
        ])

        # Update a customlocation
        self.cmd('customlocation update -g {resource_group} -n {name} -c {ansible_operator} --namespace {namespace} --host-resource-id {host_resource_id} --location {loc}  --assign-identity {None}', checks=[
            self.check('name', '{name}'),
            self.check('provisioningState', 'Succeeded'),
            self.check('namespace', '{namespace}'),
            self.check('resourceGroup', '{resource_group}'),
            self.check('clusterExtensionIds', "[\'{ansible_operator}\']"),
        ])

        # Get the custom location
        self.cmd('customlocation show -g {resource_group} -n {name} ', checks=[
            self.check('name', '{name}'),
            self.check('provisioningState', 'Succeeded'),
            self.check('namespace', '{namespace}'),
            self.check('resourceGroup', '{resource_group}'),
        ])

        # Update a customlocation
        self.cmd('customlocation patch -g {resource_group} -n {name} -c {cassandraoperator} --namespace {namespace} --host-resource-id {host_resource_id} --assign-identity {SystemAssigned}', checks=[
            self.check('name', '{name}'),
            self.check('provisioningState', 'Patching'),
            self.check('namespace', '{namespace}'),
            self.check('resourceGroup', '{resource_group}'),
            self.check('clusterExtensionIds', "[\'{clusterextids}\']"),
        ])

        # Get the custom location
        self.cmd('customlocation show -g {resource_group} -n {name} ', checks=[
            self.check('name', '{name}'),
            self.check('provisioningState', 'Patching'),
            self.check('namespace', '{namespace}'),
            self.check('resourceGroup', '{resource_group}'),
            self.check('clusterExtensionIds', "[\'{clusterextids}\']"),
        ])

        # enabled resource types
        ert_output = self.cmd(
            'customlocation list-enabled-resource-types -g {resource_group} -n {name}').get_output_in_json()
        ert = ert_output[0]
        self.assertTrue(ert["type"], 'Microsoft.ExtendedLocation/customLocations/enabledResourceTypes')

        # list by subscription
        count = len(self.cmd('customlocation list').get_output_in_json())
        assert count > 0

        # list by resource-group
        final_count = len(
            self.cmd('customlocation list -g {resource_group}').get_output_in_json())
        self.assertTrue(final_count, 1)

        # Delete the CustomLoation created above
        self.cmd(
            'customlocation delete -g {resource_group} -n {name} -y', checks=[])

        # Attest that CustomLocation has been deleted from the resource group
        post_delete_count = len(self.cmd('customlocation list -g {resource_group}').get_output_in_json())
        self.assertEquals(post_delete_count, 0)
