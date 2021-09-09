#!/usr/bin/python
#
# Copyright (c) 2018 Zim Kalinowski, <zikalino@microsoft.com>
#
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = '''
---
module: resource
version_added: "1.0.0"
short_description: Create any Azure resource
description:
    - Create, update or delete any Azure resource using Azure REST API.
    - Refer to U(https://docs.microsoft.com/en-us/rest/api/) regarding details related to specific resource REST API.

options:
    api_version:
        description:
            - Specific API version to be used. By default the latest version is used.
            - You can find all the API versions available for a particular resource type with e.g.:
            - az provider show --namespace Microsoft.ServiceBus --query "resourceTypes[?resourceType=='namespaces'].apiVersions"
    group:
        description:
            - Resource group to be used.
    path:
        description:
            - Part of the Azure RM Resource url, as printed by `az resource show` command,
            - but without the subscription_id part (will be detected automatically)
            - and without resourceGroup part (please provide via separate `group` parameter.
    definition:
        description:
            - Azure resource definition as `az resource show -o yaml` would print it.
            - This allows for an easy development cycle: create a resource interactively
            - or with a some `az` command. Then print the resource definition with
            - `az resource show`, remove properties like `createdAt`, `provisioningState`,
            - add some templating if needed. Done.

    provider:
        description:
            - Provider type.
            - Required if URL is not specified.
    resource_type:
        description:
            - Resource type.
            - Required if URL is not specified.
    resource_name:
        description:
            - Resource name.
            - Required if URL Is not specified.
    subresource:
        description:
            - List of subresources.
        suboptions:
            namespace:
                description:
                    - Subresource namespace.
            type:
                description:
                    - Subresource type.
            name:
                description:
                    - Subresource name.
    method:
        description:
            - The HTTP method of the request or response. It must be uppercase.
        choices:
            - GET
            - PUT
            - POST
            - HEAD
            - PATCH
            - DELETE
            - MERGE
        default: "PUT"
    status_code:
        description:
            - A valid, numeric, HTTP status code that signifies success of the request. Can also be comma separated list of status codes.
        type: list
        default: [ 200, 201, 202 ]
    force_update:
        description:
            - By default an existing resource will be checked using I(method=GET) first and compared with I(definition).
            - If all parameters match, an update will be skipped for performance.
            - By setting this parameter to 'yes' you can force executing I(method=PUT).
        default: no
        type: bool
    polling_timeout:
        description:
            - If enabled, idempotency check will be done by using I(method=GET) first and then comparing with I(definition).
        default: 0
        type: int
    polling_interval:
        description:
            - If enabled, idempotency check will be done by using I(method=GET) first and then comparing with I(definition).
        default: 60
        type: int
    state:
        description:
            - Assert the state of the resource. Use C(present) to create or update resource or C(absent) to delete resource.
        default: present
        choices:
            - absent
            - present

# extends_documentation_fragment:
#    - azure.azcollection.azure

author:
    - Vladimir Dobriakov (@geekq)
    - Zim Kalinowski (@zikalino)

'''

EXAMPLES = '''
    - name: Define a service bus namespace
      geekq.azbare.resource:
        api_version: '2017-04-01'
        group: experimental-applicationdevelopment
        path: /providers/Microsoft.ServiceBus/namespaces/bus1
        definition:
          location: West Europe
          sku:
            name: Premium
            tier: Premium
          tags:
            env: myenv

    - name: Define message queue topic
      geekq.azbare.resource:
        api_version: '2017-04-01'
        group: experimental-applicationdevelopment
        path: /providers/Microsoft.ServiceBus/namespaces/bus1/topics/transfers
        definition:
          location: West Europe
          properties:
            maxSizeInMegabytes: 5120
'''

RETURN = '''
response:
    description:
        - Response specific to resource type with the same structure you would get with
        - `az resource show -o yaml --ids /subscriptions/xxxx...xxxx/resourceGroups/experimental-applicationdevelopment/providers/Microsoft.ServiceBus/namespaces/bus1`
    returned: always
    type: complex
    contains:
        id:
            description:
                - Resource ID.
            type: str
            returned: always
            sample: "/subscriptions/xxxx...xxxx/resourceGroups/experimental-applicationdevelopment/providers/Microsoft.ServiceBus/namespaces/bus1"
        location:
            description:
                - The resource location, defaults to location of the resource group.
            type: str
            returned: always
            sample: eastus
        name:
            description:
                The resource name.
            type: str
            returned: always
            sample: bus1
        type:
            description:
                - The resource type.
            type: str
            returned: always
            sample: "Microsoft.ServiceBus/Namespaces"
        properties:
            description:
                - The resource specific properties
            type: dict
            returned: always
            sample:
                {
                    "provisioningState": "Succeeded",
                    "metricId": "xxxxxxx-xxxx-...:foobar",
                    "createdAt": "2021-09-06T10:44:58.823Z",
                    "updatedAt": "2021-09-08T13:47:26.56Z",
                    "serviceBusEndpoint": "https://bus1-example.servicebus.windows.net:443/",
                    "status": "Active"
                  }
        tags:
            description:
                - Resource tags.
            type: dict
            returned: always
            sample: { 'env': 'myenv' }

'''

from ansible_collections.geekq.azbare.plugins.module_utils.azure_rm_common import AzureRMModuleBase
from ansible_collections.geekq.azbare.plugins.module_utils.azure_rm_common_rest import GenericRestClient
from ansible.module_utils.common.dict_transformations import dict_merge

try:
    from msrestazure.azure_exceptions import CloudError
    from msrest.service_client import ServiceClient
    from msrestazure.tools import resource_id, is_valid_resource_id
    import json

except ImportError:
    # This is handled in azure_rm_common
    pass


class AzureRMResource(AzureRMModuleBase):
    def __init__(self):
        # define user inputs into argument
        self.module_arg_spec = dict(
            path=dict(
                type='str'
            ),
            provider=dict(
                type='str',
            ),
            group=dict(
                type='str',
            ),
            resource_type=dict(
                type='str',
            ),
            resource_name=dict(
                type='str',
            ),
            subresource=dict(
                type='list',
                default=[]
            ),
            api_version=dict(
                type='str'
            ),
            method=dict(
                type='str',
                default='PUT',
                choices=["GET", "PUT", "POST", "HEAD", "PATCH", "DELETE", "MERGE"]
            ),
            definition=dict(
                type='raw'
            ),
            status_code=dict(
                type='list',
                default=[200, 201, 202]
            ),
            force_update=dict(
                type='bool',
                default=False
            ),
            polling_timeout=dict(
                type='int',
                default=0
            ),
            polling_interval=dict(
                type='int',
                default=60
            ),
            state=dict(
                type='str',
                default='present',
                choices=['present', 'absent']
            )
        )
        # store the results of the module operation
        self.results = dict(
            changed=False,
            response=None
        )
        self.mgmt_client = None
        self.path = None
        self.api_version = None
        self.provider = None
        self.group = None
        self.resource_type = None
        self.resource_name = None
        self.subresource_type = None
        self.subresource_name = None
        self.subresource = []
        self.method = None
        self.status_code = []
        self.force_update = False
        self.polling_timeout = None
        self.polling_interval = None
        self.state = None
        self.definition = None
        super(AzureRMResource, self).__init__(self.module_arg_spec, supports_tags=False)

    def exec_module(self, **kwargs):
        for key in self.module_arg_spec:
            setattr(self, key, kwargs[key])
        self.mgmt_client = self.get_mgmt_svc_client(GenericRestClient,
                                                    base_url=self._cloud_environment.endpoints.resource_manager)

        if self.state == 'absent':
            self.method = 'DELETE'
            self.status_code.append(204)

        self.url = f"/subscriptions/{self.subscription_id}/resourceGroups/{self.group}{self.path}"
        if self.url is None:
            orphan = None
            rargs = dict()
            rargs['subscription'] = self.subscription_id
            rargs['resource_group'] = self.definition.pop('resourceGroup')
            rargs['name'] = self.definition['name']
            if self.definition['type']:
                (rargs['namespace'], rargs['type']) = self.definition['type'].split('/', 1) # from e.g. `type: Microsoft.ServiceBus/Namespaces`
                self.url = resource_id(**rargs)
            else: # legacy - TODO check if we can remove it
                if not (self.provider is None or self.provider.lower().startswith('.microsoft')):
                    rargs['namespace'] = "Microsoft." + self.provider
                else:
                    rargs['namespace'] = self.provider

                if self.resource_type is not None and self.resource_name is not None:
                    rargs['type'] = self.resource_type
                    rargs['name'] = self.resource_name
                    for i in range(len(self.subresource)):
                        resource_ns = self.subresource[i].get('namespace', None)
                        resource_type = self.subresource[i].get('type', None)
                        resource_name = self.subresource[i].get('name', None)
                        if resource_type is not None and resource_name is not None:
                            rargs['child_namespace_' + str(i + 1)] = resource_ns
                            rargs['child_type_' + str(i + 1)] = resource_type
                            rargs['child_name_' + str(i + 1)] = resource_name
                        else:
                            orphan = resource_type
                else:
                    orphan = self.resource_type

                self.url = resource_id(**rargs)

            if orphan is not None:
                self.url += '/' + orphan

        # if api_version was not specified, get latest one
        if not self.api_version:
            try:
                # extract provider and resource type
                if "/providers/" in self.url:
                    provider = self.url.split("/providers/")[1].split("/")[0]
                    resourceType = self.url.split(provider + "/")[1].split("/")[0]
                    url = "/subscriptions/" + self.subscription_id + "/providers/" + provider
                    api_versions = json.loads(self.mgmt_client.query(url, "GET", {'api-version': '2015-01-01'}, None, None, [200], 0, 0).text)
                    for rt in api_versions['resourceTypes']:
                        if rt['resourceType'].lower() == resourceType.lower():
                            self.api_version = rt['apiVersions'][0]
                            break
                else:
                    # if there's no provider in API version, assume Microsoft.Resources
                    self.api_version = '2018-05-01'
                if not self.api_version:
                    self.fail("Couldn't find api version for {0}/{1}".format(provider, resourceType))
            except Exception as exc:
                self.fail("Failed to obtain API version: {0}".format(str(exc)))

        query_parameters = {}
        query_parameters['api-version'] = self.api_version

        header_parameters = {}
        header_parameters['Content-Type'] = 'application/json; charset=utf-8'

        needs_update = True
        response = None

        if not self.force_update:
            original = self.mgmt_client.query(self.url, "GET", query_parameters, None, None, [200, 404], 0, 0)

            if original.status_code == 404:
                if self.state == 'absent':
                    needs_update = False
            else:
                try:
                    response = json.loads(original.text)
                    # self.results['previous_definition'] = response # for debugging the `force_update: false` optimization
                    needs_update = (dict_merge(response, self.definition) != response)
                    # self.results['needs_update'] = needs_update # for debugging the `force_update: false` optimization
                except Exception:
                    pass

        if needs_update:
            response = self.mgmt_client.query(self.url,
                                              self.method,
                                              query_parameters,
                                              header_parameters,
                                              self.definition,
                                              self.status_code,
                                              self.polling_timeout,
                                              self.polling_interval)
            if self.state == 'present':
                try:
                    response = json.loads(response.text)
                except Exception:
                    response = response.text
            else:
                response = None

        self.results['response'] = response
        self.results['changed'] = needs_update

        return self.results


def main():
    AzureRMResource()


if __name__ == '__main__':
    main()
