#!/usr/bin/python
#
# Copyright (c) 2021 Vladimir Dobriakov, <vladimir@infrastructure-as-code.de>
# Based on work / inspired by:
# Copyright (c) 2018 Zim Kalinowski, <zikalino@microsoft.com>
#
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

from copy import deepcopy
import json
import yaml
import difflib

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
            - Specific API version to be used. By default the latest non-preview version is used.
            - You can find all the API versions available for a particular resource type with e.g.:
            - az provider show --namespace Microsoft.ServiceBus --query "resourceTypes[?resourceType=='namespaces'].apiVersions"
            - Though the parameter is optional, you can make the execution faster (save one API call)
            - and more reliable (prepare for future Azure API changes),
            - if you find out the value in advance and set it explicitly.
    group:
        description:
            - Name of the Azure resource group to be used.
        required: true
    path:
        description:
            - Part of the Azure RM resource url, as printed by `az resource show` command,
            - but without the subscription_id part (will be detected automatically)
            - and without resourceGroup part (please provide via separate `group` parameter).
            - Another possibility: absolute url starting with `https:`
        required: true
    definition:
        description:
            - Required, if state: present.
            - Azure resource definition as `az resource show -o yaml` would print it.
            - This allows for an easy development cycle: create a resource interactively
            - or with a some `az` command. Then print the resource definition with
            - `az resource show`, remove properties like `createdAt`, `provisioningState`,
            - add some templating if needed. Done.
    force_update:
        description:
            - By default an existing resource will be checked using I(method=GET) first and compared with I(definition).
            - If all parameters match, an update will be skipped for performance.
            - By setting this parameter to 'yes' you can force executing I(method=PUT).
        default: no
        type: bool
    force_async:
        description:
            - By default this module will wait until Azure resource update or create is completely finished.
            - You can change this behavior to implement some parallel resource creation,
            - beware of race conditions though!
        default: no
        type: bool
    details:
        description:
            - Show more verbose information when processing resources.
            - Level 'info' - show diff of the current vs. proposed merged resource definition.
            - Level 'debug' - show more intermediate resource definition processing results.
        default: nothing
        choices:
            - nothing
            - info
            - debug
    polling_timeout:
        description:
            - How long to wait until the resource is updated/created. Default: forever.
        default: 0
        type: int
    polling_interval:
        description:
            - How often to check if the resource is updated/created. In seconds.
        default: 10
        type: int
    state:
        description:
            - Assert the state of the resource. Use C(present) to create or update resource or C(absent) to delete resource.
            - There is special mode to use I(method=POST) for some special operations like acquire authorization keys for
            - a service bus topic (requires POST to a special url).
        default: present
        choices:
            - absent
            - present
            - check
            - special-post

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


    - name: Get the service bus connection strings
      geekq.azbare.resource:
        api_version: '2017-04-01'
        group: experimental-applicationdevelopment
        path: /providers/Microsoft.ServiceBus/namespaces/bus1/topics/mytopic/authorizationRules/mysubscriber/ListKeys
        state: special-post
      register: bus_access # will return connection strings and secret keys

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
from ansible.module_utils.common.dict_transformations import dict_merge

try:
    from msrestazure.azure_exceptions import CloudError
    from msrest.service_client import ServiceClient
    from msrest.pipeline import ClientRawResponse
    from msrest.polling import LROPoller
    from msrestazure.tools import resource_id, is_valid_resource_id

except ImportError:
    # This is handled in azure_rm_common
    pass

def diff_dict_lists(a, b):
    """Return difference between two dicts of lists of dicts of dicts of list
    in a text diff format. Usable for e.g. debugging."""
    return '\n'.join(difflib.unified_diff(
        yaml.dump(a).splitlines(),
        yaml.dump(b).splitlines()))

def dict_list_merge(a, b):
    """Recursively merges dicts of lists of dicts of dicts of lists.
    Returns a new merged structure.
    keys in dicts of b overwrite the values in a.
    Lists are matched by index, s. doctest examples below.

    Test merging lists inside dict. Here we have a list of AKS agentPoolProfils,
    updating a single attribute (minCount) of a list item.
    >>> existing_resource = yaml.load('''
    ... identity:
    ...   type: SystemAssigned
    ... location: westeurope
    ... properties:
    ...   agentPoolProfiles:
    ...   - count: 3
    ...     enableAutoScaling: true
    ...     minCount: 3
    ...    ''', Loader=yaml.SafeLoader)
    >>> new_definition = yaml.load('''
    ... location: westeurope
    ... properties:
    ...   agentPoolProfiles:
    ...   - count: 3
    ...     enableAutoScaling: true
    ...     minCount: 5
    ...    ''', Loader=yaml.SafeLoader)
    >>> merged = dict_list_merge(existing_resource, new_definition)
    >>> merged['properties']['agentPoolProfiles'][0]['minCount']
    5
    >>> print(diff_dict_lists(existing_resource, merged))
    ---...
    -    minCount: 3
    +    minCount: 5...
    """
    if isinstance(b, dict):
        result = deepcopy(a)
        for k, v in b.items():
            if k in result and (isinstance(result[k], dict) or isinstance(result[k], list)):
                result[k] = dict_list_merge(result[k], v)
            else:
                result[k] = deepcopy(v)
        return result
    elif isinstance(b, list):
        merged = deepcopy(a)
        # merge the first elements of both lists
        for i in range(len(merged)):
            if i < len(b): # element with index is present in both lists
                merged[i] = dict_list_merge(merged[i], b[i])
        # append further elements from b list, if b is longer
        return merged + b[len(merged):]
    else:
        return b


class AzureRMResource(AzureRMModuleBase):
    def __init__(self):
        # define user inputs into argument
        self.module_arg_spec = dict(
            api_version=dict(type='str'),
            path=dict(type='str', required=True),
            group=dict(type='str', required=True),
            definition=dict(type='raw'),
            details=dict(type='str', default='nothing', choices=['nothing', 'info', 'debug']),
            force_update=dict(type='bool', default=False),
            force_async=dict(type='bool', default=False),
            polling_timeout=dict(type='int', default=0),
            polling_interval=dict(type='int', default=10),
            state=dict(type='str', default='present', choices=['present', 'absent', 'check', 'special-post']),
        )
        # store the results of the module operation
        self.results = dict(
            changed=False,
            response=None
        )
        self.mgmt_client = None
        self.path = None
        self.api_version = None
        self.group = None
        self.definition = None
        self.details = None
        self.force_update = False
        self.force_async = False
        self.polling_timeout = None
        self.polling_interval = None
        self.state = None
        super(AzureRMResource, self).__init__(self.module_arg_spec, supports_check_mode=True)

    def exec_module(self, **kwargs):
        self.logger.debug("------------------------------------------ exec_module start --------------------------------------------")
        for key in self.module_arg_spec:
            setattr(self, key, kwargs[key])
        if self.definition is None and self.state == 'present':
            self.fail("'definition' parameter is required if state=='present'")

        self.mgmt_client = self.get_mgmt_svc_client()
        if self.path.startswith('https:'):
            url = self.path
        else:
            url = f"/subscriptions/{self.subscription_id}/resourceGroups/{self.group}{self.path}"
        self.logger.debug(url)

        # if api_version was not specified, get latest one
        if not self.api_version:
            try:
                # extract provider and resource type
                if "/providers/" in url:
                    provider = url.split("/providers/")[1].split("/")[0]
                    resourceType = url.split(provider + "/")[1].split("/")[0]
                    providers_url = "/subscriptions/" + self.subscription_id + "/providers/" + provider
                    api_versions = json.loads(self.mgmt_client.query(providers_url, "GET", {'api-version': '2015-01-01'}, None, None, [200], 0, 0).text)
                    for rt in api_versions['resourceTypes']:
                        if rt['resourceType'].lower() == resourceType.lower():
                            self.api_version = next(v for v in rt['apiVersions'] if 'preview' not in v)
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
        self.logger.debug("query parameters prepared")
        self.logger.debug(f"self.state: {self.state}")

        if self.state == 'special-post':
            res = self.mgmt_client.query(url, "POST", query_parameters, header_parameters, self.definition, [200, 202], 0, 0, force_async=self.force_async)

            self.results['response'] = json.loads(res.text)
            self.results['changed'] = not self.definition is None # assuming a POST will change something unless with empty body
            return self.results

        self.logger.debug("before checking self.check_mode")
        if self.state == 'check' or self.check_mode :
            self.logger.debug("before the first GET")
            original = self.mgmt_client.query(url, "GET", query_parameters, None, None, [200, 404], 0, 0)
            if original.status_code == 200:
                self.results['response'] = json.loads(original.text)
            return self.results

        if not self.force_update:
            self.logger.debug("before getting original resource state")
            original = self.mgmt_client.query(url, "GET", query_parameters, None, None, [200, 404], 0, 0)

            if original.status_code == 404:
                if self.state == 'absent':
                    needs_update = False
            else:
                response = json.loads(original.text)
                merged = dict_list_merge(response, self.definition)
                needs_update = (merged != response)
                if self.details in ['debug']:
                    self.results['previous_definition'] = response
                    self.results['diff-from-def'] = diff_dict_lists(self.definition, response)
                if self.details in ['info', 'debug']:
                    self.results['needs_update'] = needs_update
                    self.results['diff-merged'] = diff_dict_lists(response, merged)

        self.logger.debug("before if needs_update")
        if needs_update:
            method = 'PUT'
            status_code = [200, 201, 202, 400, 409]
            if self.state == 'absent':
                method = 'DELETE'
                status_code.append(204)

            updated = self.mgmt_client.query(url, method, query_parameters, header_parameters, self.definition,
                                              status_code, self.polling_timeout, self.polling_interval, force_async=self.force_async)
            if hasattr(updated, "async_url"):
                self.results['async_url'] = updated.async_url()
            if updated.status_code in [400, 409]:
                self.results['status_code'] = updated.status_code
                self.results['failed'] = True
            if self.state == 'present':
                try:
                    response = json.loads(updated.text)
                except Exception:
                    response = updated.text
            else:
                response = None

        self.results['response'] = response
        self.results['changed'] = needs_update

        return self.results

def query2(url, method, api_version, not_found_is_ok=False):
    pass
    # TODO: move the implementation from azure_rm_common_rest.py
    # method: GET, POST, PUT, DELETE
    # api_version -> query_parameters
    # header_parameters <- content: json
    # expected_status_codes: 200, 201, 202 are always ok
    # 204 is ok if we do not expect any data (e.g. for DELETE)
    # 404 is sometimes ok for GET if state: absent desired
    # from self. global vars: polling_timeout, polling_interval, force_async
    #
    # return query result dict:
    #   response: azure xref:requests.Response
    #   async_url: if force_async

# api_versions = json.loads(self.mgmt_client.query(providers_url, "GET", {'api-version': '2015-01-01'}, None, None, [200], 0, 0).text)
# res = self.mgmt_client.query(url, "POST", query_parameters, header_parameters, self.definition, [200, 202], 0, 0, force_async=self.force_async)
# original = self.mgmt_client.query(url, "GET", query_parameters, None, None, [200, 404], 0, 0)
# original = self.mgmt_client.query(url, "GET", query_parameters, None, None, [200, 404], 0, 0)
# updated = self.mgmt_client.query(url, method, query_parameters, header_parameters, self.definition,
#                                   status_code, self.polling_timeout, self.polling_interval, force_async=self.force_async)

def main():
    AzureRMResource()


if __name__ == '__main__':
    main()
