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
import uuid
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
            - Provide an empty string for dealing with resources not bound to any group.
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
        default: 20
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
    from msrestazure.azure_configuration import AzureConfiguration
    from msrestazure.polling.arm_polling import ARMPolling
    from msrest.service_client import ServiceClient
    from msrest.pipeline import ClientRawResponse
    from msrest.polling import LROPoller
    from msrestazure.tools import resource_id, is_valid_resource_id

except ImportError:
    # This is handled in azure_rm_common
    pass

try:
    from ansible.module_utils.ansible_release import __version__ as ANSIBLE_VERSION
except Exception:
    ANSIBLE_VERSION = 'unknown'
ANSIBLE_USER_AGENT = 'Ansible/{0}'.format(ANSIBLE_VERSION)

class GenericRestClientConfiguration(AzureConfiguration):
    def __init__(self, credentials, subscription_id, base_url=None):
        if credentials is None:
            raise ValueError("Parameter 'credentials' must not be None.")
        if subscription_id is None:
            raise ValueError("Parameter 'subscription_id' must not be None.")
        if not base_url:
            base_url = 'https://management.azure.com'

        super(GenericRestClientConfiguration, self).__init__(base_url)
        self.add_user_agent(ANSIBLE_USER_AGENT)
        self.credentials = credentials
        self.subscription_id = subscription_id

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
            polling_timeout=dict(type='int', default=600),
            polling_interval=dict(type='int', default=20),
            state=dict(type='str', default='present', choices=['present', 'absent', 'check', 'special-post']),
        )
        # store the results of the module operation
        self.results = dict(
            changed=False,
            response=None
        )
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

    def query(self, comment, url, method, body, api_version, not_found_is_ok=False):
        # comment: to print in the trace logs to show which execution step is going on
        # url: REST url of an Azure API
        # method: GET, POST, PUT, DELETE
        # body: of the request in json format
        # api_version -> query_parameters
        #
        # from self members: polling_timeout, polling_interval, force_async
        #
        # return azure xref:requests.Response, possibly enriched with
        #   async_url: if force_async

        # Construct and send request
        query_parameters = {}
        query_parameters['api-version'] = api_version
        header_parameters = {}
        header_parameters['Content-Type'] = 'application/json; charset=utf-8'
        header_parameters['x-ms-client-request-id'] = str(uuid.uuid1())

        self.logger.info(f"*** {comment} *** url:")
        self.logger.info(f"{url}")
        self.logger.info(f"query_parameters: {query_parameters}")
        request = None
        if method == 'GET':
            request = self._client.get(url, query_parameters)
        elif method == 'PUT':
            request = self._client.put(url, query_parameters)
        elif method == 'POST':
            request = self._client.post(url, query_parameters)
        elif method == 'HEAD':
            request = self._client.head(url, query_parameters)
        elif method == 'PATCH':
            request = self._client.patch(url, query_parameters)
        elif method == 'DELETE':
            request = self._client.delete(url, query_parameters)
        elif method == 'MERGE':
            request = self._client.merge(url, query_parameters)

        self.logger.info(f"request: {request}")
        response = self._client.send(request, header_parameters, body)
        self.logger.info(f"response.status_code: {response.status_code}")
        for hname, hvalue in response.headers.items():
            self.logger.info(f"response header {hname}: {hvalue}")

        operation_url = response.headers.get('Azure-AsyncOperation')
        if not operation_url and response.status_code == 202:
            # Some azure APIs return 202 Accepted with Location header containing the async operations
            # url and Retry-After header instead of their usual Azure-AsyncOperation header
            operation_url = response.headers.get('Location')
        if response.status_code == 200 and len(response.text) > 0 and method == 'GET':
            # Some azure API return 200 and set Azure-AsyncOperation to some value,
            # but return the result immediately
            # For example: providers/Microsoft.StreamAnalytics/streamingjobs
            # Workaround for that case - ignore the Azure-AsyncOperation, use the direct result
            operation_url = None
        if operation_url: # if Azure tells, which operations url to poll
            # example: https://management.azure.com/subscriptions/11.......-....-......./providers \
            # .../Microsoft.ContainerService/locations/westeurope/operations/....-....?api-version=2017-08-31
            def async_url(self):
                return operation_url
            response.async_url = async_url.__get__(response)
            self.logger.debug(f"Enriched the response with async_url {operation_url}")
            if self.force_async:
                self.logger.debug(f"type(response): {type(response)}")
            else: # poll until operation completed
                self.logger.info("Got response with headers for an async operation, will initiate long polling")
                def get_long_running_output(response):
                    return response
                self.logger.debug(f"response.request.method of the original API call was: {response.request.method}")
                poller = LROPoller(self._client, response, get_long_running_output, ARMPolling(self.polling_interval))
                try:
                    poller.wait(timeout=self.polling_timeout)
                    polling_response = poller.result()
                    if polling_response: # if polling provides a new resources state - use it, otherwise...
                        response = polling_response
                # ...otherwise keep the original response, e.g. from DELETE with 202 Accepted result
                # and just log a warning
                except CloudError as cloud_error:
                    err = cloud_error
                    self.logger.warning("***** poller.wait failed, CloudError:")
                    self.logger.warning(err)
                    self.logger.warning("Will return the original response (before polling)")
                    self.logger.debug("***** enrich the response with more details")
                    def api_error(self):
                        return str(err.error)
                    def error_response(self):
                        return err.response
                    response.api_error = api_error.__get__(response)
                    response.error_response = error_response.__get__(response)
                    self.logger.debug(f"response after polling: {response}")
                except Exception as exc:
                    self.logger.warning("***** poller.wait failed (other exception):")
                    self.logger.warning(type(exc))
                    self.logger.warning(dir(exc))
                    self.logger.warning(exc)
                    self.logger.warning("Will return the original response (before polling)")
                    self.logger.debug("***** enrich the response with more details")
                    def api_error(self):
                        return str(exc)
                    response.api_error = api_error.__get__(response)
                    self.logger.debug(f"response after polling: {response}")

        self.logger.debug("\n")
        return response

    def autodetect_api_version(self, url):
        """if api_version was not specified, get latest one for the resource specified in the url"""
        try:
            # extract provider and resource type
            if "/providers/" in url:
                provider = url.split("/providers/")[1].split("/")[0]
                resourceType = url.split(provider + "/")[1].split("/")[0]
                providers_url = "/subscriptions/" + self.subscription_id + "/providers/" + provider
                resource_type_res = self.query("List resourceTypes, apiVersions", providers_url, "GET", None, '2015-01-01').text
                resource_types = json.loads(resource_type_res)
                for rt in resource_types['resourceTypes']:
                    if rt['resourceType'].lower() == resourceType.lower():
                        detected = next(v for v in rt['apiVersions'] if 'preview' not in v)
                        self.logger.info(f"Detected '{detected}' api_version for {provider}/{resourceType} resource")
                        return detected
                self.fail(f"Couldn't find api version for {provider}/{resourceType}")
            else:
                # if there's no provider in API version, assume Microsoft.Resources
                return '2018-05-01'
        except Exception as exc:
            self.fail("Failed to obtain API version: {0}".format(str(exc)))

    def exec_module(self, **kwargs):
        self.logger.debug("------------------------------------------ exec_module start --------------------------------------------")
        for key in self.module_arg_spec:
            setattr(self, key, kwargs[key])
        if self.definition is None and self.state == 'present':
            self.fail("'definition' parameter is required if state=='present'")

        base_url = self.azure_auth._cloud_environment.endpoints.resource_manager
        self.config = GenericRestClientConfiguration(self.azure_auth.azure_credentials, self.azure_auth.subscription_id, base_url)
        self._client = ServiceClient(self.config.credentials, self.config)

        if self.path.startswith('https:'): # the caller already provided an absolute path
            url = self.path
        else:
            if self.group: # the usual case: separate resource group and path provided, subscription_id autodetected
                url = f"/subscriptions/{self.subscription_id}/resourceGroups/{self.group}{self.path}"
            else: # resource not bound to any resource group
                url = f"/subscriptions/{self.subscription_id}{self.path}"

        if not self.api_version:
            self.api_version = self.autodetect_api_version(url)
        needs_update = True
        response = None

        if self.state == 'special-post':
            query_res = self.query("special-post POST", url, "POST", self.definition, self.api_version)
            changed = not self.definition is None # assuming a POST will change something unless with empty body
            return self.handle_async_and_json_res(changed, query_res)

        if self.state == 'check' or self.check_mode :
            original = self.query("Check state/mode - just GET", url, "GET", None, self.api_version, not_found_is_ok=True)
            if original.status_code == 200:
                self.results['response'] = json.loads(original.text)
            return self.results

        if not self.force_update:
            original = self.query("Get the original resource state", url, "GET", None, self.api_version, not_found_is_ok=True)

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

        if needs_update:
            method = 'DELETE' if self.state == 'absent' else 'PUT'
            query_res = self.query("Change the resource", url, method, self.definition, self.api_version)
            return self.handle_async_and_json_res(True, query_res)
        else: # just GET
            self.results['response'] = response
            self.results['changed'] = False
            return self.results

    def parsed_response(self, query_result):
        """Given an azure requests.Response, return the parsed data as structured and readably as possible"""
        if len(query_result.text) > 0:
            try:
                return json.loads(query_result.text)
            except Exception:
                return query_result.text
        else:
            return None

    def handle_async_and_json_res(self, changed, query_result):
        """After a POST, DELETE, PUT check and parse the REST API call json result
        and fill this ansible module's results dict.
        """
        self.logger.debug(f"query_result: {query_result}")
        if hasattr(query_result, "async_url"):
            self.results['async_url'] = query_result.async_url()
        if hasattr(query_result, "api_error"): # nested, async error from long polling
            self.logger.debug("Detected nested, async error from long polling")
            self.logger.debug(f"api_error: {query_result.api_error()}")
            if ('ResourceNotFound' in query_result.api_error()) and (query_result.request.method.upper() == 'DELETE'):
                self.logger.debug(f"Handle 404 bug in azure DELETE with long polling")
                self.results['failed'] = False
            else:
                self.results['failed'] = True
            self.results['api_error'] = query_result.api_error()
            if hasattr(query_result, "error_response"):
                self.results['error_response'] = self.parsed_response(query_result.error_response())
                self.results['error_status_code'] = query_result.error_response().status_code
        elif query_result.status_code not in [200, 201, 202, 204, 400, 404, 409]:
            self.results['failed'] = True
            self.results['x-ms-request-id'] = query_result.headers.get('x-ms-request-id')
        elif query_result.status_code in [400, 404, 409]:
            self.results['failed'] = True
        self.results['status_code'] = query_result.status_code
        self.results['response'] = self.parsed_response(query_result)
        self.results['changed'] = changed
        return self.results

def main():
    AzureRMResource()


if __name__ == '__main__':
    main()
