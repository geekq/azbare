# Copyright (c) 2018 Zim Kalinowski, <zikalino@microsoft.com>
#
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
import logging
from pprint import pformat
__metaclass__ = type


try:
    from ansible.module_utils.ansible_release import __version__ as ANSIBLE_VERSION
except Exception:
    ANSIBLE_VERSION = 'unknown'

try:
    from msrestazure.azure_exceptions import CloudError
    from msrestazure.azure_configuration import AzureConfiguration
    from msrest.service_client import ServiceClient
    from msrest.pipeline import ClientRawResponse
    from msrest.polling import LROPoller
    from msrestazure.polling.arm_polling import ARMPolling
    import uuid
    import json
except ImportError:
    # This is handled in azure_rm_common
    AzureConfiguration = object

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


class GenericRestClient(object):

    def __init__(self, credentials, subscription_id, base_url=None):
        self.logger = logging.getLogger('azbare.rest')
        self.config = GenericRestClientConfiguration(credentials, subscription_id, base_url)
        self._client = ServiceClient(self.config.credentials, self.config)
        self.models = None
        # TODO move to resource.py __init__

    def query(self, url, method, query_parameters, header_parameters, body, expected_status_codes, polling_timeout, polling_interval, force_async=False):
        # Construct and send request
        # TODO move to resource.py `def query()`
        operation_config = {}

        request = None

        if header_parameters is None:
            header_parameters = {}

        header_parameters['x-ms-client-request-id'] = str(uuid.uuid1())

        self.logger.debug(f"_client: {type(self._client)}")
        # TODO Try to replace by .request: https://docs.python-requests.org/en/v0.6.2/api/
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

        self.logger.info(f"url: {url}")
        self.logger.info(f"request: {request}")
        response = self._client.send(request, header_parameters, body, **operation_config)
        self.logger.info(f"response.status_code: {response.status_code}")
        for hname, hvalue in response.headers.items():
            self.logger.info(f"response header {hname}: {hvalue}")

        if response.status_code not in expected_status_codes:
            exp = CloudError(response)
            exp.request_id = response.headers.get('x-ms-request-id')
            raise exp
        else:
            operation_url = response.headers.get('Azure-AsyncOperation')
            if operation_url: # Azure tells, which operations url to poll
                # example: https://management.azure.com/subscriptions/11.......-....-....-....-........../providers/Microsoft.ContainerService/locations/westeurope/operations/....-....-....-....-....?api-version=2017-08-31
                if force_async:
                    self.logger.debug(f"type(response): {type(response)}")
                    def async_url(self):
                        return operation_url
                    self.logger.debug("***** enrich the response in that special case with async_url method")
                    response.async_url = async_url.__get__(response)
                else: # poll until operation completed
                    self.logger.info("Got response with `Azure-AsyncOperation` header, will initiate long polling")
                    def get_long_running_output(response):
                        return response
                    polling_interval = 60
                    polling_timeout = 600
                    poller = LROPoller(self._client,
                                       ClientRawResponse(None, response),
                                       get_long_running_output,
                                       ARMPolling(polling_interval, **operation_config))
                    response = self.get_poller_result(poller, polling_timeout)

            else:
                pass # result immediately known

        self.logger.debug(hasattr(response, "async_url"))
        return response

    def get_poller_result(self, poller, timeout):
        try:
            poller.wait(timeout=timeout)
            return poller.result()
        except Exception as exc:
            raise
