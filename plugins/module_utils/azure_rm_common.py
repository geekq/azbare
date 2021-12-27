# Copyright (c) 2016 Matt Davis, <mdavis@ansible.com>
#                    Chris Houseknecht, <house@redhat.com>
#
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


import os
import re
import types
import copy
import inspect
import traceback
import json

from os.path import expanduser

from ansible.module_utils.basic import AnsibleModule, missing_required_lib, env_fallback

from ansible.module_utils.six.moves import configparser
import ansible.module_utils.six.moves.urllib.parse as urlparse

AZURE_COMMON_ARGS = dict(
    auth_source=dict(
        type='str',
        choices=['auto', 'cli', 'env', 'credential_file', 'msi'],
        fallback=(env_fallback, ['ANSIBLE_AZURE_AUTH_SOURCE']),
        default="auto"
    ),
    profile=dict(type='str'),
    subscription_id=dict(type='str'),
    client_id=dict(type='str', no_log=True),
    secret=dict(type='str', no_log=True),
    tenant=dict(type='str', no_log=True),
    ad_user=dict(type='str', no_log=True),
    password=dict(type='str', no_log=True),
    cloud_environment=dict(type='str', default='AzureCloud'),
    cert_validation_mode=dict(type='str', choices=['validate', 'ignore']),
    api_profile=dict(type='str', default='latest'),
    adfs_authority_url=dict(type='str', default=None)
)

AZURE_CREDENTIAL_ENV_MAPPING = dict(
    profile='AZURE_PROFILE',
    subscription_id='AZURE_SUBSCRIPTION_ID',
    client_id='AZURE_CLIENT_ID',
    secret='AZURE_SECRET',
    tenant='AZURE_TENANT',
    ad_user='AZURE_AD_USER',
    password='AZURE_PASSWORD',
    cloud_environment='AZURE_CLOUD_ENVIRONMENT',
    cert_validation_mode='AZURE_CERT_VALIDATION_MODE',
    adfs_authority_url='AZURE_ADFS_AUTHORITY_URL'
)


HAS_AZURE = True
HAS_AZURE_EXC = None
HAS_AZURE_CLI_CORE = True
HAS_AZURE_CLI_CORE_EXC = None

HAS_MSRESTAZURE = True
HAS_MSRESTAZURE_EXC = None

try:
    import importlib
except ImportError:
    # This passes the sanity import test, but does not provide a user friendly error message.
    # Doing so would require catching Exception for all imports of Azure dependencies in modules and module_utils.
    importlib = None

try:
    from packaging.version import Version
    HAS_PACKAGING_VERSION = True
    HAS_PACKAGING_VERSION_EXC = None
except ImportError:
    Version = None
    HAS_PACKAGING_VERSION = False
    HAS_PACKAGING_VERSION_EXC = traceback.format_exc()

# NB: packaging issue sometimes cause msrestazure not to be installed, check it separately
try:
    from msrestazure import azure_cloud
except ImportError:
    HAS_MSRESTAZURE_EXC = traceback.format_exc()
    HAS_MSRESTAZURE = False

try:
    from enum import Enum
    from msrestazure.azure_active_directory import AADTokenCredentials
    from msrestazure.azure_exceptions import CloudError
    from msrestazure.azure_active_directory import MSIAuthentication
    from msrestazure.tools import parse_resource_id, resource_id, is_valid_resource_id
    from msrest.serialization import Serializer
    from msrest.service_client import ServiceClient
    from msrest.authentication import Authentication

    from azure.common.credentials import ServicePrincipalCredentials, UserPassCredentials
    from azure.mgmt.resource.resources import ResourceManagementClient
    from azure.mgmt.resource.subscriptions import SubscriptionClient
    from adal.authentication_context import AuthenticationContext
    from azure.mgmt.authorization import AuthorizationManagementClient
    from azure.mgmt.resource.locks import ManagementLockClient

    from ansible_collections.geekq.azbare.plugins.module_utils.azure_rm_common_rest import GenericRestClient

except ImportError as exc:
    Authentication = object
    HAS_AZURE_EXC = traceback.format_exc()
    HAS_AZURE = False

from base64 import b64encode, b64decode
from hashlib import sha256
from hmac import HMAC
from time import time

try:
    from urllib import (urlencode, quote_plus)
except ImportError:
    from urllib.parse import (urlencode, quote_plus)

try:
    from azure.cli.core.util import CLIError
    from azure.common.credentials import get_cli_profile
    from azure.common.cloud import get_cli_active_cloud
except ImportError:
    HAS_AZURE_CLI_CORE = False
    HAS_AZURE_CLI_CORE_EXC = None
    CLIError = Exception


def azure_id_to_dict(id):
    pieces = re.sub(r'^\/', '', id).split('/')
    result = {}
    index = 0
    while index < len(pieces) - 1:
        result[pieces[index]] = pieces[index + 1]
        index += 1
    return result


def format_resource_id(val, subscription_id, namespace, types, resource_group):
    return resource_id(name=val,
                       resource_group=resource_group,
                       namespace=namespace,
                       type=types,
                       subscription=subscription_id) if not is_valid_resource_id(val) else val


def normalize_location_name(name):
    return name.replace(' ', '').lower()


# Log more http and API auth details to a local file
import logging
logger = logging.getLogger('azbare')
logger.setLevel(logging.DEBUG) # TODO make it dependent on ansible module parameter
fh = logging.FileHandler('azbare.log')
fh.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
fh.setFormatter(formatter)
logger.addHandler(fh)

class AzureRMModuleBase(object):
    def __init__(self, derived_arg_spec, required_if=None, facts_module=False, supports_check_mode=False, skip_exec=False):

        self.logger = logging.getLogger('azbare')
        merged_arg_spec = dict()
        merged_arg_spec.update(AZURE_COMMON_ARGS)

        if derived_arg_spec:
            merged_arg_spec.update(derived_arg_spec)

        self.module = AnsibleModule(argument_spec=merged_arg_spec, supports_check_mode=supports_check_mode)

        if not HAS_PACKAGING_VERSION:
            self.fail(msg=missing_required_lib('packaging'),
                      exception=HAS_PACKAGING_VERSION_EXC)

        if not HAS_MSRESTAZURE:
            self.fail(msg=missing_required_lib('msrestazure'),
                      exception=HAS_MSRESTAZURE_EXC)

        if not HAS_AZURE:
            self.fail(msg=missing_required_lib('azure-mgmt-resource or azure-mgmt-authorization'),
                      exception=HAS_AZURE_EXC)

        self._resource = None

        self.check_mode = self.module.check_mode
        self.api_profile = self.module.params.get('api_profile')
        self.facts_module = facts_module
        self.debug = self.module.params.get('debug')

        # delegate auth to AzureRMAuth class (shared with all plugin types)
        self.azure_auth = AzureRMAuth(fail_impl=self.fail, **self.module.params)

        # common parameter validation
        if self.module.params.get('tags'):
            self.validate_tags(self.module.params['tags'])

        if not skip_exec:
            res = self.exec_module(**self.module.params)
            self.module.exit_json(**res)

    def exec_module(self, **kwargs):
        self.fail("Error: {0} failed to implement exec_module method.".format(self.__class__.__name__))

    def fail(self, msg, **kwargs):
        '''
        Shortcut for calling module.fail()

        :param msg: Error message text.
        :param kwargs: Any key=value pairs
        :return: None
        '''
        self.module.fail_json(msg=msg, **kwargs)

    def deprecate(self, msg, version=None):
        self.module.deprecate(msg, version)

    def log(self, msg, pretty_print=False):
        if pretty_print:
            self.module.debug(json.dumps(msg, indent=4, sort_keys=True))
        else:
            self.module.debug(msg)

    def get_mgmt_svc_client(self):
        base_url = self.azure_auth._cloud_environment.endpoints.resource_manager
        client = GenericRestClient(credentials=self.azure_auth.azure_credentials, subscription_id=self.azure_auth.subscription_id, base_url=base_url)
        return client

    # passthru methods to AzureAuth instance for backcompat
    @property
    def _cloud_environment(self):
        return self.azure_auth._cloud_environment

    @property
    def subscription_id(self):
        return self.azure_auth.subscription_id

class AzureRMAuthException(Exception):
    pass


class AzureRMAuth(object):
    _cloud_environment = None
    _adfs_authority_url = None

    def __init__(self, auth_source=None, profile=None, subscription_id=None, client_id=None, secret=None,
                 tenant=None, ad_user=None, password=None, cloud_environment='AzureCloud', cert_validation_mode='validate',
                 api_profile='latest', adfs_authority_url=None, **kwargs):

        self.logger = logging.getLogger('azbare.auth')
        # authenticate
        self.credentials = self._get_credentials(
            auth_source=auth_source,
            profile=profile,
            subscription_id=subscription_id,
            client_id=client_id,
            secret=secret,
            tenant=tenant,
            ad_user=ad_user,
            password=password,
            cloud_environment=cloud_environment,
            cert_validation_mode=cert_validation_mode,
            api_profile=api_profile,
            adfs_authority_url=adfs_authority_url)

        if not self.credentials:
            if HAS_AZURE_CLI_CORE:
                self.fail("Failed to get credentials. Either pass as parameters, set environment variables, "
                          "define a profile in ~/.azure/credentials, or log in with Azure CLI (`az login`).")
            else:
                self.fail("Failed to get credentials. Either pass as parameters, set environment variables, "
                          "define a profile in ~/.azure/credentials, or install Azure CLI and log in (`az login`).")

        # if cloud_environment specified, look up/build Cloud object
        raw_cloud_env = self.credentials.get('cloud_environment')
        if self.credentials.get('credentials') is not None and raw_cloud_env is not None:
            self._cloud_environment = raw_cloud_env
        elif not raw_cloud_env:
            self._cloud_environment = azure_cloud.AZURE_PUBLIC_CLOUD  # SDK default
        else:
            # try to look up "well-known" values via the name attribute on azure_cloud members
            all_clouds = [x[1] for x in inspect.getmembers(azure_cloud) if isinstance(x[1], azure_cloud.Cloud)]
            matched_clouds = [x for x in all_clouds if x.name == raw_cloud_env]
            if len(matched_clouds) == 1:
                self._cloud_environment = matched_clouds[0]
            elif len(matched_clouds) > 1:
                self.fail("Azure SDK failure: more than one cloud matched for cloud_environment name '{0}'".format(raw_cloud_env))
            else:
                if not urlparse.urlparse(raw_cloud_env).scheme:
                    self.fail("cloud_environment must be an endpoint discovery URL or one of {0}".format([x.name for x in all_clouds]))
                try:
                    self._cloud_environment = azure_cloud.get_cloud_from_metadata_endpoint(raw_cloud_env)
                except Exception as e:
                    self.fail("cloud_environment {0} could not be resolved: {1}".format(raw_cloud_env, e.message), exception=traceback.format_exc())

        if self.credentials.get('subscription_id', None) is None and self.credentials.get('credentials') is None:
            self.fail("Credentials did not include a subscription_id value.")
        self.logger.debug("setting subscription_id")
        self.subscription_id = self.credentials['subscription_id']

        # get authentication authority
        # for adfs, user could pass in authority or not.
        # for others, use default authority from cloud environment
        if self.credentials.get('adfs_authority_url') is None:
            self._adfs_authority_url = self._cloud_environment.endpoints.active_directory
        else:
            self._adfs_authority_url = self.credentials.get('adfs_authority_url')

        # get resource from cloud environment
        self._resource = self._cloud_environment.endpoints.active_directory_resource_id

        if self.credentials.get('credentials') is not None:
            # AzureCLI credentials
            self.azure_credentials = self.credentials['credentials']
        elif self.credentials.get('client_id') is not None and \
                self.credentials.get('secret') is not None and \
                self.credentials.get('tenant') is not None:
            self.azure_credentials = ServicePrincipalCredentials(client_id=self.credentials['client_id'],
                                                                 secret=self.credentials['secret'],
                                                                 tenant=self.credentials['tenant'],
                                                                 cloud_environment=self._cloud_environment,
                                                                 verify=True)

        elif self.credentials.get('ad_user') is not None and \
                self.credentials.get('password') is not None and \
                self.credentials.get('client_id') is not None and \
                self.credentials.get('tenant') is not None:

            self.azure_credentials = self.acquire_token_with_username_password(
                self._adfs_authority_url,
                self._resource,
                self.credentials['ad_user'],
                self.credentials['password'],
                self.credentials['client_id'],
                self.credentials['tenant'])

        elif self.credentials.get('ad_user') is not None and self.credentials.get('password') is not None:
            tenant = self.credentials.get('tenant')
            if not tenant:
                tenant = 'common'  # SDK default

            self.azure_credentials = UserPassCredentials(self.credentials['ad_user'],
                                                         self.credentials['password'],
                                                         tenant=tenant,
                                                         cloud_environment=self._cloud_environment,
                                                         verify=True)
        else:
            self.fail("Failed to authenticate with provided credentials. Some attributes were missing. "
                      "Credentials must include client_id, secret and tenant or ad_user and password, or "
                      "ad_user, password, client_id, tenant and adfs_authority_url(optional) for ADFS authentication, or "
                      "be logged in using AzureCLI.")

    def fail(self, msg, exception=None, **kwargs):
        raise AzureRMAuthException(msg)

    def _get_env(self, module_key, default=None):
        "Read envvar matching module parameter"
        return os.environ.get(AZURE_CREDENTIAL_ENV_MAPPING[module_key], default)

    def _get_profile(self, profile="default"):
        path = expanduser("~/.azure/credentials")
        try:
            config = configparser.ConfigParser()
            config.read(path)
        except Exception as exc:
            self.fail("Failed to access {0}. Check that the file exists and you have read "
                      "access. {1}".format(path, str(exc)))
        credentials = dict()
        for key in AZURE_CREDENTIAL_ENV_MAPPING:
            try:
                credentials[key] = config.get(profile, key, raw=True)
            except Exception:
                pass

        if credentials.get('subscription_id'):
            return credentials

        return None

    def _get_msi_credentials(self, subscription_id=None, client_id=None, **kwargs):
        credentials = MSIAuthentication(client_id=client_id)
        subscription_id = subscription_id or self._get_env('subscription_id')
        if not subscription_id:
            try:
                # use the first subscription of the MSI
                subscription_client = SubscriptionClient(credentials)
                subscription = next(subscription_client.subscriptions.list())
                subscription_id = str(subscription.subscription_id)
            except Exception as exc:
                self.fail("Failed to get MSI token: {0}. "
                          "Please check whether your machine enabled MSI or grant access to any subscription.".format(str(exc)))
        return {
            'credentials': credentials,
            'subscription_id': subscription_id
        }

    def _get_azure_cli_credentials(self, subscription_id=None):
        subscription_id = subscription_id or self._get_env('subscription_id')
        profile = get_cli_profile()
        credentials, subscription_id, tenant = profile.get_login_credentials(
            subscription_id=subscription_id)
        cloud_environment = get_cli_active_cloud()

        cli_credentials = {
            'credentials': credentials,
            'subscription_id': subscription_id,
            'cloud_environment': cloud_environment
        }
        return cli_credentials

    def _get_env_credentials(self):
        env_credentials = dict()
        for attribute, env_variable in AZURE_CREDENTIAL_ENV_MAPPING.items():
            env_credentials[attribute] = os.environ.get(env_variable, None)

        if env_credentials['profile']:
            credentials = self._get_profile(env_credentials['profile'])
            return credentials

        if env_credentials.get('subscription_id') is not None:
            return env_credentials

        return None

    def _get_credentials(self, auth_source=None, **params):
        # Get authentication credentials.
        self.logger.debug('Getting credentials')

        arg_credentials = dict()
        for attribute, env_variable in AZURE_CREDENTIAL_ENV_MAPPING.items():
            arg_credentials[attribute] = params.get(attribute, None)

        if auth_source == 'msi':
            self.logger.debug('Retrieving credentials from MSI')
            return self._get_msi_credentials(subscription_id=params.get('subscription_id'), client_id=params.get('client_id'))

        if auth_source == 'cli':
            if not HAS_AZURE_CLI_CORE:
                self.fail(msg=missing_required_lib('azure-cli', reason='for `cli` auth_source'),
                          exception=HAS_AZURE_CLI_CORE_EXC)
            try:
                self.logger.debug('Retrieving credentials from Azure CLI profile')
                cli_credentials = self._get_azure_cli_credentials(subscription_id=params.get('subscription_id'))
                return cli_credentials
            except CLIError as err:
                self.fail("Azure CLI profile cannot be loaded - {0}".format(err))

        if auth_source == 'env':
            self.logger.debug('Retrieving credentials from environment')
            env_credentials = self._get_env_credentials()
            return env_credentials

        if auth_source == 'credential_file':
            self.logger.debug("Retrieving credentials from credential file")
            profile = params.get('profile') or 'default'
            default_credentials = self._get_profile(profile)
            return default_credentials

        # auto, precedence: module parameters -> environment variables -> default profile in ~/.azure/credentials -> azure cli
        # try module params
        if arg_credentials['profile'] is not None:
            self.logger.debug('Retrieving credentials with profile parameter.')
            credentials = self._get_profile(arg_credentials['profile'])
            return credentials

        if arg_credentials['client_id'] or arg_credentials['ad_user']:
            self.logger.debug('Received credentials from parameters.')
            return arg_credentials

        # try environment
        env_credentials = self._get_env_credentials()
        if env_credentials:
            self.logger.debug('Received credentials from env.')
            return env_credentials

        # try default profile from ~./azure/credentials
        default_credentials = self._get_profile()
        if default_credentials:
            self.logger.debug('Retrieved default profile credentials from ~/.azure/credentials.')
            return default_credentials

        try:
            if HAS_AZURE_CLI_CORE:
                self.logger.debug('Retrieving credentials from AzureCLI profile')
            cli_credentials = self._get_azure_cli_credentials(subscription_id=params.get('subscription_id'))
            return cli_credentials
        except CLIError as ce:
            self.logger.debug('Error getting AzureCLI profile credentials - {0}'.format(ce))

        return None

    def acquire_token_with_username_password(self, authority, resource, username, password, client_id, tenant):
        authority_uri = authority

        if tenant is not None:
            authority_uri = authority + '/' + tenant

        context = AuthenticationContext(authority_uri)
        token_response = context.acquire_token_with_username_password(resource, username, password, client_id)

        return AADTokenCredentials(token_response)

    def log(self, msg, pretty_print=False):
        # Use only during module development
        if True: # self.debug
            with open('azure_rm.log', 'a') as log_file:
                try:
                    if pretty_print:
                        print(json.dumps(msg, indent=4, sort_keys=True), file=log_file)
                    else:
                        print(msg, file=log_file)
                except Exception as e:
                    print('Can not log the log message', file=log_file)
                    print(e, file=log_file)
