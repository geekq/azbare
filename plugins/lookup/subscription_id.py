from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = """
  lookup: subscription_id
  author: Vladimir Dobriakov <info@infrastructure-as-code.de>
  version_added: "1.0"
  short_description: currently configured azure subscription_id
  description:
      - This lookup detects and returns the azure subscription id, as currently locally configured,
      - e.g. with `az login` command and persisted in `~/.azure/azureProfile.json` file.
      - It is the same value, which would be used by the resource module.
"""
from ansible.errors import AnsibleError, AnsibleParserError
from ansible.plugins.lookup import LookupBase
from ansible.utils.display import Display

from ansible_collections.geekq.azbare.plugins.module_utils.azure_rm_common import AzureRMAuth

display = Display()

class LookupModule(LookupBase):

    def run(self, terms, **kwargs):
        auth = AzureRMAuth()
        return [auth.subscription_id]
