from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = """
  lookup: version
  author: Vladimir Dobriakov <info@infrastructure-as-code.de>
  version_added: "1.1"
  short_description: version of this library
  description:
      - Returns the current version of this library to check
      - for e.g. incompatible changes
"""
from ansible.errors import AnsibleError, AnsibleParserError
from ansible.plugins.lookup import LookupBase

class LookupModule(LookupBase):

    def run(self, terms, **kwargs):
        return ['1.1.0']
