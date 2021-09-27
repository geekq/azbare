import yaml
from os import path

class FilterModule(object):
    def filters(self):
        return {'detect_role_assignment': detect_role_assignment}

def detect_role_assignment(assignments, principal_type, principal_id, role_id, scope_suffix):
    """Go through the list and return the first azure role assignment which matches the criteria.

    >>> assignments = yaml.load(open(path.join(path.dirname(__file__), '../../tests/data/assignments.yaml')), Loader=yaml.SafeLoader)
    >>> res = detect_role_assignment(assignments, 'ServicePrincipal', '222222-aaaa-bbbb',
    ...   '/subscriptions/xxxx-xxxx/providers/Microsoft.Authorization/roleDefinitions/7f951dda-4ed3-4680-a7ca-43fe172d538d',
    ...   'Microsoft.ContainerRegistry/registries/someacrregistry')
    >>> res['type']
    'Microsoft.Authorization/roleAssignments'
    """
    for assignment in assignments:
        p = assignment['properties']
        if (p['principalType'] == principal_type
                and p['principalId'] == principal_id
                and p['roleDefinitionId'] == role_id
                and p['scope'].endswith(scope_suffix)):
            return assignment
    return None
