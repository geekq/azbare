# Advanced scenarios

## Rotate authorization keys for an Azure Service Bus topic

Lets have a look at some advanced operations like rotating the access
keys for an Azure Service Bus topic. First run some az CLI commands in
debug mode to find out the resource url, http method and request body
used to run the desired operation:

```
$ az servicebus topic create -g experimental-applicationdevelopment --namespace-name myexample-bus1 -n topic1
$ az servicebus topic authorization-rule create -g experimental-applicationdevelopment --namespace-name myexample-bus1 --topic-name topic1 -n app1 --rights Send
$ az servicebus topic authorization-rule keys list -g experimental-applicationdevelopment --namespace-name myexample-bus1 --topic-name topic1 -n app1
$ az servicebus topic authorization-rule keys renew --key SecondaryKey --key-value '5fIlk/JTSJVc40LWASmsHAni3t8/yw+eThTLwx3uQL8=' -g experimental-applicationdevelopment --namespace-name myexample-bus1 --topic-name topic1 -n app1 --debug

msrest.http_logger : Request URL: 'https://management.azure.com/subscriptions/xxxxxxxx-...-xxxx/resourceGroups/experimental-applicationdevelopment/providers/Microsoft.ServiceBus/namespaces/myexample-bus1/topics/topic1/authorizationRules/app1/regenerateKeys?api-version=2017-04-01'
msrest.http_logger : Request method: 'POST'
msrest.http_logger : Request body:
msrest.http_logger : {"keyType": "SecondaryKey", "key": "5fIlk/JTSJVc40LWASmsHAni3t8/yw+eThTLwx3uQL8="}

```

Now we can use the special `state: special-post` to run the same via ansible:

```
- name: Get the existing topic access secret keys
  geekq.azbare.resource:
    api_version: '2017-04-01'
    group: experimental-applicationdevelopment
    path: /providers/Microsoft.ServiceBus/namespaces/myexample-bus1/topics/topic1/authorizationRules/app1/ListKeys
    state: special-post

- name: Copy the primary secret key to secondary
  geekq.azbare.resource:
    api_version: '2017-04-01'
    group: experimental-applicationdevelopment
    path: /providers/Microsoft.ServiceBus/namespaces/myexample-bus1/topics/topic1/authorizationRules/app1/regenerateKeys
    state: special-post
    definition:
      keyType: SecondaryKey
      key: '4fIlk/JTSJVc40LWASmsHAni3t8/yw+eThTLwx3uQL8=' # assuming this is the value returned by the previous command
```


## Filter role assignments; create a new role assignment

A role assignmend in Azure requires a unique "name" (UUID). But the
combination of principal_id, role_id and scope needs to be unique. So
before creating a new role assignment we always need to check, if there
is an existing one with the combination of above parameters:

```

# Assuming
# principal: "{{ mycluster.response.properties.identityProfile.kubeletidentity.objectId }}"
# scope: e.g. '/providers/Microsoft.ContainerRegistry/registries/my-acr'

- name: Get AcrPull role details - find role id for a role name
  geekq.azbare.resource:
    api_version: '2018-01-01-preview'
    group: my-acr-group
    path: "{{ scope }}/providers/Microsoft.Authorization/roleDefinitions?$filter=roleName%20eq%20%27AcrPull%27"
    state: check
  register: pull_role

- name: Check for existing role assignments with that role definition and principal
  geekq.azbare.resource:
    api_version: '2020-04-01-preview'
    group: my-acr-group
    path: "{{ scope }}/providers/Microsoft.Authorization/roleAssignments?$filter=atScope%28%29"
    state: check
  register: assignments

- name: Allow pulling docker images from ACR (container registry)
  geekq.azbare.resource:
    api_version: '2020-04-01-preview'
    group: my-acr-group
    path: "{{ scope }}"/providers/Microsoft.Authorization/roleAssignments/{{ 999 | random | to_uuid }}
    details: info
    definition:
      properties:
        roleDefinitionId: "{{ pull_role.response.value[0].id }}"
        principalId: "{{ principal }}"
  # Note: parenthesis are important for boolean conversion, see https://medium.com/opsops/wft-bool-filter-in-ansible-e7e2fd7a148f
  when: not (assignments.response.value | geekq.azbare.detect_role_assignment('ServicePrincipal', principal, pull_role.response.value[0].id, scope))
```


## subscription_id Lookup

You can use this ansible lookup whenever you need your current subscription id:

    /subscriptions/{{ lookup('geekq.azbare.subscription_id') }}/resourceGroups/...
