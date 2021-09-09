# Minimalistic ansible collection for managing Azure resources

There is an existing `azcollection`, which supports a lot of different types
of azure resources, includes examples and documentation.

Unforturnately, there are some problems with maintenance:

* it is still based on the old versions of Microsoft Azure API and is having problems updating its dependencies https://github.com/ansible-collections/azure/issues/477
* does not include all resources Azures supports, especially the new ones
* lacks support for advanced options for many resources, especially for hosting resource inside virtual private networks (relevant for my enterprise customers)
* conflicts with official azure command line client `az` - it is not possible/easy to use the both on the same computer

Explanation for that: `ansible-collections/azure` development is not
scalable. While Microsoft constantly expands and changes its API by
introducing new resources and new features to existing resources, every
such change requires adjustment to the implementation of these ansible
modules, which is not feasible for a project driven by a couple of
enthusiasts.

Heavily inspired by `resource` and `resource_info` modules of the
azcollection, without the ballast of obsolete dependencies, it supports
*all* Azure resources with the newest API and allows for a
high-productivity workflow, described below.

**Welcome to `azbare`!**


## Ideal workflow

For a cloud engineer productivity following workflow would be desirable:

Assuming you've alreade created a resource group like
`az group create -g experimental-applicationdevelopment -l westeurope`.
Try out something with resource specific az command like `az servicebus
namespace create -g experimental-applicationdevelopment -n myexample-bus1 --sku
Standard`. The extensive documentation behind `az servicebus
--help` helps a lot. Alternatively or optionaly you can check/edit the
resource interactively via Azure Portal.

:arrow_down:

Find out the resource id with `az servicebus namespace list -o yaml | grep myexample | grep id`

:arrow_down:

Now print a generic resource definition with
`az resource show -o yaml --ids /subscriptions/xxxxx-...-xxxx/resourceGroups/devinfra/providers/Microsoft.ServiceBus/namespaces/myexample-bus1`

```
id: /subscriptions/xxxxx-....-xxxx/resourceGroups/experimental-applicationdevelopment/providers/Microsoft.ServiceBus/namespaces/myexample-bus1
identity: null
kind: null
location: West Europe
managedBy: null
name: myexample-bus1
plan: null
properties:
  createdAt: '2021-09-09T19:41:47.587Z'
  metricId: xxxx-8b05-xxxx-ad6d-6f43b47f438f:myexample-bus1
  provisioningState: Succeeded
  serviceBusEndpoint: https://myexample-bus1.servicebus.windows.net:443/
  status: Active
  updatedAt: '2021-09-09T19:42:32.827Z'
resourceGroup: experimental-applicationdevelopment
sku:
  capacity: null
  family: null
  model: null
  name: Standard
  size: null
  tier: Standard
tags: {}
type: Microsoft.ServiceBus/Namespaces
```

:arrow_down:

Remove empty (`null`) and other not relevant parameters from the output
and feed that content to the `definition` parameter of the new
azbare.resource module to create the resource. Set `group` and `path`
based on the `id` value.

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


## Installation

    pip install -r requirements-azure.txt
    ansible-galaxy collection install git+git@github.com:geekq/azbare.git --force

