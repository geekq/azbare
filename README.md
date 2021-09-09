# Minimalistic ansible collection for managing Azure resources

There is an existing azcollection, supporting a lot of different types
of azure resources, some examples and documentation.

Unforturnately, the azcollection is not well maintained:

* still based on the old versions of Microsoft Azure API and is having problems updating its dependencies https://github.com/ansible-collections/azure/issues/477
* does not include all resources Azures supports, especially the new ones
* lacks support for advanced options for many resources, especially for hosting resource inside virtual private networks (relevant for my enterprise customers)
* conflicts with official azure command line client `az` - it is not possible/easy to use the both on the same computer

Explanation for that: `ansible-collections/azure` development is not
scalable. While Microsoft constantly expands and changes its API by
introducing new resources and new features to existing resources, every
such change requires adjustment to the implementation of these ansible
modules, which is not feasible for a project driven by a couple of
enthusiasts.

For a cloud engineer productivity instead of tinkering with az CLI or
Portal first, than trying to find out, which parameters to use for e.g.
https://docs.ansible.com/ansible/latest/collections/azure/azcollection/azure_rm_servicebus_module.html
I wish something more streamlined.

*Welcome to `azbare`!*

Heavily inspired by `resource` and `resource_info` modules of the
azcollection, without the ballast of obsolete dependencies, it supports
*all* Azure resources with the newest API and allows for the following,
high-productivity workflow:

Try out something with resource specific az command like `az servicebus
namespace create -g mygroup -n bus1 --sku Standard`, the extensive `az
servicebus --help` documentation helps a lot.

:arrow_down:

Alternatively or optionaly you can check/edit the resource interactively via Azure Portal. :arrow_right:
Get a generic resource definition with `az resource show -g mygroup
--resource-type "Microsoft.ServiceBus/Namespaces" -n bus1 -o yaml`,
which prints the resource definition, and can also be used as input by
`az resource @resource-definition-file`

:arrow_right:

Feed that resource definition to the new azbare.resource module to create the resource.

## Installation

    pip install -r requirements-azure.txt
    ansible-galaxy collection install git+git@github.com:geekq/azbare.git --force

