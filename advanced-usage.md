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

