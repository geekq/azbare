# Development

ansible-galaxy is the official way for packaging ansible related
goodies. Unfortunately it provides no simple way to integrate a galaxy
collection under development into an existing ansible setup.

Assuming you have created a separate virtualenv as desribed
[for testing](../tests/README.md), we can use following automation as
workaround for a shorter feedback cycle. Define a shell function like

```
azbareinstall () {
    ansible-galaxy collection build --force
    # assuming you've created a separate ~/.pyenvs/azbare python virtualenv
    ansible-galaxy collection install geekq-azbare-1.0.0.tar.gz --force \
      -p ~/.pyenvs/azbare/lib/python3.8/site-packages/ansible_collections
}
```

and on every source code change you can run

```
azbareinstall && ansible-playbook tests/all-tests.playbook.yaml -vv
```
