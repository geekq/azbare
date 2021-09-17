Following setup is used for testing (and works)

```
# Create environment for testing
rm -rf ~/pyenvs/azbare
mkdir -p ~/pyenvs/azbare
python3.8 -m venv ~/pyenvs/azbare

# Install dependencies
. ~/pyenvs/azbare/bin/activate
pip install wheel
pip install -r requirements-azure.txt --force
pip install ansible==2.10.5
ansible-galaxy collection build --force
ansible-galaxy collection install geekq-azbare-1.0.0.tar.gz --force \
  -p $VIRTUAL_ENV/lib/python3.8/site-packages/ansible_collections

# Run the tests
ansible-playbook tests/all-tests.playbook.yaml -vv
```

