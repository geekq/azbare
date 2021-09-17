```
# Create environment for testing
rm -rf ~/pyenvs/azbare
mkdir -p ~/pyenvs/azbare
python3.8 -m venv ~/pyenvs/azbare

# Install dependencies
. ~/pyenvs/azbare/bin/activate
pip install wheel
pip install ansible==2.10.5
pip install -r requirements-azure.txt --force
ansible-galaxy collection install git+file://`pwd` --force

# Run the tests
ansible-playbook tests/all-tests.playbook.yaml -vv
```

