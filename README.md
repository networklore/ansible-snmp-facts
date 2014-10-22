## ABOUT

This is an [Ansible](https://github.com/ansible/ansible) module from [Networklore](http://networklore.com). The snmp_facts module collects information from network devices such as router, firewalls and switches. This information is then stored as Ansible facts which can be used in Ansible playbooks.

## DOCUMENTATION

Currently there isn't much documentation available, but the reasoning around this module is described in the post [Gathering Ansible facts from network devices using SNMP](http://networklore.com/ansible-snmp-facts/).

The module itself contains basic information which shows you how to use it in a Playbook, also an example playbook comes bundled in this repo.

## INSTALLATION

This repo assumes you have the [DEPENDENCIES](#dependencies) installed on your system.  

## DEPENDENCIES

Thes modules require the following to be installed on the Ansible server:

* Python 2.7 (haven't tested other versions)
* [Ansible](http://www.ansible.com) 1.5 or later
* [pysnmp](http://pysnmp.sourceforge.net/) 4.2.5 or later (haven't tested other versions)

## LICENSE

GPL 2.0
  
## CONTRIBUTORS

- Patrick Ogenstad (@networklore)

