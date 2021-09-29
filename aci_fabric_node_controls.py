#!/usr/bin/python
# -*- coding: utf-8 -*-

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'certified'}

DOCUMENTATION = r'''
---
module: aci_fabric_node_control
short_description: Manage Fabric Node Controls monitoring policiy (fabricNodeControl) 
description: Fabric Node Controls monitoring policy
- Manage Fabric Node Controls monitoring policiy 
options:
  dom_control:
    description:
    - Enable/Disable digital optical monitoring (DOM) monitoring. 0 is disabled, 1 is enabled.
    type: int
    default: 0
    choices: [ 0, 1 ]
  policy:
    description:
    - The name of the Fabric Node Controls monitoring policiy.
    type: str
    aliases: [ policy_name, name ]
  feature:
    description:
    - Select a flow collection feature such as Analytics, NetFlow, and Telemetry.
    type: str
    choices: [ telemetry, analytics, netflow ]
    default: telemetry
    aliases: [ feature_select ]
  state:
    description:
    - Use C(present) or C(absent) for adding or removing.
    - Use C(query) for listing an object or multiple objects.
    type: str
    choices: [ absent, present, query ]
    default: present
  name_alias:
    description:
    - The alias for the current object. This relates to the nameAlias field in ACI.
    type: str
   description:
    description:
    - Description for the Scheduler.
    type: str
    aliases: [ descr ]
extends_documentation_fragment:
- cisco.aci.aci
notes:
- Note for 'dom_control' paramater only possible values are 0 (disable DOM) and 1 (enable DOM).
see also: 
- name: APIC Management Information Model reference
  description: More information about the internal APIC class (latency:ptpmode).
  link: https://developer.cisco.com/docs/apic-mim-ref/
author:
- 
'''

EXAMPLES = r'''
- name: Enable a new global PTP profile
  cisco.aci.aci_ap:
    host: apic
    username: admin
    password: SomeSecretPassword
    admin_state: enabled
    profile: aes67 
    state: present
    validate_certs: no
  delegate_to: localhost
- name: Disable a global PTP profile
  cisco.aci.aci_ap:
    host: apic
    username: admin
    password: SomeSecretPassword
    state: absent
  delegate_to: localhost
- name: Query a global PTP policy
  cisco.aci.aci_ap:
    host: apic
    username: admin
    password: SomeSecretPassword
    state: query
  delegate_to: localhost
  register: query_result
'''

RETURN = r'''
current:
  description: The existing configuration from the APIC after the module has finished
  returned: success
  type: list
  sample:
        [
        {
            "fvTenant": {
                "attributes": {
                    "descr": "Production environment",
                    "dn": "uni/tn-production",
                    "name": "production",
                    "nameAlias": "",
                    "ownerKey": "",
                    "ownerTag": ""
                }
            }
        }
    ]
error:
  description: The error information as returned from the APIC
  returned: failure
  type: dict
  sample:
    {
        "code": "122",
        "text": "unknown managed object class foo"
    }
raw:
  description: The raw output returned by the APIC REST API (xml or json)
  returned: parse error
  type: str
  sample: '<?xml version="1.0" encoding="UTF-8"?><imdata totalCount="1"><error code="122" text="unknown managed object class foo"/></imdata>'
sent:
  description: The actual/minimal configuration pushed to the APIC
  returned: info
  type: list
  sample:
    {
        "fvTenant": {
            "attributes": {
                "descr": "Production environment"
            }
        }
    }
previous:
  description: The original configuration from the APIC before the module has started
  returned: info
  type: list
  sample:
    [
        {
            "fvTenant": {
                "attributes": {
                    "descr": "Production",
                    "dn": "uni/tn-production",
                    "name": "production",
                    "nameAlias": "",
                    "ownerKey": "",
                    "ownerTag": ""
                }
            }
        }
    ]
proposed:
  description: The assembled configuration from the user-provided parameters
  returned: info
  type: dict
  sample:
    {
        "fvTenant": {
            "attributes": {
                "descr": "Production environment",
                "name": "production"
            }
        }
    }
filter_string:
  description: The filter string used for the request
  returned: failure or debug
  type: str
  sample: ?rsp-prop-include=config-only
method:
  description: The HTTP method used for the request to the APIC
  returned: failure or debug
  type: str
  sample: POST
response:
  description: The HTTP response from the APIC
  returned: failure or debug
  type: str
  sample: OK (30 bytes)
status:
  description: The HTTP status from the APIC
  returned: failure or debug
  type: int
  sample: 200
url:
  description: The HTTP url used for the request to the APIC
  returned: failure or debug
  type: str
  sample: https://10.11.12.13/api/mo/uni/fabric/ptpmode.json
'''


from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.aci.plugins.module_utils.aci import ACIModule, aci_argument_spec


def main():
    argument_spec = aci_argument_spec()
    argument_spec.update(
        dom_control=dict(type='int', choices=[0, 1], default=0, aliases=['control']), 
        feature=dict(type='str', choices=[ 'telemetry', 'analytics', 'netflow' ], default='telemetry', aliases=['feature_select']), 
        policy=dict(type='str', aliases=['policy_name', 'name']),
        name_alias=dict(type='str'),
        description=dict(type='str', aliases=['descr']),
        state=dict(type='str', default='present', choices=['absent', 'present', 'query']),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ['state', 'absent', ['policy']],
            ['state', 'present', ['policy']],
        ],
    )

    feature = module.params.get('feature')
    policy = module.params.get('policy')
    state = module.params.get('state')
    dom_control = module.params.get('dom_control')
    name_alias = module.params.get('name_alias')
    description = module.params.get('description')
    
    

    aci = ACIModule(module)
    aci.construct_url(
        root_class=dict(
            aci_class='fabricNodeControl',
            aci_rn='fabric/nodecontrol-{0}'.format(policy),
            module_object=policy,
            target_filter={'name': policy},
        ),
    )

    aci.get_existing()

    
    if state == 'present':
        aci.payload(
            aci_class='fabricNodeControl',
            class_config=dict(
                name=policy,
                featureSel=feature,
                control=dom_control,
                descr=description,
                nameAlias=name_alias,
            ),
        )

        aci.get_diff(aci_class='fabricNodeControl')

        aci.post_config()


    elif state == 'absent':
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
