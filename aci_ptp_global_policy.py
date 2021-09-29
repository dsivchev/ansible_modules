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
module: aci_ptp_policy
short_description: Manage Precision Time Protocol (PTP) policy (latencyPtpMode) 
description: Precision Time Protocol (PTP) policy
- Manage Precision Time Protocol (PTP) global policy 
options:
  admin_state:
    description:
    - Enable PTP mode.
    type: str
    choices: [ enabled, disabled ]
  profile:
    description:
    - The name of the PTP Profile.
    type: str
    choices: [ aes67, smpte, default ]
    default: aes67
    aliases: [ fabric_ptp_profile ]
  state:
    description:
    - Use C(present) or C(absent) for adding or removing.
    - Use C(query) for listing an object or multiple objects.
    type: str
    choices: [ absent, present, query ]
    default: present
extends_documentation_fragment:
- cisco.aci.aci
notes:
- "absent" state is not deleting the object. class:latencyPtpMode can be only enabled or disabled but not removed.
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
        admin_state=dict(type='str', choices=['enabled', 'disabled']), 
        profile=dict(type='str', choices=[ 'aes67', 'smpte', 'default' ], default='aes67', aliases=['ptp_profile']), 
        state=dict(type='str', default='present', choices=['absent', 'present', 'query']),
        #name_alias=dict(type='str'),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        #required_if=[
        #    ['state', 'absent', [admin_state]],
        #    ['state', 'present', [admin_state]],
        #],
    )

    admin_state = module.params.get('admin_state')
    state = module.params.get('state')
    profile = module.params.get('profile')
    #name_alias = module.params.get('name_alias')
    

    aci = ACIModule(module)
    aci.construct_url(
        root_class=dict(
            aci_class='latencyPtpMode',
            aci_rn='fabric/ptpmode',
        ),
    )

    aci.get_existing()

    
    if state == 'present':
        if profile == "default":
            fabSyncIntvl = 1
            fabDelayIntvl = 0
        else:
            fabSyncIntvl = -2
            fabDelayIntvl = -3
        aci.payload(
            aci_class='latencyPtpMode',
            class_config=dict(
                state=admin_state,
                fabProfileTemplate=profile,
                fabSyncIntvl=fabSyncIntvl,
                fabDelayIntvl=fabDelayIntvl,
                #nameAlias=name_alias,
            ),
        )

        aci.get_diff(aci_class='latencyPtpMode')

        aci.post_config()

    elif state == 'absent':
        aci.payload(
            aci_class='latencyPtpMode',
            class_config=dict(
                state="disabled",
                fabProfileTemplate=profile,
            ),
        )
        
        aci.get_diff(aci_class='latencyPtpMode')

        aci.post_config()


    aci.exit_json()


if __name__ == "__main__":
    main()
