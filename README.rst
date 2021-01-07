API Management for Infra as Code
=======================================================================
.. contents:: Table of Contents

Introduction
==================================================
Use Case
###############
- **Passwordless** -- Do not share admin right account to API consumer, use temporary token
- **Control and Visibility** -- Manage who can consume (Authentication), which API (Authorization) and track consumption (Accounting)
- **Secured front door** -- Publishing directly infrastructure management API to consumers is also an open door to exploit vulnerability or doing misconfiguration. Because patching infra devices could be a long process, use a WAF natively API oriented to protect control-plane access.
- **Collaboration** -- Publish live documentation to Application Developper (AppDev) on how to consume Infra as Code (IaC)
- **Agility** -- Do not change API when an infrastructure product change, publish agnostic API to your consumer

Benefit
###############
- **Secure Infra as Code** -- Protect and manage published API of your Infra as Code (IaC)
- **Faster App Deployment** -- Accelerate your App deployment by publishing automatically clear and up-to-date API documentation to AppDev
- **Simple management** -- Security Team updates all components of this front door (WAF, API GW and DevPortal) with one file : `openAPI spec file (swagger) <https://swagger.io/specification/>`_

Architecture
###############
Global view
*********************
Infrastructure's management API can be published directly through a secured API GW, as described below:

.. figure:: _figures/Architecture_global_direct.png

Some Infra as Code function could be complex to do in one call and this complexity could not be in charge of the consumer.
In this case, complexity is hidden and process by a playbook published through an Automation layer.
This use case permits also to publish an Agnostic API workflow dissociated from infrastructure editors.
Regarding the data path, consumers still make API call to the secured API GW and this one now routes this API request to an automation layer.

.. figure:: _figures/Architecture_global_agnostic.png

Functional view
*********************

.. figure:: _figures/Architecture_functionnal_view.png

Functional components in the data path between consumers and infrastructure devices:

- **DNS** -- DNS name resolution to access to published Application and DevPortal
- **DevPortal** -- Web User Interface that presents to developers how to consume published Applications i.e. published IaC APIs
- **Consumer** -- orchestration tool (`Gitlab <https://docs.gitlab.com/ee/ci/>`_ , `Ansible Tower <https://www.ansible.com/products/tower>`_ , ...)
- **IdP / oAuth Authorization server** -- oAuth Identity Provider to manage access policy to allow Users (consumer) to consume Application (published IaC API)
- **WAF** -- Web Application Firewall to prevent from attack on Application and send metrics/security events to its Controller. Protection features are:
- **+-- Reduce attack surface**: Publish the strict necessary of API apps using up to date `openAPI spec file (swagger) <https://swagger.io/specification/>`_
- **+-- Virtual Patching**: block exploitation of vulnerabilities (`CVE <https://cve.mitre.org/>`_) on underlying App's technologies
- **+-- Weakness in code**: Following awareness of OWASP foundation for `API app <https://owasp.org/www-project-api-security/>`_, raise protection to `prevent from hacking actions <http://veriscommunity.net/enums.html#section-actions>`_
- **API GW** -- oAuth Resource Server, rate limit, monitor service, route based on URI and send metrics/security events to its Controller.
- **infrastructure | Virtual Appliance** -- final devices that receive API requests from consumer
- **infrastructure | Network** -- underlying network and L3/L4 FW

Functional out-of-band components used to manage the solution:

- **Controller** -- Through API or UI, manage configuration, collect metrics/security events and give visibility on managed instances: WAF, API GW, DevPortal
- **Repository** -- External Source of Truth i.e. store configuration files : WAF policy, openAPI spec file of published Applications
- **Key/value store** -- In spite of querying regularly components to retrieve information by playbooks, useful information are stored in a Key/value store
- **Automation tool** -- Deploy configuration on Controller


Product
*********************
Products used for this demo:

- **DNS** -- `F5 Cloud Services <https://simulator.f5.com/>`_
- **DevPortal** -- unlimited instances managed by `NGINX Controller <https://docs.nginx.com/nginx-controller/services/api-management/manage-dev-portals/>`_
- **Consumer** -- `Postman <https://www.postman.com/>`_
- **IdP** -- `Okta <https://www.okta.com/developer/signup>`_
- **WAF**: unlimited instances managed by `NGINX Controller + add-on Application Security module <https://www.nginx.com/blog/introducing-nginx-controller-app-security-for-delivery>`_
- **API GW**: unlimited instances managed by `NGINX Controller + add-on API Management module <https://www.nginx.com/resources/datasheets/nginx-controller-api-management/>`_
- **Repository**: GitHub
- **Controller** -- `NGINX Controller <https://www.nginx.com/products/nginx-controller/>`_
- **Key/value store**: `Consul <https://www.consul.io/>`_
- **Automation tool**: `Ansible Tower <https://www.ansible.com/products/tower>`_
- **infrastructure | Virtual Appliance** -- `F5 BIG-IP <https://clouddocs.f5.com/>`_
- **infrastructure | Network** -- `Azure <https://github.com/ansible-collections/azure>`_

Network view
*********************
The diagram below present the data flow through network components.

.. figure:: _figures/Architecture_network.png

oAuth view
*********************
Client Credentials Grant is used in this demo because the identity of the user is not known and consumer (client) is in confidence, so client_secret can be stored client side.
Other grant type work as well, only an access token need to be present in Bearer header.

.. figure:: _figures/Architecture_oauth.png

WAF policy structure
*********************
A WAF policy includes:
- ** Base line **: enabled protection. Definition could be stored in an external file.
- ** API definition **: strict positive policy generated from an external openAPI spec file (swagger). Only compliant request URI, method, JSON key/value specified is allowed.
- ** Modification **: deviation from the Base line. Contains a list of changes to express exceptions to the intended Base line policy. These exceptions are usually the result of fixing false positive incidents and failures in tests applied to those policies.

.. figure:: _figures/waf_policy_structure.png

More details `here <https://docs.nginx.com/nginx-app-protect/configuration/#policy-authoring-and-tuning>`_.

Demo
###############
1) Create Identity Provider
*********************

.. raw:: html

    <a href="http://www.youtube.com/watch?v=2QuP4FQ1-EU"><img src="http://img.youtube.com/vi/2QuP4FQ1-EU/0.jpg" width="600" height="400" title="Deploy Ingress Controller" alt="Deploy Ingress Controller"></a>

Pre-requisites
==============
Okta
##############
- Create an dev account `here <https://developer.okta.com/signup/>`_
- Keep the created Okta domain, it will be used later in deployment workflow as an ``extra variable`` named ``organization``
- Create a token for automation tool that will deploy the solution

.. figure:: _figures/okta_token.png

- Keep the created API key, it will be used later in deployment workflow as an ``extra variable`` named ``api_key``

Ansible Tower
##############
virtualenv
***************************
- Create a virtualenv following `this guide <https://docs.ansible.com/ansible-tower/latest/html/upgrade-migration-guide/virtualenv.html>`_
- In virtualenv, as a prerequisite for Azure collection, install Azure SDK following `this guide <https://github.com/ansible-collections/azure>`_
- In virtualenv, as a prerequisite for K8S collection, install ``openshift`` following `this guide <https://github.com/ansible-collections/community.kubernetes>`_

Credential
***************************
- Create a Service Principal on Azure following `this guide <https://docs.microsoft.com/en-us/azure/active-directory/develop/quickstart-register-app>`_
- Create a Microsoft Azure Resource Manager following `this guide <https://docs.ansible.com/ansible-tower/latest/html/userguide/credentials.html#microsoft-azure-resource-manager>`_
- Create Credentials ``cred_NGINX`` to manage access to NGINX instances following `this guide <https://docs.ansible.com/ansible-tower/latest/html/userguide/credentials.html#machine>`_

=====================================================   =============================================   =============================================   =============================================   =============================================
REDENTIAL TYPE                                          USERNAME                                        SSH PRIVATE KEY                                 SIGNED SSH CERTIFICATE                          PRIVILEGE ESCALATION METHOD
=====================================================   =============================================   =============================================   =============================================   =============================================
``Machine``                                             ``my_VM_admin_user``                            ``my_VM_admin_user_key``                        ``my_VM_admin_user_CRT``                        ``sudo``
=====================================================   =============================================   =============================================   =============================================   =============================================

Ansible role structure
######################
- Deployment is based on ``workflow template``. Example: ``workflow template`` = ``wf-create_create_edge_security_inbound``
- ``workflow template`` includes multiple ``job template``. Example: ``job template`` = ``poc-azure_create_hub_edge_security_inbound``
- ``job template`` have an associated ``playbook``. Example: ``playbook`` = ``playbooks/poc-azure.yaml``
- ``playbook`` launch a ``play`` in a ``role``. Example: ``role`` = ``poc-azure``

.. code:: yaml

    - hosts: localhost
      gather_facts: no
      roles:
        - role: poc-azure

- ``play`` is an ``extra variable`` named ``activity`` and set in each ``job template``. Example: ``create_hub_edge_security_inbound``
- The specified ``play`` (or ``activity``) is launched by the ``main.yaml`` task located in the role ``tasks/main.yaml``

.. code:: yaml

    - name: Run specified activity
      include_tasks: "{{ activity }}.yaml"
      when: activity is defined

- The specified ``play`` contains ``tasks`` to execute. Example: play=``create_hub_edge_security_inbound.yaml``

1) Create Identity Provider
==================================================
Create and launch a workflow template ``wf-okta-create_IdP`` that includes those Job templates in this order:

=============================================================   =============================================       =============================================   =============================================   =============================================   =============================================   =============================================
Job template                                                    objective                                           playbook                                        activity                                        inventory                                       limit                                           credential
=============================================================   =============================================       =============================================   =============================================   =============================================   =============================================   =============================================
``poc-okta-create_group``                                       Create a user group                                 ``playbooks/poc-okta.yaml``                    ``create_group``                                 localhost                                       localhost
``poc-okta-create_user``                                        Create a user                                       ``playbooks/poc-okta.yaml``                    ``create_user``                                  localhost                                       localhost
``poc-okta-create_app``                                         Create an application for each infra product        ``playbooks/poc-okta.yaml``                    ``create_app``                                   localhost                                       localhost
``poc-okta-create_auth_server``                                 Create an authorization server                      ``playbooks/poc-okta.yaml``                    ``create_auth_server``                           localhost                                       localhost
``poc-consul_agnostic_api-register_idp_info``                   Save info in Key/Value store                        ``playbooks/poc-consul.yaml``                  ``register_idp_info``                            localhost                                       localhost
=============================================================   =============================================       =============================================   =============================================   =============================================   =============================================   =============================================

==============================================  =============================================   ================================================================================================================================================================================================================
Extra variable                                  Description                                     Example
==============================================  =============================================   ================================================================================================================================================================================================================
``extra_okta``                                  dict with properties regarding Okta
``extra_okta.organization``                     domain (see § Pre-requisites)                   ``dev-431905``
``extra_okta.api_key``                          API key (see § Pre-requisites)
``extra_okta.group_name``                       user group                                      ``iac_api_consumers``
``extra_okta.user``                             dict with user properties
``extra_okta.user.name``                        user name                                       ``orchestrator``
``extra_okta.user.login``                       user login                                      ``orchestrator@acme.com``
``extra_okta.user.password``                    user password                                   ``pwn3dPassw0rd!``
``extra_okta.app``                              dict with app properties
``extra_okta.app.name``                         infra product. Example: F5, PAN...              ``f5-bigip-api.f5app.dev``
``extra_okta.auth_server``                      dict with authorization server properties
``extra_okta.auth_server.name``                 server name                                     ``agnostic-api``
``extra_okta.auth_server.audience``             short name that specifies auth server           ``agnostic``
``extra_okta.auth_server.scopes``               list of allowed scopes                          ``['read:f5_bigip', ...]``
``extra_okta.auth_server.claims``               list of claims
``extra_okta.auth_server.claims.X.name``        authorized access value to an infra perimeter   ``f5_bigip``
``extra_okta.auth_server.claims.X.scopes``      list of scopes authorized to have this claim    ``['read:f5_bigip', ...]``
``extra_consul``                                dict with properties regarding Consul
``extra_consul.agent_scheme``                   scheme to access consul server                  ``http``
``extra_consul.agent_ip``                       one consul server IP                            ``10.100.0.60``
``extra_consul.agent_port``                     TCP port of REST API                            ``8500``
``extra_consul.datacenter``                     tenant                                          ``demoLab``
``extra_consul.path_source_of_truth``           top level Key to store info                     ``agnostic_api``
==============================================  =============================================   ================================================================================================================================================================================================================

.. code:: yaml

    extra_okta:
      organization: dev-431905
      api_key: XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
      group_name: iac_api_consumers
      user:
        name: orchestrator
        login: orchestrator@acme.com
        password: pwn3dPassw0rd!
      app:
        name: f5-bigip-api.f5app.dev
      auth_server:
        name: agnostic-api
        audience: agnostic
        scopes:
          - read:f5_bigip
          - write:f5_bigip
          - read:pan_ngfw
          - write:pan_ngfw
        claims:
          - name: f5_bigip
            scopes:
            - read:f5_bigip
            - write:f5_bigip
          - name: pan_ngfw
            scopes:
            - read:pan_ngfw
            - write:pan_ngfw
    extra_consul:
      agent_scheme: http
      agent_ip: 10.100.0.60
      agent_port: 8500
      datacenter: demoLab
      path_source_of_truth: agnostic_api

Troubleshoot
==================================================
Test oAuth configuration:

:kbd:`Okta >> API >> Authorization servers >> MyServer >> Token preview`

:kbd:`https://oidcdebugger.com`


Reference
==================================================
- `oAuth OpenID Connect test tool <https://oidcdebugger.com/>`_
- `WAF policies repository <https://github.com/nergalex/f5-nap-policies>`_
