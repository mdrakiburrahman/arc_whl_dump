# ------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for
# license information.
# ------------------------------------------------------------------------------

from knack.help_files import helps

helps[
    "arcdata ad-connector"
] = """
    type: group
    short-summary: {short}
""".format(
    short="Manage Active Directory authentication for Azure Arc data services."
)

helps[
    "arcdata ad-connector create"
] = """
    type: command
    short-summary: {short}
    examples:
        - name: {ex1}
          text: >
            az arcdata ad-connector create 
            --name arcadc 
            --k8s-namespace arc 
            --realm CONTOSO.LOCAL 
            --primary-ad-dc-hostname azdc01.contoso.local 
            --secondary-ad-dc-hostname "azdc02.contoso.local, azdc03.contoso.local" 
            --netbios-domain-name CONTOSO 
            --dns-domain-name contoso.local 
            --nameserver-addresses 10.10.10.11,10.10.10.12,10.10.10.13 
            --dns-replicas 2 
            --prefer-k8s-dns false 
            --use-k8s
""".format(
    short="Create a new Active Directory connector.",
    ex1="Ex 1 - Deploy a new Active Directory connector in indirect mode.",
)

helps[
    "arcdata ad-connector update"
] = """
    type: command
    short-summary: {short}
    examples:
        - name: {ex1}
          text: >
            az arcdata ad-connector update 
            --name arcadc 
            --k8s-namespace arc 
            --primary-ad-dc-hostname azdc01.contoso.local
            --secondary-ad-dc-hostname "azdc02.contoso.local, azdc03.contoso.local" 
            --nameserver-addresses 10.10.10.11,10.10.10.12,10.10.10.13
            --dns-replicas 2 
            --prefer-k8s-dns false 
            --use-k8s
""".format(
    short="Update the settings of an existing Active Directory connector.",
    ex1="Ex 1 - Update an existing Active Directory connector in indirect mode.",
)

helps[
    "arcdata ad-connector delete"
] = """
    type: command
    short-summary: {short}
    examples:
        - name: {ex1}
          text: >
            az arcdata ad-connector delete 
            --name arcadc 
            --k8s-namespace arc 
            --use-k8s
""".format(
    short="Delete an existing Active Directory connector.",
    ex1="Ex 1 - Delete an existing Active Directory connector in indirect mode.",
)

helps[
    "arcdata ad-connector show"
] = """
    type: command
    short-summary: {short}
    examples:
        - name: {ex1}
          text: >
            az arcdata ad-connector show 
            --name arcadc 
            --k8s-namespace arc 
            --use-k8s
""".format(
    short="Get the details of an existing Active Directory connector.",
    ex1="Ex 1 - Get an existing Active Directory connector in indirect mode.",
)
