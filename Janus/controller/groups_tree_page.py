import pprint

from mitreattack.stix20 import MitreAttackData


def get_groups_list():
    output_list = dict()
    n_enterprise_groups = 0
    n_ics_groups = 0
    n_mobile_groups = 0
    mitre_attack_data = MitreAttackData(r"../Janus/json/json_matrix/enterprise-attack.json")
    groups = mitre_attack_data.get_groups(remove_revoked_deprecated=True)
    n_enterprise_groups = len(groups)

    # popolo gruppi enterprise
    output_list["enterprise_groups"] = []
    enterprise_groups = []
    for group in groups:
        # print(f"print group:{group}")
        group_element = dict()
        group_element["external_id"] = group['external_references'][0]['external_id']
        group_element["name"] = group.name
        group_element["description"] = group.description
        group_element["alias_intestation"] = f"{group.name} has {len(group.aliases)} aliases."
        group_element["aliases"] = group.aliases
        enterprise_groups.append(group_element)
    output_list["enterprise_groups"] = enterprise_groups

    # popolo gruppi ics
    mitre_attack_data = MitreAttackData(r"../Janus/json/json_matrix/ics-attack.json")
    groups = mitre_attack_data.get_groups(remove_revoked_deprecated=True)
    n_ics_groups = len(groups)
    output_list["ics_groups"] = []
    ics_groups = []
    for group in groups:
        group_element = dict()
        group_element["external_id"] = group['external_references'][0]['external_id']
        group_element["name"] = group.name
        group_element["description"] = group.description
        group_element["alias_intestation"] = f"{group.name} has {len(group.aliases)} aliases."
        group_element["aliases"] = group.aliases
        ics_groups.append(group_element)
    output_list["ics_groups"] = ics_groups

    # popolo gruppi mobile
    mitre_attack_data = MitreAttackData(r"../Janus/json/json_matrix/mobile-attack.json")
    groups = mitre_attack_data.get_groups(remove_revoked_deprecated=True)
    n_mobile_groups = len(groups)
    output_list["mobile_groups"] = []
    mobile_groups = []
    for group in groups:
        group_element = dict()
        group_element["external_id"] = group['external_references'][0]['external_id']
        group_element["name"] = group.name
        group_element["description"] = group.description
        group_element["alias_intestation"] = f"{group.name} has {len(group.aliases)} aliases."
        group_element["aliases"] = group.aliases
        mobile_groups.append(group_element)
    output_list["mobile_groups"] = mobile_groups

    print(f"Retrieved {n_enterprise_groups + n_ics_groups + n_mobile_groups} ATT&CK groups: ENTERPRISE [{n_enterprise_groups}], ICS[{n_ics_groups}] , MOBILE [{n_mobile_groups}].")
    output_list["report"] = f"Retrieved {n_enterprise_groups + n_ics_groups + n_mobile_groups} ATT&CK groups:  {n_enterprise_groups} operating in ENTERPRISE context , {n_ics_groups} operating in ICS context, {n_mobile_groups} operating in  MOBILE context."
    pprint.pprint(output_list)
    return output_list


if __name__ == "__main__":
    get_groups_list()
