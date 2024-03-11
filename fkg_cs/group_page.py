import pprint

from fkg_cs.cve_json_controller import get_technique_risk_scores
from mitreattack.stix20 import MitreAttackData

def get_group_info(external_id):
    output_list = dict()
    mitre_attack_enterprise_data = MitreAttackData(
        r"C:\Users\franc\Desktop\mitrepy\mitreattack-python\fkg_cs\json\json_matrix\enterprise-attack.json")
    mitre_attack_ics_data = MitreAttackData(
        r"C:\Users\franc\Desktop\mitrepy\mitreattack-python\fkg_cs\json\json_matrix\ics-attack.json")
    mitre_attack_mobile_data = MitreAttackData(
        r"C:\Users\franc\Desktop\mitrepy\mitreattack-python\fkg_cs\json\json_matrix\mobile-attack.json")
    output_list["external_id"] = external_id
    group=mitre_attack_enterprise_data.get_object_by_attack_id(external_id, "intrusion-set")
    group_stix_id=group.id
    output_list["external_id"] = external_id
    output_list["name"] = group.name
    output_list["description"] = group.description
    output_list["alias_intestation"] = f"{group.name} has {len(group.aliases)} aliases."
    output_list["aliases"] = group.aliases

    # gestione campagne enterprise
    group_enterprise_campaigns=mitre_attack_enterprise_data.get_campaigns_attributed_to_group(group_stix_id)
    output_list["n_enterprise_campaigns"] = len(group_enterprise_campaigns)

    if len(group_enterprise_campaigns) > 0:
        output_list["enterprise_campaigns_intestation"]= f"There are {len(group_enterprise_campaigns)} ENTERPRISE campaigns attributed to {output_list['name']} group:"
    else:
        output_list["enterprise_campaigns_intestation"] = f"There are no ENTERPRISE campaigns attributed to {output_list['name']} group."

    output_list["enterprise_campaigns"] = []
    for campaign in group_enterprise_campaigns:
        my_campaign = dict()
        my_campaign["external_id"] = campaign['object']['external_references'][0]['external_id']
        my_campaign["name"] = campaign['object']['name']
        my_campaign["description"] = campaign['object']['description']
        output_list["enterprise_campaigns"].append(my_campaign)

    # gestione campagne ics
    group_ics_campaigns = mitre_attack_ics_data.get_campaigns_attributed_to_group(group_stix_id)
    output_list["n_ics_campaigns"] = len(group_ics_campaigns)
    if len(group_enterprise_campaigns) > 0:
            output_list["ics_campaigns_intestation"] = f"There are {len(group_enterprise_campaigns)} ICS campaigns attributed to {output_list['name']} group:"
    else:
            output_list["ics_campaigns_intestation"] = f"There are no ICS campaigns attributed to {output_list['name']} group."

    output_list["ics_campaigns"] = []
    for campaign in group_ics_campaigns:
        my_campaign = dict()
        my_campaign["external_id"] = campaign['object']['external_references'][0]['external_id']
        my_campaign["name"] = campaign['object']['name']
        my_campaign["description"] = campaign['object']['description']
        output_list["ics_campaigns"].append(my_campaign)

    # gestione campagne mobile
    group_mobile_campaigns = mitre_attack_mobile_data.get_campaigns_attributed_to_group(group_stix_id)
    output_list["n_mobile_campaigns"] = len(group_mobile_campaigns)
    if len(group_mobile_campaigns) > 0:
            output_list["mobile_campaigns_intestation"] = f"There are {len(group_mobile_campaigns)} MOBILE campaigns attributed to {output_list['name']} group:"
    else:
            output_list["mobile_campaigns_intestation"] = f"There are no MOBILE campaigns attributed to {output_list['name']} group."

    output_list["mobile_campaigns"] = []
    for campaign in group_mobile_campaigns:
            my_campaign = dict()
            my_campaign["external_id"] = campaign['object']['external_references'][0]['external_id']
            my_campaign["name"] = campaign['object']['name']
            my_campaign["description"] = campaign['object']['description']
            output_list["mobile_campaigns"].append(my_campaign)


    # gestione tecniche usate in campagne enterprise
    techniques_used_by_group = mitre_attack_enterprise_data.get_techniques_used_by_group(group_stix_id)
    if len(techniques_used_by_group) > 0:
        output_list[
            "enterprise_techniques_intestation"] = f"There are {len(techniques_used_by_group)} ENTERPRISE techniques used by {output_list['name']} group:"
    else:
        output_list[
            "enterprise_techniques_intestation"] = f"There are no ENTERPRISE techniques reported to be used by {output_list['name']} group."

    output_list["enterprise_techniques"] = []
    for technique in techniques_used_by_group:
        my_technique = dict()
        my_technique["external_id"] = technique['object']['external_references'][0]['external_id']
        my_technique["name"] = technique['object']['name']
        my_technique["description"] = technique['object']['description']
        output_list["enterprise_techniques"].append(my_technique)

    # gestione tecniche usate in campagne ics
    techniques_used_by_group = mitre_attack_ics_data.get_techniques_used_by_group(group_stix_id)
    if len(techniques_used_by_group) > 0:
        output_list["ics_techniques_intestation"]=f"There are {len(techniques_used_by_group)} ICS techniques used by {output_list['name']} group:"
    else:
        output_list["ics_techniques_intestation"] = f"There are no ICS techniques reported to be used by {output_list['name']} group."

    output_list["ics_techniques"]=[]
    for technique in techniques_used_by_group:
        my_technique = dict()
        my_technique["external_id"]= technique['object']['external_references'][0]['external_id']
        my_technique["name"] = technique['object']['name']
        my_technique["description"] = technique['object']['description']
        output_list["ics_techniques"].append(my_technique)

    # gestione tecniche usate in campagne mobile
    techniques_used_by_group = mitre_attack_mobile_data.get_techniques_used_by_group(group_stix_id)
    if len(techniques_used_by_group) > 0:
        output_list["mobile_techniques_intestation"] = f"There are {len(techniques_used_by_group)} MOBILE techniques used by {output_list['name']} group:"
    else:
        output_list["mobile_techniques_intestation"] = f"There are no MOBILE techniques reported to be used by {output_list['name']} group."

    output_list["mobile_techniques"] = []
    for technique in techniques_used_by_group:
        my_technique = dict()
        my_technique["external_id"] = technique['object']['external_references'][0]['external_id']
        my_technique["name"] = technique['object']['name']
        my_technique["description"] = technique['object']['description']
        output_list["mobile_techniques"].append(my_technique)

#gestione software usati da gruppi in campagne enterprise
    softwares_used_by_group = mitre_attack_enterprise_data.get_software_used_by_group(group_stix_id)
    if len(softwares_used_by_group) > 0:
        output_list["enterprise_software_intestation"] = f"There are {len(softwares_used_by_group)} software used by {output_list['name']} group in enterprise context:"
    else:
        output_list[
            "enterprise_software_intestation"] = f"There are no software known to be used by {output_list['name']} group in enterprise context."

    output_list["enterprise_software"] = []
    for software in softwares_used_by_group:
        my_software = dict()
        my_software["external_id"] = software['object']['external_references'][0]['external_id']
        my_software["name"] = software['object']['name']
        my_software["description"] = software['object']['description']
        output_list["enterprise_software"].append(my_software)

#gestione software usati da gruppi in campagne ics
    softwares_used_by_group = mitre_attack_ics_data.get_software_used_by_group(group_stix_id)
    if len(softwares_used_by_group) > 0:
        output_list["ics_software_intestation"] = f"There are {len(softwares_used_by_group)} software used by {output_list['name']} group in ICS context:"
    else:
        output_list["ics_software_intestation"] = f"There are no software known to be used by {output_list['name']} group in enterprise context."

    output_list["ics_software"] = []
    for software in softwares_used_by_group:
        my_software = dict()
        my_software["external_id"] = software['object']['external_references'][0]['external_id']
        my_software["name"] = software['object']['name']
        my_software["description"] = software['object']['description']
        output_list["ics_software"].append(my_software)

#gestione software usati da gruppi in campagne enterprise
    softwares_used_by_group = mitre_attack_mobile_data.get_software_used_by_group(group_stix_id)
    if len(softwares_used_by_group) > 0:
        output_list["mobile_software_intestation"] = f"There are {len(softwares_used_by_group)} software used by {output_list['name']} group in mobile context:"
    else:
        output_list["mobile_software_intestation"] = f"There are no software known to be used by {output_list['name']} group in mobile context."

    output_list["mobile_software"] = []
    for software in softwares_used_by_group:
        my_software = dict()
        my_software["external_id"] = software['object']['external_references'][0]['external_id']
        my_software["name"] = software['object']['name']
        my_software["description"] = software['object']['description']
        output_list["mobile_software"].append(my_software)


    pprint.pprint(output_list)
    return output_list

if __name__ == "__main__":
    get_group_info("G1006")
