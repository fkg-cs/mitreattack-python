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
    #groups = (mitre_attack_enterprise_data.get_groups(remove_revoked_deprecated=True) +
                  #mitre_attack_ics_data.get_groups(remove_revoked_deprecated=True) +
                  #mitre_attack_mobile_data.get_groups(remove_revoked_deprecated=True))

   # for group in groups:
        #group_external_id = group["external_references"][0].get("external_id")
        #if group_external_id == external_id:
            #pprint.pprint(group)
            #group_stix_id=group.id
            #output_list["external_id"] = external_id
            #output_list["name"] = group.name
            #output_list["description"] = group.description
            #output_list["alias_intestation"] = f"{group.name} has {len(group.aliases)} aliases."
            #output_list["aliases"] = group.aliases
            #break
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

    #gestione tecniche usate










    pprint.pprint(output_list)
    return output_list

if __name__ == "__main__":
    get_group_info("G1006")
