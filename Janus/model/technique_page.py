import pprint

from Janus.model.cve_json_controller import get_technique_risk_scores
from mitreattack.stix20 import MitreAttackData

def get_technique_info(id):
    output_list = dict()
    n_subtechniques = 0
    mitre_attack_enterprise_data = MitreAttackData(r"../Janus/json/json_matrix/enterprise-attack.json")
    mitre_attack_ics_data = MitreAttackData(r"../Janus/json/json_matrix/ics-attack.json")
    mitre_attack_mobile_data = MitreAttackData(r"../Janus/json/json_matrix/mobile-attack.json")
    output_list["external_id"] = id
    output_list["mitigations"] = []

    technique=mitre_attack_enterprise_data.get_object_by_attack_id(id, "attack-pattern")

    if technique is None:
        technique = mitre_attack_ics_data.get_object_by_attack_id(id, "attack-pattern")
    elif technique is None:
        technique = mitre_attack_mobile_data.get_object_by_attack_id(id, "attack-pattern")

    output_list["name"] = technique.name
    output_list["external_id"] = id
    output_list["description"] = technique.description
    output_list["platforms"] = technique.x_mitre_platforms
    output_list["creation_date"] = f"{technique.created}"[:10]#ottengo solo mese-giorno-anno e taglio timestamp
    output_list["risk_scores"] = get_technique_risk_scores(technique.name+' '+technique.description)
    technique_stix_id=technique.id

    if hasattr(technique, 'x_mitre_detection'):
        output_list["detection"] = technique.x_mitre_detection
        if output_list["detection"] == '':
            output_list["detection"] = f"There are no detection methods known for {technique.name}"
    else:
        output_list["detection"] = f"There are no detection methods known for {technique.name}"

    output_list["subtechniques"] = []
    subs=[]
    #devo conntrollare il dominio e prendere le sottotecniche solo del dominio o sanificare qualcosa
    print(f"------------------>sto controllando il domain per le sottotecniche: {technique.x_mitre_domains}")
    if technique.x_mitre_domains[0] == 'enterprise-attack':
        subs = mitre_attack_enterprise_data.get_subtechniques_of_technique(technique_stix_id)
    if technique.x_mitre_domains[0]== 'ics-attack':
        subs = mitre_attack_ics_data.get_subtechniques_of_technique(technique_stix_id)
    if technique.x_mitre_domains[0]== 'moblile-attack':
        subs = mitre_attack_mobile_data.get_subtechniques_of_technique(technique_stix_id)
    print(f"----------->stocontrollando len di sub: {len(subs)}")
    if len(subs) >= 1:
        output_list["subtechniques_intestation"] = f"There are {len(subs)} subtechniques related to {technique.name} techinique:"
        for s in subs:
                my_subtechnique = dict()
                sub = s["object"]  # casto in oggetto
                my_subtechnique["name"] = sub.name
                #controllo in che dominio devo cercare l'external id
                if technique.x_mitre_domains[0] == 'enterprise-attack':
                    my_subtechnique["external_id"] = mitre_attack_enterprise_data.get_attack_id(sub.id)

                if technique.x_mitre_domains[0] == 'moblile-attack':
                    my_subtechnique["external_id"] = mitre_attack_ics_data.get_attack_id(sub.id)

                if technique.x_mitre_domains[0] == 'ics-attack':
                    my_subtechnique["external_id"] = mitre_attack_mobile_data.get_attack_id(sub.id)

                my_subtechnique["description"] = sub.description
                output_list["subtechniques"].append(my_subtechnique)

    mitigations_of_technique = (
                    mitre_attack_enterprise_data.get_mitigations_mitigating_technique(technique_stix_id) +
                    mitre_attack_ics_data.get_mitigations_mitigating_technique(technique_stix_id) +
                    mitre_attack_mobile_data.get_mitigations_mitigating_technique(technique_stix_id)
            )

    if len(mitigations_of_technique) >= 1:
        output_list["mitigations_intestation"] = f"There are {len(mitigations_of_technique)} mitigations mitigating {technique.name} technique:"
        # popolo mitigazioni
        for mitigation in mitigations_of_technique:
            my_mitigation = dict()
            my_mitigation["name"] = mitigation["object"]["name"]
            my_mitigation["description"] = mitigation["object"]["description"]
            my_mitigation["external_id"] = mitigation['object']['external_references'][0]['external_id']

            output_list["mitigations"].append(my_mitigation)
    else:
        output_list["mitigations_intestation"] = f"There are no mitigations known mitigating {technique.name}."
    #gestione campagne
    output_list["campaigns"]=[]
    campaigns_enterprise_using_technique = mitre_attack_enterprise_data.get_campaigns_using_technique(technique_stix_id)
    campaigns_ics_using_technique = mitre_attack_ics_data.get_campaigns_using_technique(technique_stix_id)
    campaigns_mobile_using_technique = mitre_attack_mobile_data.get_campaigns_using_technique(technique_stix_id)
    campaigns_using_technique= campaigns_enterprise_using_technique + campaigns_ics_using_technique +  campaigns_mobile_using_technique
    #pprint.pprint(campaigns_using_technique)
    output_list["campaign_intestation"] =f"{technique.name} was reported to be used in {len(campaigns_using_technique)} campaigns: {len(campaigns_enterprise_using_technique)} ENTERPRISE,{len(campaigns_ics_using_technique)} ICS,{len(campaigns_mobile_using_technique)} MOBILE."
    output_list["n_enterprise_campaigns"]= len(campaigns_enterprise_using_technique)
    output_list["n_ics_campaigns"] = len(campaigns_ics_using_technique)
    output_list["n_mobile_campaigns"] = len(campaigns_mobile_using_technique)
    for campaign in campaigns_using_technique:
        my_campaign = dict()
        my_campaign["external_id"] = campaign['object']['external_references'][0]['external_id']
        my_campaign["name"] = campaign['object']['name']
        my_campaign["description"] = campaign['object']['description']

        output_list["campaigns"].append(my_campaign)

            #break

    pprint.pprint(output_list)
    return output_list

if __name__ == "__main__":
    get_technique_info("T1418")
