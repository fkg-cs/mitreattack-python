from mitreattack.stix20 import MitreAttackData


def main():
    mitre_attack_data = MitreAttackData("../Janus/json/json_matrix/mobile-attack.json")
    # ottengo tutte le campagne enterprise
    campaigns = mitre_attack_data.get_campaigns(remove_revoked_deprecated=True)
    i_campaign=0
    n_campaigns=len(campaigns)
    n_techniques=0

    print("--------- TREE OF CAMPAIGNS MOBILE AND USED TECHNIQUES ---------")
    for campaign in campaigns:
        i_campaign=i_campaign+1
        # id campagna su cui iterare
        campaign_stix_id=campaign.id
        techniques_used_by_campaign = mitre_attack_data.get_techniques_used_by_campaign(campaign_stix_id)

        n_techniques=n_techniques+len(techniques_used_by_campaign)#aggiorno totale tecniche recueprate

        print(f"{i_campaign}) Campaign '{campaign['name']}' has used {len(techniques_used_by_campaign)} techniques:")

        i_technique=0#azzero contatore tecniche per ogni campagna
        for technique in techniques_used_by_campaign:
            i_technique=i_technique+1
            #siccome questa volta il metodo restituisce un dizionario e non una semplice lista devo castare in oggetto
            technique_object=technique['object']
            print(f"        {i_technique}) {technique_object.name} (TECHNIQUE ATT&CK ID:{mitre_attack_data.get_attack_id(technique_object.id)}): {technique_object.description}\n")

    print(f"\n --> REPORT: RETRIVED CAMPAIGNS: {n_campaigns} , TECHNIQUES RETRIVED: {n_techniques} <--\n")

if __name__ == "__main__":
    main()
