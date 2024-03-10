from mitreattack.stix20 import MitreAttackData
import pprint


def main():
    mitre_attack_data = MitreAttackData("../json/json_matrix/ics-attack.json")

    # ottengo tutti i gruppi a cui sono state attribuite tutte le campagne
    groups_attributing = mitre_attack_data.get_all_groups_attributing_to_all_campaigns()
    # ottengo tutte le campagne ics
    campaigns = mitre_attack_data.get_campaigns(remove_revoked_deprecated=True)
    # pprint.pprint(campaigns)#stampa per vedere struttrura oggetto

    # valori default campagna
    campaing_name = 'campaign name'
    campaign_external_id = 'CXXXXX'

    print(f"Retrived {len(groups_attributing.keys())} ICS campaigns attributed to groups:")
    i = 0
    # metodo ricerca mitre id tra tutti i
    for id, groups in groups_attributing.items():
        i = i + 1
        # ciclo recupero informazioni della campagna, recupero nome e id esterno mitre
        for campaign in campaigns:
            if campaign['id'] == id:
                campaign_name = campaign['name']
                campaign_external_id = campaign.external_references[0].external_id

        print(
            f"{i}) Campain '{campaign_name}' (ATT&CK CAMPAING ID: {campaign_external_id} ) was attributed to {len(groups)} {'group' if len(groups) == 1 else 'groups'} :")

        # pprint.pprint(groups)#stampa debug
        j = 0
        for group in groups:
            j = j + 1
            external_group_id = group['object'].external_references[0].external_id
            print(f"   {j}) {group['object'].name} (ATT&CK GROUP ID: {external_group_id})")


if __name__ == "__main__":
    main()
