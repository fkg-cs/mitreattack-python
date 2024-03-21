from mitreattack.stix20.MitreAttackData import MitreAttackData


def main():
    mitre_attack_data = MitreAttackData("../Janus/json/json_matrix/mobile-attack.json")
    groups = mitre_attack_data.get_groups(remove_revoked_deprecated=True)
    n_aliases = 0

    print(f"----- TREE OF GROUPS MOBILE ALIASES -----")
    print(f"Retrieved {len(groups)} ATT&CK groups.")

    i = 0
    for group in groups:
        i = i + 1
        print(f"{i}) GROUP: {group.description}")
        print(f"This group has {len(group.aliases)} alias:")

        n_aliases = n_aliases + len(group.aliases)  # aggiorno totale degli alias trovati
        i_alias = 0
        for alias in group.aliases:
            i_alias = i_alias + 1
            print(f"   {i_alias}) {alias}")

    print(f"\n --> REPORT: {len(groups)} GROUP FOUND , {n_aliases} ALIASES FOUND <--\n")


if __name__ == "__main__":
    main()
