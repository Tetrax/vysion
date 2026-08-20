# Vysion 2.7 — Restauration de la restitution V1

## Objectif

Vysion 2.7 conserve le moteur V2, le parser FortiOS, le registry, les `control_id` et les statuts internes. Elle restaure l'expérience client V1 dans la GUI et les exports.

## Restitution SD-WAN

Le preview expose toutes les zones SD-WAN déclarées, même sans membre ou avec une preuve incomplète :

- `sdwan_zones`: nom, membres observés et `proof_state` ;
- `sdwan_members`: interface membre et zones associées ;
- zone vide conservée avec `Aucun membre observé` côté GUI ;
- la sélection WAN n'est pas réduite à la zone actuellement résolue.

## Restitution métier

- `control_id` reste interne au moteur ;
- `display_name` porte le titre métier V1 ;
- le DOCX suit l'ordre documentaire V1 numéroté `3.1` à `3.7` ;
- le VPN SSL reste visible lorsqu'il est non applicable ;
- les résultats utilisent `CONFORME`, `NON CONFORME`, `À VÉRIFIER` et `NON APPLICABLE` selon la logique V1 ;
- les risques R1/R2/R3 suivent l'ordre documentaire, pas l'ordre du registry.

## Modèle DOCX

Le renderer réutilise le template V1 fourni :

- garde, identité SNS, confidentialité, headers, footers et pagination préservés ;
- placeholder `LOGO CLIENT si existe` conservé sans logo ;
- insertion possible d'un logo client lorsqu'un chemin est fourni au renderer ;
- schéma HA `cluster.png` ;
- illustration CTI `cti.png` ;
- illustration ISDB `isdb.png` ;
- schéma profils de sécurité `security_profiles.png` ;
- tableau `Profil de sécurité | Flux entrant | Flux sortant`.

## Comparaison V1/V2

- 57 points métier V1 présentés ;
- 60 contrôles moteur V2 conservés ;
- 3 sous-vérifications issues des splits V1 ;
- 4 contrôles V2-only séparés ;
- matrice XLSX `Matrice V1-V2` conservée pour les comparaisons entre audits.

## Validation 2.7

- Backend : `814 passed` ;
- Ruff : OK ;
- Frontend : `12 passed` ;
- ESLint et build : OK ;
- image candidate : `vysion:v2.7-restoration-check` ;
- smoke HTTP isolé : `2.7.0`, `running|healthy|restarts=0` ;
- configuration réelle : `FW-AVR-01_7-2_1639_202608121044.conf` ;
- zones vérifiées : `virtual-wan-link`, `Z-INTERSITE`, `Z-INTERNET` ;
- relation vérifiée : `Z-INTERSITE → Interco_MPLS` ;
- DOCX package : valide ;
- DOCX : 4 schémas métier, aucun `control_id` ni vocabulaire interne interdit ;
- XLSX : quatre feuilles, matrice de 61 lignes de données ;
- production : non modifiée et non déployée depuis ce candidat.

## Limite volontaire

La validation multi-configurations reste ouverte. Chaque nouvel écart terrain doit être ajouté au corpus différentiel et couvert par un test de non-régression avant toute nouvelle release.
