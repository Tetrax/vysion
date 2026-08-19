from __future__ import annotations

import re
from dataclasses import dataclass

from vysion.audit.models import AuditFinding, AuditStatus, RiskAssessment


@dataclass(frozen=True, slots=True)
class BusinessText:
    """Client-facing prose for one audit point.

    The point text is deliberately independent from the control implementation.
    When a historical V1 equivalent exists, its wording and risk scale are kept
    here; the finding still supplies the live result and detected values.
    """

    point: str
    risk_point: str | None = None
    risk_description: str | None = None
    likelihood: str | None = None
    impact: str | None = None
    correction: str | None = None
    remediation: str | None = None


_V1_OBJECTS_POINT = (
    "Vérification d'objet sans référence. L'absence d'objet sans référence permet de "
    "réduire la surface d'exposition ou des risques d'erreur. Contrôle dans les "
    "adresses, groupes d'adresses, VIP, groupes de VIP, Virtuals Serveur, Zones, "
    "Utilisateurs, Groupes d'utilisateurs et profils de sécurité."
)
_V1_MFA_POINT = (
    "Vérification de la présence de double authentification (MFA) sur les comptes "
    "administrateurs et utilisateurs présents dans votre fichier de configuration. "
    "Les comptes distants non synchronisés ne sont pas contrôlés car le FortiGate ne "
    "peut pas gérer leur MFA."
)
_V1_WAN_ADMIN_POINT = (
    "Le point audité est la vérification que les services SSH, HTTP et HTTPS sur les "
    "interfaces WAN soient désactivés. En effet, l’accès au pare-feu depuis Internet "
    "est critique car un attaquant qui prend la main sur le pare-feu peut faire des "
    "dégâts considérables au sein des SI. Par défaut, les accès HTTP et HTTPS au "
    "pare-feu sont activés sur les liens WANs."
)
_V1_PORT_FILTER_POINT = (
    "Filtrage des ports au strict minimum pour les flux vers Internet. Pourquoi limiter "
    "les ports ouverts ? 1) Surface d’attaque réduite : plus il y a de ports ouverts, "
    "plus il y a de services accessibles et donc de points d'entrée potentiels pour les "
    "attaquants. Chaque port ouvert représente un service qui pourrait être exploité s'il "
    "est vulnérable ou mal configuré. 2) Moins de risques d’exploitation de vulnérabilités : "
    "des malwares et vers comme WannaCry attaquent des ports spécifiques (SMB/445 par "
    "exemple). 3) Limiter l’exposition des données : certains protocoles non chiffrés "
    "(ex. FTP) exposent les informations sensibles transitant sur le réseau."
)
_V1_ISDB_POINT = (
    "Les ISDB (Internet Service Database) sont des bases complètes d’adresses IP qui "
    "regroupent les plages d’adresses IP, les propriétaires d’IP, les numéros de ports "
    "de service ainsi que la crédibilité en matière de sécurité des adresses IP. Les "
    "données proviennent du système de services FortiGuard. Des informations y sont "
    "régulièrement ajoutées, telles que la localisation géographique, la réputation des "
    "adresses IP, leur popularité et les enregistrements DNS. Fortinet distingue des ISDB "
    "malveillants, qui peuvent être bloqués dans les deux directions (source et destination) "
    "pour certains."
)
_V1_GEO_POINT = (
    "FortiGuard a un service « GeoIP » qui est une base de données permettant d’identifier "
    "le pays d’origine d’une adresse IP. Cette base de données est régulièrement mise à "
    "jour afin d’assurer sa précision et sa pertinence. Ce service permet de filtrer les "
    "flux entrants de deux façons : autoriser uniquement certains pays considérés comme "
    "sources de confiance, ou bloquer d’office certains pays d’où proviennent fréquemment "
    "des attaques. Ce filtrage doit être utilisé avec prudence pour éviter de bloquer de "
    "manière inappropriée des utilisateurs légitimes ou des partenaires commerciaux."
)
_V1_CTI_POINT = (
    "L’utilisation de sources de Cyber Threat Intelligence (CTI) permet de renforcer "
    "significativement la protection du système d’information en élargissant le spectre "
    "de détection et de blocage. En complément des ISDB Fortinet, une CTI consolide les "
    "flux issus de plusieurs sources de cybersécurité et intègre des indicateurs tels que "
    "les adresses IP, les noms de domaine et les hachages de malwares. Cette approche "
    "réduit la surface d’exposition et améliore la capacité à anticiper, détecter et "
    "stopper les attaques avant qu’elles ne compromettent les infrastructures."
)
_V1_UTM_LICENSE_POINT = (
    "Vérification que la licence UTM est toujours valide. La licence UTM permet d'utiliser "
    "des profils de sécurité. Sans cette licence, le FortiGate ne peut pas accéder aux "
    "bases de données de FortiGuard lui permettant d’analyser les flux."
)


_BUSINESS_TEXT: dict[str, BusinessText] = {
    "SYS-HOSTNAME-001": BusinessText(
        "Vérification que le hostname est explicite et permet d'identifier sans ambiguïté "
        "l'équipement audité."
    ),
    "NET-WAN-MGMT-001": BusinessText(
        _V1_WAN_ADMIN_POINT,
        risk_point="Durcissement accès admin",
        risk_description="Tentatives d’accès non autorisées à votre FortiGate depuis Internet.",
        likelihood="VRAISEMBLABLE",
        impact="GRAVE",
        correction="SIMPLE",
        remediation=(
            "Désactiver les services SSH/HTTP/HTTPS sur toutes les interfaces et IP "
            "secondaires WAN. Utiliser une loopback à la place."
        ),
    ),
    "IAM-ADMIN-MFA-001": BusinessText(
        _V1_MFA_POINT,
        risk_point="MFA pour les comptes admins et users locaux",
        risk_description="Tentatives d’accès non autorisées à votre FortiGate, réseau et données.",
        likelihood="TRÈS VRAISEMBLABLE",
        impact="CRITIQUE",
        correction="SIMPLE",
        remediation="Utiliser de la MFA sur l'ensemble des comptes admins et users.",
    ),
    "IAM-LOCAL-USER-MFA-001": BusinessText(_V1_MFA_POINT),
    "IAM-DEFAULT-ADMIN-001": BusinessText(
        "Vérification si le compte 'Admin' par défaut a été supprimé. Les attaquants qui "
        "tentent d'accéder à un système commencent souvent par cibler les comptes par "
        "défaut bien connus, comme 'admin'.",
        risk_point="Compte 'admin' par défaut",
        risk_description=(
            "Le compte 'admin' par défaut facilite les accès non autorisés, compromettant "
            "la sécurité du FortiGate et du réseau."
        ),
        likelihood="VRAISEMBLABLE",
        impact="CRITIQUE",
        correction="SIMPLE",
        remediation="Supprimer le compte 'admin' par défaut.",
    ),
    "IAM-GUEST-ACCOUNT-001": BusinessText(
        "Vérification de l'absence du compte 'guest' par défaut, afin de limiter les "
        "identifiants connus pouvant être ciblés par des tentatives d'accès."
    ),
    "FW-IMPLICIT-DENY-LOG-001": BusinessText(
        "Activation des logs pour la règle 'implicit deny' afin d’assurer la journalisation "
        "des flux réseau bloqués par défaut. Ces logs donnent une visibilité essentielle "
        "sur les tentatives d’accès non autorisées. Par défaut, ils sont désactivés.",
        risk_point="Logs implicit deny",
        risk_description=(
            "Manque de visibilité sur les flux bloqués, réduisant la capacité à détecter "
            "rapidement les incidents de sécurité."
        ),
        likelihood="TRÈS VRAISEMBLABLE",
        impact="GRAVE",
        correction="SIMPLE",
        remediation="Activer les logs sur la règle implicit deny.",
    ),
    "FW-INTERNET-ALL-SERVICE-001": BusinessText(
        _V1_PORT_FILTER_POINT,
        risk_point="Filtrage des ports vers Internet",
        risk_description=(
            "Ouvrir trop de ports sur un pare-feu expose le réseau à des attaques, "
            "exploitations de vulnérabilités, intrusions non autorisées, propagation de "
            "malwares et rend la détection des menaces plus difficile."
        ),
        likelihood="TRÈS VRAISEMBLABLE",
        impact="SIGNIFICATIF",
        correction="RAISONNABLE",
        remediation="Filtrer les ports au minimum pour les flux à destination d'Internet.",
    ),
    "FW-UTM-PROFILE-BINDING-001": BusinessText(
        "Recherche de règles avec logs en UTM sans profils de sécurité activés. Les logs "
        "en UTM n'enregistrent que les flux qui correspondent aux profils de sécurité. "
        "Régler les logs en UTM sans configurer de profils revient donc à n'avoir aucun "
        "log de flux.",
        risk_point="Logs en UTM sans profil de sécurité",
        risk_description="Absence de traçabilité des actions et opérations.",
        likelihood="QUASI CERTAIN",
        impact="GRAVE",
        correction="SIMPLE",
        remediation=(
            "Effectuer une revue des réglages des logs et des profils de sécurité dans "
            "les règles concernées."
        ),
    ),
    "FW-VIP-EXTINTF-ANY-001": BusinessText(
        "Les VIP (Virtual IP) sont utilisées pour faire entrer du flux de l’extérieur vers "
        "l’interne à destination d'un serveur. Si les VIP sont en écoute sur 'ANY', le "
        "FortiGate peut appliquer un NAT non désiré et utiliser l’adresse de la VIP au lieu "
        "de l’adresse publique normale du WAN. Sauf cas particulier et mesuré, il est "
        "préférable de sélectionner une interface et d’éviter 'ANY'.",
        risk_point="Absence de VIP en ANY",
        risk_description="Dysfonctionnement du NAT sur le FortiGate.",
        likelihood="TRÈS VRAISEMBLABLE",
        impact="SIGNIFICATIF",
        correction="SIMPLE",
        remediation="Ne pas utiliser de ANY sur les VIP.",
    ),
    "FW-VSERVER-EXTINTF-ANY-001": BusinessText(
        "Les Virtual Servers sont utilisés pour faire entrer du flux de l’extérieur vers "
        "l’interne via un load balancer. Une écoute sur 'ANY' peut provoquer un NAT non "
        "désiré. Deux situations peuvent toutefois être acceptables : l’adresse IP externe "
        "est dans le même subnet que les real servers, ou plusieurs interfaces sont présentes "
        "dans les règles de pare-feu.",
        risk_point="Absence de Virtual Server en ANY",
        risk_description="Dysfonctionnement du NAT sur le FortiGate.",
        likelihood="TRÈS VRAISEMBLABLE",
        impact="SIGNIFICATIF",
        correction="SIMPLE",
        remediation="Éviter d'utiliser ANY en interface externe des Virtual Servers.",
    ),
    "FW-SENSITIVE-PROTOCOL-DENY-001": BusinessText(
        "Nous recommandons le blocage de certains ports pour les flux à destination "
        "d'Internet : KERBEROS, LDAP, LDAPS, RADIUS, SAMBA et SMB.",
        risk_point="Ports-Deny vers Internet",
        risk_description="Risque accru d'accès non autorisé et de compromission.",
        likelihood="TRÈS VRAISEMBLABLE",
        impact="GRAVE",
        correction="SIMPLE",
        remediation="Bloquer les ports recommandés par SNS.",
    ),
    "VPN-SSL-001": BusinessText("Contrôle de la non-utilisation du VPN SSL."),
    "VPN-IKEV2-001": BusinessText(
        "IKE (Internet Key Exchange) établit les Security Associations et les paramètres "
        "cryptographiques d'un tunnel IPsec. Deux versions coexistent : IKEv1 et IKEv2. "
        "Les référentiels de sécurité recommandent l’utilisation exclusive d’IKEv2, qui "
        "corrige des vulnérabilités connues dans IKEv1 et améliore la gestion des erreurs.",
        risk_point="Durcissement des VPN IPSEC : contrôle IKE",
        risk_description=(
            "L’utilisation d’IKEv1 expose à des vulnérabilités connues, notamment des "
            "attaques de type Man-in-the-Middle ou de déni de service."
        ),
        likelihood="TRÈS VRAISEMBLABLE",
        impact="GRAVE",
        correction="SIMPLE",
        remediation="Utiliser IKE V2.",
    ),
    "VPN-DH-001": BusinessText(
        "Le processus d’échange de clés est réalisé avec des groupes Diffie-Hellman. Les "
        "groupes numérotés plus élevés offrent une sécurité accrue, mais nécessitent davantage "
        "de temps. Nous recommandons d'utiliser au minimum le groupe 14, correspondant à une "
        "longueur de clé de 2048 bits.",
        risk_point="Durcissement des VPN IPSEC : contrôle DH Group",
        risk_description=(
            "L’utilisation d’un groupe Diffie-Hellman inférieur à 14 réduit considérablement "
            "la sécurité du tunnel et peut permettre de casser la clé échangée."
        ),
        likelihood="TRÈS VRAISEMBLABLE",
        impact="GRAVE",
        correction="SIMPLE",
        remediation="Utiliser au minimum le groupe DH 14.",
    ),
    "VPN-CRYPTO-001": BusinessText(
        "L’ESP (Encapsulating Security Payload) assure confidentialité, intégrité et "
        "authentification des données dans IPsec. DES, 3DES et MD5 sont obsolètes et ne "
        "doivent plus être utilisés. Nous recommandons AES256 pour le chiffrement et SHA256 "
        "pour l’intégrité.",
        risk_point="Durcissement des VPN IPSEC : contrôle des algorithmes",
        risk_description=(
            "L’utilisation d’algorithmes obsolètes comme DES, 3DES, MD5 ou SHA1 expose le "
            "tunnel à une compromission des échanges."
        ),
        likelihood="TRÈS VRAISEMBLABLE",
        impact="GRAVE",
        correction="SIMPLE",
        remediation="Utiliser au moins AES256 et SHA256 pour les algorithmes ESP.",
    ),
    "UTM-LICENSE-001": BusinessText(
        _V1_UTM_LICENSE_POINT,
        risk_point="Vérification de la licence UTM",
        risk_description=(
            "En cas de licence UTM expirée, une couche de sécurité précieuse est perdue, "
            "ce qui augmente le risque de compromission des réseaux et des données."
        ),
        likelihood="TRÈS VRAISEMBLABLE",
        impact="GRAVE",
        correction="RAISONNABLE",
        remediation="Commander une licence UTM auprès du service commercial SNS.",
    ),
    "UTM-AUTOUPDATE-001": BusinessText(
        "Vérification que les mises à jour automatiques des bases AV et IPS (FortiGuard) "
        "sont configurées sur 'automatic'. Ce réglage permet de recevoir plus rapidement "
        "les mises à jour critiques.",
        risk_point="Mises à jour FortiGuard",
        risk_description=(
            "Un retard dans la mise à jour des bases critiques provoque une baisse temporaire "
            "du niveau de sécurité du réseau."
        ),
        likelihood="TRÈS VRAISEMBLABLE",
        impact="GRAVE",
        correction="SIMPLE",
        remediation="Configurer les mises à jour FortiGuard sur 'Automatic'.",
    ),
    "UTM-DNSFILTER-001": BusinessText(
        "Vérification de l'utilisation de la fonction DNS Filter. Ce filtrage évalue les "
        "requêtes DNS selon les notations de domaine de FortiGuard, le filtrage CTI et le "
        "blocage de botnets connus. Il permet aussi de personnaliser le filtrage par "
        "catégories et de créer des listes de domaines ou d'IP à bloquer.",
        risk_point="Utilisation du DNS-Filter",
        risk_description="Risque de compromission.",
        likelihood="TRÈS VRAISEMBLABLE",
        impact="GRAVE",
        correction="RAISONNABLE",
        remediation="Utiliser le DNS Filter et le durcir conformément aux préconisations.",
    ),
    "UTM-WEBFILTER-001": BusinessText(
        "Vérification de l'utilisation de la fonction Web-filter. Les filtres Web "
        "contrôlent l'accès aux ressources web et distinguent notamment les catégories "
        "de contenu adulte, de consommation de bande passante et de risques pour la "
        "sécurité, comme les sites de phishing.",
        risk_point="Utilisation du Web-Filter",
        risk_description=(
            "Risque de compromission, notamment par des sites de phishing non bloqués, et "
            "risque de perte de performance par des sites consommateurs de bande passante."
        ),
        likelihood="TRÈS VRAISEMBLABLE",
        impact="GRAVE",
        correction="RAISONNABLE",
        remediation="Utiliser le Web-filter et le durcir conformément aux préconisations.",
    ),
    "UTM-ANTIVIRUS-001": BusinessText(
        "Vérification de l'utilisation de la fonction antivirus. L’antivirus de FortiGuard "
        "défend les SI contre les virus, logiciels espions et menaces polymorphes. Il "
        "inspecte le trafic transitant au travers du FortiGate et compare les signatures "
        "aux bases FortiGuard, avec la possibilité d'utiliser des bases CTI et l'analyse "
        "comportementale.",
        risk_point="Utilisation de l'Antivirus",
        risk_description="Risque de compromission par des virus.",
        likelihood="TRÈS VRAISEMBLABLE",
        impact="GRAVE",
        correction="RAISONNABLE",
        remediation=(
            "Utiliser l'antivirus de FortiGuard et le durcir conformément aux "
            "préconisations."
        ),
    ),
    "UTM-IPS-001": BusinessText(
        "Vérification de l'utilisation de la fonction IPS (système de prévention "
        "d'intrusion). Ce système détecte et bloque les attaques réseau au moyen de "
        "signatures, décodeurs de protocole, heuristique, intelligence des menaces et "
        "détection avancée, y compris contre des attaques zero-day.",
        risk_point="Utilisation de l'IPS",
        risk_description="Risque de compromission accru.",
        likelihood="TRÈS VRAISEMBLABLE",
        impact="GRAVE",
        correction="RAISONNABLE",
        remediation="Utiliser l'IPS et le durcir conformément aux préconisations.",
    ),
    "UTM-APPCONTROL-001": BusinessText(
        "Vérification de l'utilisation de la fonction Application Control. Ce profil "
        "permet de surveiller ou de bloquer des applications contraires à une politique "
        "de sécurité. Nous recommandons de bloquer au minimum les catégories Proxy, "
        "Remote.Access et P2P, avec des exceptions documentées si nécessaire.",
        risk_point="Utilisation de l'Application Control",
        risk_description="Risque de compromission accru.",
        likelihood="TRÈS VRAISEMBLABLE",
        impact="GRAVE",
        correction="RAISONNABLE",
        remediation=(
            "Utiliser l'Application Control et bloquer au moins les catégories Proxy, "
            "Remote.Access et P2P."
        ),
    ),
    "IAM-LDAPS-001": BusinessText(
        "Utilisation du LDAPS avec certificat pour les connecteurs AD. Le LDAPS chiffre "
        "les données et offre une protection accrue contre les interceptions malveillantes."
    ),
    "EXT-PSIRT-001": BusinessText(
        "Vérification de la version du firmware FortiOS installée sur le FortiGate afin "
        "de détecter la présence de vulnérabilités hautes ou critiques connues pouvant "
        "compromettre la sécurité du système.",
        risk_point="Version FortiOS vulnérable",
        risk_description=(
            "La version de FortiOS actuelle présente des vulnérabilités hautes et/ou "
            "critiques connues qui peuvent être exploitées pour compromettre la sécurité "
            "du système, entraînant des accès non autorisés ou des interruptions de service."
        ),
        likelihood="TRÈS VRAISEMBLABLE",
        impact="CRITIQUE",
        correction="SIMPLE",
        remediation="Mettre à jour la version FortiOS avec le dernier patch sécuritaire.",
    ),
    "SYS-BACKUP-AUTO-001": BusinessText(
        "Vérification que les options 'set revision-backup-on-logout' et "
        "'set revision-image-auto-backup' sont activées. Elles permettent la création "
        "automatique de sauvegardes du FortiGate lors d'un upgrade ou à chaque logout "
        "d'un compte admin. Ces sauvegardes sont essentielles pour permettre un rollback "
        "rapide en cas de dysfonctionnement ou de configuration erronée."
    ),
    "CFG-REF-INTEGRITY-001": BusinessText(
        "Vérification que les relations entre zones, interfaces, politiques et services "
        "pointent vers des objets définis et non ambigus. Cette lecture permet de repérer "
        "les incohérences de configuration qui empêchent une politique de produire le "
        "flux attendu."
    ),
    "SYS-AUTO-INSTALL-USB-001": BusinessText(
        "Vérification de la désactivation des options ‘set auto-install-config’ et "
        "‘set auto-install-image’. Si ces fonctionnalités sont actives, un attaquant "
        "disposant d’un accès physique pourrait introduire une clé USB contenant un "
        "firmware ou une configuration malveillante sur le FortiGate. Lors d’un redémarrage, "
        "le contenu USB pourrait être installé automatiquement.",
        risk_point="Auto-installation d'image par USB",
        risk_description=(
            "L’auto-installation d'une configuration ou d'un firmware via USB peut permettre "
            "à un attaquant local de compromettre le FortiGate et, par effet de propagation, "
            "le réseau."
        ),
        likelihood="VRAISEMBLABLE",
        impact="CRITIQUE",
        correction="SIMPLE",
        remediation="Désactiver le paramètre auto install par USB.",
    ),
    "SYS-FORTIMANAGER-SYNC-001": BusinessText(
        "Vérification que votre FortiGate soit configuré avec un FortiManager ou FortiCloud."
    ),
    "SYS-FORTIANALYZER-SYNC-001": BusinessText(
        "Vérification que votre FortiGate soit configuré avec un FortiAnalyzer."
    ),
    "SYS-ADMIN-HTTPS-PORT-001": BusinessText(
        "Vérification que le port HTTPS d’accès administrateur au FortiGate n’est pas "
        "laissé sur la valeur par défaut 443."
    ),
    "NET-SIP-ALG-001": BusinessText(
        "Vérification de la désactivation du SIP ALG et de l'absence de helper SIP. Cette "
        "mesure évite que le FortiGate modifie inutilement le traitement des flux de téléphonie."
    ),
    "HA-SESSION-PICKUP-001": BusinessText(
        "Vérification si les options 'session pickup' sont activées. Le session pickup "
        "permet de minimiser les interruptions de communication et évite de devoir "
        "redémarrer les sessions actives. Le périmètre couvre les sessions TCP, UDP et "
        "dynamiques telles que FTP ou SIP."
    ),
    "HA-HEARTBEAT-REDUNDANCY-001": BusinessText(
        "Vérification si les interfaces de HA sont redondées avec au minimum 2 heartbeats. "
        "Cela assure la redondance nécessaire à la synchronisation du cluster.",
        risk_point="HA / Cluster : Redondance des interfaces HA",
        risk_description=(
            "Une redondance insuffisante des interfaces HA expose le cluster à une "
            "défaillance du lien de synchronisation. En cas de panne d’une interface unique, "
            "l’absence de lien alternatif peut entraîner une perte de synchronisation, une "
            "indisponibilité du cluster ou un basculement intempestif."
        ),
        likelihood="VRAISEMBLABLE",
        impact="SIGNIFICATIF",
        correction="SIMPLE",
        remediation="Mettre au moins 2 heartbeat.",
    ),
    "HA-OVERRIDE-001": BusinessText(
        "Si l'override est activé, une durée d'attente de 30 secondes constitue un "
        "compromis entre stabilité et réactivité. Sinon, l'override peut être désactivé."
    ),
    "HA-CABLING-REDUNDANCY-001": BusinessText(
        "Vérification si le câblage est redondé entre les FortiGate. Cette redondance "
        "assure une continuité des flux en cas de bascule. Des tests de bascule doivent "
        "être réalisés régulièrement pour vérifier le fonctionnement de la redondance."
    ),
    "UTM-FORTISANDBOX-CLOUD-001": BusinessText(
        "Contrôle de l'activation et du paramétrage de la FortiSandbox Cloud. Cette sandbox "
        "permet de bloquer des fichiers suspects sans impacter les performances du FortiGate.",
        risk_point="FortiSandbox Cloud",
        risk_description=(
            "Sans FortiSandbox Cloud, les attaques zero-day et menaces avancées que les "
            "signatures classiques ne détectent pas sont moins bien couvertes."
        ),
        likelihood="VRAISEMBLABLE",
        impact="GRAVE",
        correction="SIMPLE",
        remediation="Activer et configurer la FortiSandbox Cloud.",
    ),
    "UTM-FORTIGUARD-ANYCAST-001": BusinessText(
        "Vérification du paramétrage de FortiGuard Anycast afin que les requêtes vers les "
        "services FortiGuard suivent le mode retenu par la politique de sécurité."
    ),
    "NET-SDWAN-USAGE-001": BusinessText(
        "Contrôle de l'utilisation du SD-WAN. Le SD-WAN optimise la bande passante, permet "
        "le load balancing des liens et améliore les performances. Même avec un seul lien "
        "WAN, une configuration anticipée apporte de la flexibilité lors de l'ajout de "
        "nouveaux liens.",
        risk_point="Utilisation du SD-WAN",
        risk_description=(
            "Mauvaise répartition de la charge, dégradation des performances réseau et "
            "moindre résilience en cas d'ajout de nouveaux liens WAN."
        ),
        likelihood="VRAISEMBLABLE",
        impact="SIGNIFICATIF",
        correction="RAISONNABLE",
        remediation="Utiliser le SD-WAN et y configurer tous les liens WAN.",
    ),
    "FW-BY-SEQUENCE-USAGE-001": BusinessText(
        "Contrôle de l'utilisation du 'By Sequence' pour les règles du pare-feu. Ce mode "
        "permet de contrôler précisément l’ordre d’évaluation, en positionnant d’abord les "
        "règles restrictives puis les règles permissives, afin d'optimiser la sécurité et "
        "les performances.",
        risk_point="Règles en By Sequence",
        risk_description=(
            "Les règles peuvent être mal ordonnées et laisser passer du trafic "
            "indésirable."
        ),
        likelihood="TRÈS VRAISEMBLABLE",
        impact="GRAVE",
        correction="SIMPLE",
        remediation="Utiliser le 'By Sequence' pour les règles.",
    ),
    "UTM-MAIL-FILTER-USAGE-001": BusinessText(
        "Vérification que le profil de sécurité Mail Filter n'est pas utilisé sur les règles "
        "du pare-feu. Le FortiGate n'est pas un relais de messagerie ; un besoin de "
        "passerelle de messagerie sécurisée relève d'un service dédié comme FortiMail."
    ),
    "FW-SSL-SSH-PROFILE-001": BusinessText(
        "Vérification des profils SSL/SSH utilisés et de leur comportement en cas d’échec "
        "de vérification de certificat. Le contrôle protège l'inspection HTTPS contre un "
        "traitement inattendu des certificats."
    ),
    "CFG-UNUSED-SERVICE-001": BusinessText(
        "Vérification d'objets sans référence. Sur le périmètre V2 de ce contrôle, sont "
        "examinés les services et groupes de services. Le contrôle historique V1 élargissait "
        "la recherche aux adresses, groupes d'adresses, VIP, Virtual Servers, zones, "
        "utilisateurs et profils de sécurité ; cette différence de couverture est conservée "
        "et signalée plutôt que de fabriquer une non-conformité.",
        risk_point="Objet sans référence",
        risk_description="Erreur de configuration et augmentation de la surface d'exposition.",
        likelihood="VRAISEMBLABLE",
        impact="SIGNIFICATIF",
        correction="SIMPLE",
        remediation="Supprimer les objets sans référence après validation.",
    ),
    "IAM-LEGACY-ADMIN-001": BusinessText(
        "Vérification de la présence et de la protection du compte administrateur local "
        "attendu par la règle historique V1."
    ),
    "IAM-LEGACY-PKI-REMOVAL-001": BusinessText(
        "Vérification de l'absence du compte PKI historique qui ne doit plus être présent "
        "dans la configuration auditée."
    ),
    "IAM-LEGACY-PKI-PRESENCE-001": BusinessText(
        "Vérification de la présence du compte PKI géré attendu par la règle historique V1."
    ),
    "NET-LEGACY-ADMIN-LOOPBACK-001": BusinessText(
        "Vérification de la chaîne historique d'administration via la source FQDN, la "
        "loopback, le VIP et la policy autorisée. L'objectif est de conserver un accès "
        "d'administration maîtrisé sans exposition directe sur les interfaces WAN."
    ),
    "DNS-LEGACY-DATABASE-001": BusinessText(
        "Vérification de la présence de l'entrée DNS database attendue par la règle "
        "historique V1, nécessaire à la résolution du service d'administration prévu."
    ),
    "NET-GEO-IP-USAGE-001": BusinessText(
        _V1_GEO_POINT,
        risk_point="Utilisation de la fonction GEO-IP",
        risk_description=(
            "Exposition des réseaux à un risque accru d’attaques provenant de zones "
            "géographiques non maîtrisées ou hostiles."
        ),
        likelihood="TRÈS VRAISEMBLABLE",
        impact="GRAVE",
        correction="RAISONNABLE",
        remediation="Utiliser de la GEO-IP.",
    ),
    "NET-RFC6890-BLACKHOLE-001": BusinessText(
        "Nous recommandons la mise en place d'une route Blackhole pour les réseaux privés, "
        "sauf si un lien MPLS ou L2L est présent. Elle permet de s'aligner sur la RFC 6890 "
        "et d'empêcher des fuites de paquets privés vers Internet."
    ),
    "FW-LEGACY-SCHEDULE-INVENTORY-001": BusinessText(
        "Vérification de l'inventaire des schedules appliqués aux policies afin de repérer "
        "les fenêtres temporelles expirées ou incohérentes avec le fonctionnement attendu "
        "du pare-feu."
    ),
    "WIFI-FORTIAP-OBSOLETE-001": BusinessText(
        "Vérification des modèles de FortiAP utilisés et de leur obsolescence. Anticiper "
        "leur renouvellement permet d'éviter les interruptions de service liées aux "
        "incompatibilités après les mises à jour majeures du FortiGate."
    ),
    "WIFI-SSID-LIMIT-001": BusinessText(
        "Contrôle du nombre de SSID par profil Wi-Fi. Avoir plus de quatre SSID sur un "
        "profil entraîne une dégradation des performances et une saturation du spectre radio."
    ),
    "WIFI-RADIO2-40MHZ-001": BusinessText(
        "Contrôle de l'utilisation de la bande 5 GHz sur le canal 40 MHz. La bande 5 GHz "
        "est moins sensible aux interférences et le canal 40 MHz offre un compromis entre "
        "débit et stabilité."
    ),
    "WIFI-DARRP-001": BusinessText(
        "Vérification de l'activation de Radio Resource Provision, qui permet une gestion "
        "dynamique des ressources radio et réduit les interférences."
    ),
    "WIFI-FREQUENCY-HANDOFF-001": BusinessText(
        "Vérification de l'activation de Frequency Handoff, qui améliore le load balancing "
        "entre les bandes 2,4 GHz et 5 GHz. Cette option doit être testée dans un réseau "
        "correctement conçu pour éviter les déconnexions."
    ),
    "WIFI-TIM-001": BusinessText(
        "L'activation de TIM permet une meilleure gestion des économies d'énergie pour les "
        "clients connectés, tout en garantissant une connectivité efficace."
    ),
    "WIFI-BAND-001": BusinessText(
        "Vérification de l'utilisation des standards récents n/ac/ax pour de meilleures "
        "performances. Les standards obsolètes a/b/g sont sources d'interférences et de "
        "faible débit."
    ),
    "WIFI-CHANNELS-001": BusinessText(
        "Utiliser uniquement les canaux 1, 6 et 11 permet d’éviter les interférences entre "
        "réseaux voisins et d'assurer une transmission stable."
    ),
    "WIFI-SHORT-GUARD-INTERVAL-001": BusinessText(
        "Dans les environnements où il y a peu d'interférences et d'obstacles, l'option "
        "Short Guard Interval permet d’augmenter le débit jusqu’à 11 %."
    ),
}


# CTI and ISDB were separate V1 report points. Keep their business prose available
# for a future/legacy finding without inventing an engine result in the current
# 60-control registry.
_BUSINESS_TEXT["NET-ISDB-WAN-001"] = BusinessText(
    _V1_ISDB_POINT,
    risk_point="Utilisation des ISDB sur les flux WAN",
    risk_description=(
        "Des flux WAN non filtrés par les services FortiGuard augmentent la surface "
        "d'exposition."
    ),
    likelihood="VRAISEMBLABLE",
    impact="SIGNIFICATIF",
    correction="RAISONNABLE",
    remediation="Utiliser les ISDB FortiGuard pour filtrer les flux WAN concernés.",
)
_BUSINESS_TEXT["NET-CTI-WAN-001"] = BusinessText(
    _V1_CTI_POINT,
    risk_point="Utilisation de sources CTI sur les flux WAN",
    risk_description=(
        "L'absence de sources CTI réduit la capacité à détecter et bloquer les "
        "indicateurs de compromission."
    ),
    likelihood="VRAISEMBLABLE",
    impact="GRAVE",
    correction="RAISONNABLE",
    remediation="Configurer une source CTI approuvée et documenter son périmètre.",
)
_BUSINESS_TEXT["FW-SENSITIVE-PROTOCOL-DENY-001"] = BusinessText(
    "Nous recommandons le blocage de certains ports pour les flux à destination "
    "d'Internet : KERBEROS, LDAP, LDAPS, RADIUS, SAMBA et SMB.",
    risk_point="Ports-Deny vers Internet",
    risk_description="Risque accru d'accès non autorisé et de compromission.",
    likelihood="TRÈS VRAISEMBLABLE",
    impact="GRAVE",
    correction="SIMPLE",
    remediation="Bloquer les ports recommandés par SNS.",
)


def business_text_for(finding: AuditFinding) -> BusinessText | None:
    return _BUSINESS_TEXT.get(finding.control_id)


def business_risk_for(finding: AuditFinding) -> RiskAssessment | None:
    """Return V1 risk values when the historical point defines them."""

    content = business_text_for(finding)
    if content is None or not any(
        value is not None
        for value in (
            content.risk_description,
            content.likelihood,
            content.impact,
            content.correction,
            content.remediation,
        )
    ):
        return finding.risk
    fallback = finding.risk
    return RiskAssessment(
        summary=content.risk_description or (fallback.summary if fallback else ""),
        impact=content.impact or (fallback.impact if fallback else None),
        likelihood=content.likelihood or (fallback.likelihood if fallback else None),
        treatment=(
            content.correction
            or content.remediation
            or (fallback.treatment if fallback else None)
        ),
    )


def _clean_observation(value: str) -> str:
    text = value.strip()
    text = re.sub(
        r"\bfortigate-(?:sensitive-protocols|vpn-crypto)(?:[@\s][\w.-]+)?",
        "",
        text,
        flags=re.I,
    )
    text = re.sub(r"\b(?:rule_version|ruleset-version|ruleset)\b[^;,.]*", "", text, flags=re.I)
    text = re.sub(r"\bprovenance\b[^;,.]*", "", text, flags=re.I)
    text = re.sub(r"\blegacy_v1\b", "", text, flags=re.I)
    text = re.sub(r"\btyped\s+projection(?:s)?\b", "configuration analysée", text, flags=re.I)
    text = re.sub(r"\bnamespaces?\b", "configuration", text, flags=re.I)
    text = re.sub(r"\bprojection(?:s)?\b", "analyse", text, flags=re.I)
    text = re.sub(r"\bparser\b", "analyse", text, flags=re.I)
    text = re.sub(
        r"\b(?:proof_state|proof|evidence|control_id|internal|engine|registry)\b",
        "",
        text,
        flags=re.I,
    )
    text = re.sub(r"\b(?:line|line number)\s*\d*\b", "", text, flags=re.I)
    text = re.sub(r"\bJSON\b", "rapport", text, flags=re.I)
    text = re.sub(r"\bcertain\b", "confirmé", text, flags=re.I)
    text = re.sub(r"\bcertaine\b", "confirmée", text, flags=re.I)
    text = re.sub(r"\bcertains\b", "confirmés", text, flags=re.I)
    text = re.sub(r"\bcertaines\b", "confirmées", text, flags=re.I)
    text = re.sub(r"\buncertain\b", "non confirmé", text, flags=re.I)
    text = re.sub(r"\bambiguous\b", "incomplet", text, flags=re.I)
    text = re.sub(r"\bdefaulted\b", "par défaut", text, flags=re.I)
    text = re.sub(r"\bproven\b", "confirmé", text, flags=re.I)
    text = re.sub(r"\bpolicy\s+(\d+)\b", r"règle \1", text, flags=re.I)
    text = re.sub(r"\s{2,}", " ", text).strip(" .;:-")
    text = re.sub(r"^[=+@]", "", text)
    return text


def _detected_values(finding: AuditFinding) -> str:
    names = tuple(
        dict.fromkeys(
            item.name.strip()
            for item in finding.affected_objects
            if item.name.strip()
        )
    )
    if names:
        policy_names = tuple(
            item.name.strip()
            for item in finding.affected_objects
            if item.name.strip() and item.object_type.casefold() in {"policy", "firewall-policy"}
        )
        if policy_names:
            return f"Règles concernées : {', '.join(dict.fromkeys(policy_names))}."
        return f"Éléments détectés : {', '.join(dict.fromkeys(names))}."

    relevant: list[str] = []
    for item in finding.evidence:
        if not isinstance(item, str):
            continue
        cleaned = _clean_observation(item)
        if not cleaned or cleaned.casefold() in {
            _clean_observation(finding.message).casefold(),
            "backup complet",
        }:
            continue
        if any(
            marker in cleaned.casefold()
            for marker in (
                "compte",
                "cible",
                "flux",
                "règle",
                "policy",
                "profil",
                "route",
                "heartbeat",
                "connecteur",
                "entrée",
                "absence",
                "configuration",
                "section",
            )
        ):
            relevant.append(cleaned)
    if not relevant:
        return ""
    return "Données détectées : " + " ; ".join(dict.fromkeys(relevant[:3])) + "."


def client_result_for(finding: AuditFinding) -> str:
    """Render a useful client result from the engine message and live evidence."""

    if finding.control_id == "IAM-GUEST-ACCOUNT-001":
        if finding.status is AuditStatus.PASS:
            return "Le compte guest n'a pas été détecté dans la configuration analysée."
        if finding.status is AuditStatus.FAIL:
            return "Le compte guest par défaut a été détecté dans la configuration analysée."
        return (
            "La présence du compte guest n'a pas pu être confirmée dans la "
            "configuration analysée."
        )

    message = _clean_observation(finding.message)
    detected = _detected_values(finding)
    if detected and detected.casefold() not in message.casefold():
        separator = "" if message.endswith((".", "!", "?")) else "."
        return f"{message}{separator} {detected}"
    return message or "Le résultat détaillé n'est pas renseigné."
