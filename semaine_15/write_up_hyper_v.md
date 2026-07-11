# Hyper-V — Déploiement et jonction au domaine d'une PME

Virtualisation · Active Directory · Diagnostic réseau

**09 juillet 2026**

**Environnement** : Home lab Hyper-V + VirtualBox — domaine `dpro.lab`
**Objectif** : Déployer une VM Windows 11 sous Hyper-V, la joindre au domaine Active Directory existant, et comparer concrètement Hyper-V et VirtualBox en contexte professionnel.
**Outils** : Hyper-V Manager · PowerShell · Active Directory · DNS/DHCP Windows Server
**Niveau** : Guidé (installation) puis Autonome (jonction domaine et diagnostic réseau)

## Contexte

Dans le cadre du renforcement de mes compétences en virtualisation, j'ai déployé Hyper-V, l'hyperviseur natif de Windows, en complément de VirtualBox déjà utilisé pour l'ensemble de mon infrastructure de lab. L'objectif de cet exercice était double. D'une part, créer une nouvelle machine virtuelle Windows 11 (PC02) capable de rejoindre le domaine Active Directory dpro.lab déjà en place, en réutilisant les compétences acquises sur PC01 en semaine 14. D'autre part, comparer concrètement Hyper-V et VirtualBox sur des critères pertinents pour un contexte professionnel, notamment la complexité de mise en réseau, la compatibilité avec les prérequis de Windows 11 et la place de chaque outil dans une infrastructure d'entreprise déjà standardisée sous Windows Server.

Cet exercice s'inscrit dans une problématique réelle de technicien systèmes en PME : de nombreuses entreprises qui utilisent déjà Windows Server et Active Directory choisissent naturellement Hyper-V pour leur virtualisation plutôt qu'une solution tierce, du fait de son intégration native à l'écosystème Microsoft.

## Méthodologie

### Vérification des prérequis

Avant toute activation, j'ai lancé la commande `systeminfo` pour vérifier la compatibilité matérielle de la machine hôte. Le résultat n'affichait pas la section habituelle listant les prérequis Hyper-V, avec le message suivant : "Un hyperviseur a été détecté. Les fonctionnalités nécessaires à Hyper-V ne seront pas affichées." Cette information signifiait qu'un composant utilisait déjà le socle de virtualisation de Windows avant même que j'active Hyper-V volontairement. J'ai identifié la cause en listant précisément l'état des fonctionnalités liées à la virtualisation, avec la commande suivante :

```powershell
Get-WindowsOptionalFeature -Online | Where-Object {$_.FeatureName -like "*Hyper*" -or $_.FeatureName -like "*Virtual*"}
```

- `Get-WindowsOptionalFeature -Online` interroge directement le système en cours d'exécution pour connaître l'état de chaque fonctionnalité Windows optionnelle.
- `Where-Object` filtre les résultats selon une condition, ici la présence des mots-clés "Hyper" ou "Virtual" dans le nom de la fonctionnalité, ce qui évite d'afficher la liste complète, souvent plusieurs centaines de lignes.

Le résultat, avant toute activation, était le suivant :

| Fonctionnalité | État |
|---|---|
| VirtualMachinePlatform | Activée |
| HypervisorPlatform | Désactivée |
| Microsoft-Hyper-V-All | Désactivée |
| Microsoft-Hyper-V | Désactivée |
| Microsoft-Hyper-V-Tools-All | Désactivée |
| Microsoft-Hyper-V-Management-PowerShell | Désactivée |
| Microsoft-Hyper-V-Hypervisor | Désactivée |
| Microsoft-Hyper-V-Services | Désactivée |
| Microsoft-Hyper-V-Management-Clients | Désactivée |

Ce tableau a confirmé la cause de l'observation initiale : `VirtualMachinePlatform` était déjà activée, héritée d'un usage antérieur de Docker Desktop et WSL2, ce qui explique pourquoi `systeminfo` détectait déjà un hyperviseur actif. Toutes les fonctionnalités propres à Hyper-V, en revanche, étaient encore désactivées, confirmant que l'activation complète restait à faire.

#### Point de restauration système

Avant toute modification, j'ai créé un point de restauration via `sysdm.cpl`, en limitant la protection au disque C: uniquement. Ce choix se justifie par le fait que l'activation d'Hyper-V ne modifie que des composants système présents sur le disque système, sans impact sur le disque de données D: ni sur les VMs VirtualBox existantes.

#### Activation d'Hyper-V

```powershell
Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All -All -NoRestart
```

- `Enable-WindowsOptionalFeature` est la cmdlet PowerShell qui active une fonctionnalité Windows optionnelle directement sur le système en cours d'exécution, sans passer par l'interface graphique "Programmes et fonctionnalités". Elle prend en paramètre le nom exact de la fonctionnalité à activer.
- `-Online` indique que la modification s'applique au système actuellement démarré, par opposition à une image Windows hors ligne.
- `Microsoft-Hyper-V-All` est la fonctionnalité parente qui regroupe l'ensemble des sous-composants nécessaires au fonctionnement complet d'Hyper-V, contrairement à `HypervisorPlatform` qui est une fonctionnalité indépendante non requise ici.
- Le paramètre `-All` active également toutes les dépendances liées.
- Le paramètre `-NoRestart` empêche un redémarrage automatique immédiat, pour me laisser le temps de vérifier la commande avant de relancer la machine manuellement.

Après redémarrage, j'ai relancé la même commande de filtrage pour vérifier le résultat de l'activation :

| Fonctionnalité | État |
|---|---|
| VirtualMachinePlatform | Activée |
| HypervisorPlatform | Désactivée |
| Microsoft-Hyper-V-All | Activée |
| Microsoft-Hyper-V | Activée |
| Microsoft-Hyper-V-Tools-All | Activée |
| Microsoft-Hyper-V-Management-PowerShell | Activée |
| Microsoft-Hyper-V-Hypervisor | Activée |
| Microsoft-Hyper-V-Services | Activée |
| Microsoft-Hyper-V-Management-Clients | Activée |

L'ensemble des fonctionnalités nécessaires à Hyper-V est passé à l'état activé, confirmant le succès de l'activation. `HypervisorPlatform` reste désactivée volontairement : il s'agit d'une fonctionnalité indépendante d'Hyper-V, non nécessaire ici.

#### Architecture Hyper-V — Type 1 versus Type 2

VirtualBox est un hyperviseur de Type 2 : il s'installe comme une application classique au-dessus d'un système d'exploitation déjà présent, et chaque accès au matériel de la VM traverse plusieurs couches, de la VM vers le logiciel VirtualBox, puis vers le noyau de l'OS hôte, puis vers le matériel physique.

Hyper-V est un hyperviseur de Type 1 : il s'installe directement au-dessus du matériel, en occupant le niveau de privilège le plus élevé du processeur. Une fois Hyper-V activé, l'OS Windows d'origine n'est plus l'unique système en contrôle de la machine : il devient lui-même une partition privilégiée, appelée partition parente, qui conserve un accès quasi direct au matériel par l'intermédiaire du VMBus et de pilotes appelés VSP, pour Virtualization Service Providers. Cette partition parente héberge également le service de gestion des machines virtuelles, VMMS, et le pilote responsable du switch virtuel, `vmswitch.sys`.

Les machines virtuelles créées ensuite, comme PC02, sont des partitions enfants. Elles n'ont aucun accès matériel direct et passent systématiquement par la partition parente, via des pilotes appelés VSC, pour Virtualization Service Clients, symétriques des VSP côté parente.

#### Les trois modes de switch virtuel

Hyper-V propose trois types de switch virtuel, dont le choix détermine la portée de la communication réseau des VMs.

Le mode Privé permet uniquement aux VMs de communiquer entre elles, sans aucune carte réseau créée côté partition parente. Ce mode convient à des scénarios de test isolés ou d'analyse de malware, où toute fuite vers le réseau réel doit être exclue.

Le mode Interne ajoute une communication possible entre les VMs et la partition parente elle-même, grâce à une carte réseau virtuelle créée automatiquement à cet effet.

Le mode Externe étend cette communication au réseau physique ou virtuel externe, via un pont, aussi appelé bridge, sur une carte réseau réelle ou virtuelle existante.

Un point important à retenir est que le pilote du switch, `vmswitch.sys`, tourne toujours côté partition parente, quel que soit le mode choisi. Ce qui varie réellement entre les trois modes, c'est la présence ou non d'un point d'accès réseau logique, autrement dit une carte et une adresse IP, pour la partition parente sur ce segment.

#### Création du switch virtuel pour ce lab

J'ai créé un switch de type Externe, nommé `vSwitch-HostOnly-Lab`, en le pontant sur la carte VirtualBox Host-Only Ethernet Adapter déjà utilisée par mon infrastructure VirtualBox existante. J'ai coché la case "Autoriser le système d'exploitation de gestion à partager cette carte réseau", ce qui permet à la partition parente d'obtenir elle-même une adresse IP sur le segment 192.168.56.x. Ce choix combine en réalité les capacités des modes Interne et Externe, et était nécessaire pour que PC02 puisse communiquer avec DC01 et les autres VMs de mon infrastructure VirtualBox, toutes situées sur ce même segment réseau.

#### Création de la VM PC02

J'ai créé la VM via l'assistant graphique de Hyper-V Manager, en Génération 2, seule génération compatible avec les exigences UEFI et TPM 2.0 de Windows 11, la Génération 1 reposant sur un BIOS legacy incompatible. J'ai configuré une RAM dynamique, une fonctionnalité qui ajuste automatiquement l'allocation mémoire réelle en fonction de l'usage constaté, contrairement à l'allocation fixe classique de VirtualBox. Le disque a été créé au format VHDX dynamique, ce qui signifie que l'espace disque n'est réservé qu'au fur et à mesure des besoins réels, et non intégralement dès la création.

| Paramètre | Valeur choisie | Justification |
|---|---|---|
| Nom | PC02 | Convention alignée sur PC01 et DC01 déjà existants |
| Emplacement | Disque C: (par défaut) | C: identifié comme disque SSD, plus rapide en I/O que D: (HDD) |
| Génération | 2 (UEFI) | Seule génération compatible avec les exigences UEFI et TPM 2.0 de Windows 11 |
| RAM | Dynamique — Démarrage 4096 Mo, Min 1024 Mo, Max 6144 Mo | RAM dynamique : ajustement automatique de l'allocation selon l'usage réel, contrairement à l'allocation fixe de VirtualBox |
| vCPU | 2 | Suffisant pour un poste client de test, sans charge lourde prévue |
| Disque | VHDX dynamique, 60 Go | Format dynamique : espace réservé à la demande, pas intégralement dès la création |
| Réseau | vSwitch-HostOnly-Lab | Rejoint le segment 192.168.56.x de l'infrastructure existante |
| Installation | ISO officiel Microsoft (Win11_25H2_French_x64_v2.iso) | Image Windows 11 25H2 en français |

#### Dépannage — trois blocages rencontrés à l'installation

**Premier blocage, échec de démarrage lié au Secure Boot.** Au premier démarrage, la VM affichait un échec de chargement du système d'exploitation. Mon hypothèse s'est portée sur le Secure Boot, activé par défaut avec le profil de certificats "Microsoft Windows". J'ai testé un premier changement de profil vers "Microsoft UEFI Certificate Authority", qui a fait évoluer l'erreur vers un message plus précis indiquant que le hash de l'image signée n'était pas autorisé dans la base de certificats. J'ai alors désactivé complètement le Secure Boot pour cette VM, ce qui a débloqué le démarrage de l'installateur. Cette désactivation reste un choix pragmatique propre à un contexte de lab de test, à ne jamais reproduire en environnement de production, où le Secure Boot doit rester activé pour garantir l'intégrité de la chaîne de démarrage.

**Deuxième blocage, configuration insuffisante détectée par l'installateur Windows 11.** L'installateur signalait l'absence de TPM 2.0 et une mémoire insuffisante, alors que la VM disposait bien d'une RAM maximale largement suffisante. La cause identifiée est que l'installateur vérifie la valeur de RAM de démarrage, appelée Startup RAM, affichée à l'instant du contrôle, et non le plafond de RAM dynamique configuré. J'ai donc relevé le Startup RAM de 2048 à 4096 Mo, et activé le module de plateforme sécurisée, autrement dit le TPM virtuel, non coché par défaut à la création de la VM. Ces deux corrections ont résolu le blocage simultanément.

**Troisième blocage, écran réseau OOBE exigeant une connexion Internet.** L'installateur bloquait la progression tant qu'aucune sortie Internet réelle n'était détectée, alors que la connectivité locale fonctionnait correctement : un ping depuis la partition parente vers DC01, en 192.168.56.110, aboutissait, et la VM avait déjà obtenu une adresse par DHCP à ce stade. La cause est que l'écran OOBE de Windows 11 exige spécifiquement une sortie vers Internet, absente sur mon réseau Host-Only isolé, qui ne dispose d'aucune passerelle vers l'extérieur. J'ai contourné ce blocage en ouvrant une invite de commandes avec Shift+F10, et en exécutant la commande `OOBE\BYPASSNRO`, qui relance l'étape réseau de l'installateur en proposant une option de poursuite sans connexion Internet.

#### Vérifications post-installation

Une fois PC02 installé, j'ai confirmé la stabilité de son adressage avec `ipconfig`, l'adresse 192.168.56.108 restant inchangée après redémarrage complet, et la connectivité avec DC01 via un ping réussi. J'ai également vérifié l'état des services d'intégration Hyper-V avec `Get-Service vmic*`, qui a montré cinq services actifs sur sept, les deux services arrêtés correspondant à des fonctions optionnelles non utilisées dans ce lab, à savoir la session PowerShell Direct et l'interface invité avancée.

### Jonction au domaine et diagnostic réseau

*(section à rédiger)*

## Résultats

À l'issue de ces deux journées, l'environnement suivant est opérationnel : une VM Windows 11, PC02, fonctionne sous Hyper-V, dispose d'une adresse IP stable sur le segment 192.168.56.x, communique avec DC01 et est jointe au domaine dpro.lab sous le nom correct. La commande `Get-ADComputer -Filter * | Select-Object Name, DistinguishedName` exécutée sur DC01 confirme la présence de trois postes dans l'annuaire : DC01, le contrôleur de domaine, PC01, rejoint en semaine 14, et PC02, chacun rattaché au conteneur ou à l'unité d'organisation attendue.

Le tableau ci-dessous récapitule les incidents rencontrés et leur résolution :

| Incident | Cause | Résolution |
|---|---|---|
| Échec de démarrage VM | Secure Boot, profil de certificats incompatible | Désactivation du Secure Boot, VM Génération 2 |
| Configuration système insuffisante détectée | Startup RAM sous le seuil requis, TPM virtuel non activé | Startup RAM relevé à 4096 Mo, TPM virtuel activé |
| Blocage écran réseau OOBE | Absence de sortie Internet réelle sur réseau Host-Only isolé | Commande `OOBE\BYPASSNRO` |
| Échec de jonction au domaine, 1er essai | DC01 éteint, PC02 en adresse APIPA | Redémarrage DC01, renouvellement DHCP |
| Échec de jonction au domaine, 2e essai | DNS resté sur anciennes adresses IPv6 après renouvellement DHCP | Configuration DNS manuelle vers 192.168.56.110 |
| Échec de jonction au domaine, 3e essai | DC01 pas encore complètement démarré, DNS toujours injoignable | Attente du démarrage complet, confirmation par nslookup |
| Nom incorrect dans l'annuaire, DESKTOP-NN5J43N | Nom VM Hyper-V distinct du hostname Windows interne | `Rename-Computer` puis re-jonction |

## Analyse comparative Hyper-V vs VirtualBox

*(section à rédiger)*

## Recommandations

Plusieurs points identifiés au cours de ce lab mériteraient d'être traités dans un contexte de production réel. La désactivation du Secure Boot, nécessaire ici pour débloquer l'installation, ne doit jamais être reproduite telle quelle sur un poste de production, où l'intégrité de la chaîne de démarrage est un enjeu de sécurité à part entière ; une mise à jour de la base de certificats Hyper-V, ou l'utilisation d'une image Windows 11 dont le chargeur de démarrage est déjà reconnu, résoudrait ce problème sans compromis.

L'adressage IP de PC02, actuellement en DHCP dynamique bien que stable, gagnerait à être fixé par une réservation DHCP basée sur l'adresse MAC, à l'image de ce qui a déjà été mis en place pour le serveur Debian DMZ en semaine 15, ce qui garantirait la stabilité nécessaire à des règles de pare-feu ou une supervision réseau fiables.

Enfin, cet incident de jonction a mis en évidence une dépendance critique de l'infrastructure à l'ordre de démarrage des machines : tant que DC01 n'est pas complètement opérationnel, aucun poste client ne peut résoudre le domaine ni s'y authentifier, ce qui constitue un point de vigilance à documenter dans toute procédure de démarrage d'une infrastructure Active Directory en environnement réel.

## Conclusion

*(section à rédiger)*
