# NordLogistique — Déploiement d'une infrastructure réseau PME complète
## Segmentation · Accès distant · Routage internet · Diagnostic réseau


**27 juin 2026**

  
**Environnement :** Simulation réseau Cisco (Packet Tracer) + VMs Linux (VirtualBox)  
**Objectif :** Concevoir et déployer une infrastructure réseau complète pour une PME fictive — segmentation par VLANs, accès distant chiffré par VPN, routage internet contrôlé par NAT/PAT — et valider sa robustesse par des exercices de diagnostic sur pannes réelles.  
**Outils :** Cisco Packet Tracer · VirtualBox · WireGuard · Wireshark  
**Niveau :** Guidé — lab intégré NordLogistique  

---

## Table des matières

1. [Contexte et problématique](#1-contexte-et-problématique)
2. [Architecture globale](#2-architecture-globale)
3. [Phase 1 — Segmentation réseau par VLANs](#3-phase-1--segmentation-réseau-par-vlans)
   - 3.1 Théorie : pourquoi segmenter ?
   - 3.2 Plan d'adressage
   - 3.3 Configuration des équipements
   - 3.4 Tests de connectivité
   - 3.5 Anomalies rencontrées
4. [Phase 2 — Accès distant sécurisé par VPN WireGuard](#4-phase-2--accès-distant-sécurisé-par-vpn-wireguard)
   - 4.1 Théorie : pourquoi un VPN ?
   - 4.2 Architecture du tunnel
   - 4.3 Déploiement du tunnel
   - 4.4 Démonstration Wireshark
   - 4.5 Problèmes rencontrés
5. [Phase 3 — Routage internet et résilience de l'infrastructure](#5-phase-3--routage-internet-et-résilience-de-linfrastructure)
   - 5.1 Théorie : NAT/PAT
   - 5.2 Configuration NAT/PAT sur R-NL
   - 5.3 Positionnement IDS/IPS dans l'architecture
   - 5.4 Diagnostic de pannes réseau
   - 5.5 Analyse globale
6. [Bonnes pratiques appliquées](#6-bonnes-pratiques-appliquées)
7. [Limites et points d'amélioration](#7-limites-et-points-damélioration)
8. [Conclusion](#8-conclusion)

---

## 1. Contexte et problématique

NordLogistique est une PME fictive de logistique régionale d'environ 45 salariés, répartis sur quatre départements : RH, Informatique, Direction et Production. Le département Production opère sur un réseau physiquement séparé, dédié aux équipements de l'entrepôt — il sort du périmètre de ce projet, qui couvre uniquement les postes bureautiques des trois autres départements.

Au démarrage du projet, l'entreprise présentait trois lacunes majeures sur son infrastructure réseau :

**Absence de segmentation.** Tous les postes bureautiques partageaient un réseau à plat sans séparation logique. Un poste compromis dans le département RH pouvait accéder directement aux machines de la Direction ou de l'Informatique. Cette absence de cloisonnement est une violation du principe de défense en profondeur.

**Absence d'accès distant sécurisé.** Les salariés en télétravail ne disposaient d'aucun moyen sécurisé pour accéder au réseau interne de l'entreprise.

**Absence de routage internet contrôlé.** Si l'accès internet existait via la box FAI, le routeur interne R-NL n'était pas configuré pour gérer les flux de sortie de manière maîtrisée. Aucune règle ne définissait précisément quels réseaux internes étaient autorisés à sortir vers internet, et les interfaces inside/outside n'étaient pas distinguées.

Ce projet documente la construction progressive d'une infrastructure réseau répondant à ces trois problèmes, dans l'ordre logique d'une mise en place réelle : on sécurise d'abord l'intérieur (segmentation), puis on sécurise les accès distants (VPN), puis on ouvre l'accès internet de manière contrôlée (NAT/PAT), et enfin on valide la robustesse de l'ensemble par des exercices de diagnostic.

---

## 2. Architecture globale

### Équipements réseau (Packet Tracer)

| Équipement | Modèle | Rôle |
|---|---|---|
| R-NL | Cisco 2911 | Routeur principal — routage inter-VLAN, NAT/PAT, passerelle internet |
| SW-RH | Cisco 2960-24TT | Switch d'accès — département RH |
| SW-INFO-DIR | Cisco 2960-24TT | Switch d'accès — départements Informatique et Direction |
| Server0 | Serveur simulé | Serveur web externe — IP publique simulée 203.0.113.2 |
| PC-RH-1, PC-RH-2 | — | Postes département RH |
| PC-INFO-1, PC-INFO-2 | — | Postes département Informatique |
| PC-DIR-1, PC-DIR-2 | — | Postes département Direction |

### VMs Linux (VirtualBox — Phase 2)

| Machine | Rôle | IP Host-Only | IP tunnel WireGuard |
|---|---|---|---|
| Kali Linux | Poste distant simulant un salarié en télétravail | 192.168.56.100 (eth0) | 10.0.0.1 |
| Debian DMZ | Serveur VPN en DMZ de l'entreprise | 192.168.56.103 (enp0s8) | 10.0.0.2 |

### Plan d'adressage VLANs

| VLAN | Département | Réseau | Passerelle | Ports assignés |
|---|---|---|---|---|
| 10 | RH | 192.168.10.0/24 | 192.168.10.1 | SW-RH Fa0/1-2 |
| 20 | Informatique | 192.168.20.0/24 | 192.168.20.1 | SW-INFO-DIR Fa0/1-2 |
| 30 | Direction | 192.168.30.0/24 | 192.168.30.1 | SW-INFO-DIR Fa0/3-4 |
| 999 | NATIF_UNUSED | — | — | Tous ports inutilisés + native VLAN trunks |

### Interface WAN simulée

| Interface | IP | Rôle |
|---|---|---|
| R-NL Gig0/2 | 203.0.113.1/24 | Interface WAN simulée (ip nat outside) |
| Server0 | 203.0.113.2/24 | Serveur web externe simulant internet |

**Note :** La plage 203.0.113.0/24 est réservée à des fins de documentation par la RFC5737. C'est la convention standard utilisée dans les cours et exemples réseau pour représenter une adresse publique simulée.

---

## 3. Phase 1 — Segmentation réseau par VLANs

### 3.1 Théorie : pourquoi segmenter ?

Sans segmentation, tous les postes de NordLogistique partagent le même réseau. Concrètement, si un poste du département RH est infecté par un ransomware, l'attaquant peut immédiatement tenter d'accéder aux machines de la Direction et de l'Informatique. Il n'y a aucune barrière.

Un VLAN (Virtual LAN) crée des réseaux logiques séparés sur la même infrastructure physique. Il fonctionne en couche 2 (Data Link) du modèle OSI : le switch confine chaque trame au VLAN auquel elle appartient et ne la transmet jamais vers un port d'un autre VLAN. Deux machines dans des VLANs différents ne peuvent communiquer qu'en passant par le routeur, qui peut alors appliquer des règles de contrôle. C'est le principe de segmentation : contenir une compromission dans un périmètre délimité.

Le standard **802.1Q** permet à un seul câble de transporter plusieurs VLANs simultanément. Pour cela, il ajoute un champ de 4 octets dans l'en-tête Ethernet de chaque trame, contenant l'identifiant du VLAN d'appartenance. Ce mécanisme s'appelle le **tagging**. Un port qui transporte du trafic tagué 802.1Q s'appelle un **port trunk**.

Le **routage inter-VLAN** est assuré par le routeur. La technique utilisée ici est le **router-on-a-stick** : le routeur possède une sous-interface virtuelle par VLAN, chacune avec sa propre adresse IP qui sert de passerelle par défaut pour les machines de ce VLAN.

### 3.2 Plan d'adressage des postes

| PC | IP | Masque | Passerelle |
|---|---|---|---|
| PC-RH-1 | 192.168.10.10 | 255.255.255.0 | 192.168.10.1 |
| PC-RH-2 | 192.168.10.11 | 255.255.255.0 | 192.168.10.1 |
| PC-INFO-1 | 192.168.20.10 | 255.255.255.0 | 192.168.20.1 |
| PC-INFO-2 | 192.168.20.11 | 255.255.255.0 | 192.168.20.1 |
| PC-DIR-1 | 192.168.30.10 | 255.255.255.0 | 192.168.30.1 |
| PC-DIR-2 | 192.168.30.11 | 255.255.255.0 | 192.168.30.1 |

### 3.3 Configuration des équipements

#### Configuration de base sécurisée (appliquée sur SW-RH, SW-INFO-DIR et R-NL)

Les commandes sont entrées en mode configuration global sur chaque équipement :

```
SW-RH(config)# hostname SW-RH
SW-RH(config)# no ip domain-lookup
SW-RH(config)# line console 0
SW-RH(config-line)#  password admin
SW-RH(config-line)#  login
SW-RH(config-line)# exit
SW-RH(config)# enable secret admin
SW-RH(config)# service password-encryption
SW-RH(config)# banner motd ^C
 Acces reserve au personnel autorise.
 Toute connexion non autorisee fera l'objet de poursuites.
^C
SW-RH# copy running-config startup-config
```

Explication de chaque commande :

- `hostname SW-RH` : renomme l'équipement pour l'identifier immédiatement en CLI
- `no ip domain-lookup` : désactive la résolution DNS. Sans ça, une faute de frappe en CLI provoque un blocage de 30 secondes pendant que l'équipement tente une résolution DNS
- `line console 0` : entre dans la configuration de la ligne console (accès physique à l'équipement)
- `password admin` + `login` : définit un mot de passe et active son exigence : sans `login`, le mot de passe existe mais n'est jamais demandé
- `enable secret admin` : mot de passe pour accéder au mode privilégié, stocké hashé en MD5. À distinguer de `enable password` qui stocke en clair. `enable secret` est toujours préférable
- `service password-encryption` : chiffre les mots de passe restants en clair dans la configuration (type 7, chiffrement faible mais meilleur que le clair)
- `banner motd` : affiche un avertissement légal à chaque connexion : obligatoire avant toute action judiciaire sur une connexion non autorisée
- `copy running-config startup-config` : sauvegarde la configuration active (RAM) vers la mémoire persistante (NVRAM) sinon la configuration est perdue au redémarrage

#### Création des VLANs (sur SW-RH et SW-INFO-DIR)

Les commandes sont entrées en mode configuration global :

```
SW-RH(config)# vlan 10
SW-RH(config-vlan)#  name RH
SW-RH(config-vlan)# exit
SW-RH(config)# vlan 20
SW-RH(config-vlan)#  name INFO
SW-RH(config-vlan)# exit
SW-RH(config)# vlan 30
SW-RH(config-vlan)#  name DIR
SW-RH(config-vlan)# exit
SW-RH(config)# vlan 999
SW-RH(config-vlan)#  name NATIF_UNUSED
SW-RH(config-vlan)# exit
```

Les VLANs doivent être créés sur tous les switches qui les transportent parce qu'un switch refuse de faire transiter un VLAN qu'il ne connaît pas.

#### Ports access (SW-RH — département RH)

Les commandes sont entrées en mode configuration global sur SW-RH :

```
SW-RH(config)# interface fa0/1
SW-RH(config-if)#  switchport mode access
SW-RH(config-if)#  switchport access vlan 10
SW-RH(config-if)# exit
SW-RH(config)# interface fa0/2
SW-RH(config-if)#  switchport mode access
SW-RH(config-if)#  switchport access vlan 10
SW-RH(config-if)# exit
```

- `switchport mode access` : configure le port pour un seul VLAN, sans tag 802.1Q : le PC branché ne sait pas qu'il est dans un VLAN
- `switchport access vlan 10` : assigne ce port au VLAN 10

#### Ports access (SW-INFO-DIR — départements Informatique et Direction)

Les commandes sont entrées en mode configuration global sur SW-INFO-DIR :

```
SW-INFO-DIR(config)# interface fa0/1
SW-INFO-DIR(config-if)#  switchport mode access
SW-INFO-DIR(config-if)#  switchport access vlan 20
SW-INFO-DIR(config-if)# exit
SW-INFO-DIR(config)# interface fa0/2
SW-INFO-DIR(config-if)#  switchport mode access
SW-INFO-DIR(config-if)#  switchport access vlan 20
SW-INFO-DIR(config-if)# exit
SW-INFO-DIR(config)# interface fa0/3
SW-INFO-DIR(config-if)#  switchport mode access
SW-INFO-DIR(config-if)#  switchport access vlan 30
SW-INFO-DIR(config-if)# exit
SW-INFO-DIR(config)# interface fa0/4
SW-INFO-DIR(config-if)#  switchport mode access
SW-INFO-DIR(config-if)#  switchport access vlan 30
SW-INFO-DIR(config-if)# exit
```

#### Ports trunk (identique sur les deux switches)

Les commandes sont entrées en mode configuration global sur les deux switchs. Exemple sur SW-RH :

```
SW-RH(config)# interface fa0/24
SW-RH(config-if)#  switchport mode trunk
SW-RH(config-if)#  switchport trunk allowed vlan 10,20,30
SW-RH(config-if)#  switchport trunk native vlan 999
SW-RH(config-if)# exit
SW-RH(config)# interface gig0/1
SW-RH(config-if)#  switchport mode trunk
SW-RH(config-if)#  switchport trunk allowed vlan 10,20,30
SW-RH(config-if)#  switchport trunk native vlan 999
SW-RH(config-if)# exit
```

- `switchport mode trunk` : active le mode trunk — le port transporte plusieurs VLANs avec les tags 802.1Q
- `switchport trunk allowed vlan 10,20,30` : restreint le trunk aux VLANs nécessaires uniquement. C'est une bonne pratique de sécurité
- `switchport trunk native vlan 999` : définit le VLAN natif à 999 (un VLAN sans aucune machine). Le VLAN natif est celui dont les trames transitent sur un trunk SANS tag 802.1Q. En laissant le VLAN 1 par défaut, on s'expose au VLAN hopping, qui est une technique où un attaquant envoie des trames non taguées pour accéder à un autre VLAN. En pointant vers un VLAN inutilisé, le trafic non tagué aboutit dans un trou noir réseau

#### Sécurisation des ports inutilisés

Les commandes sont entrées en mode configuration global sur les deux switchs. Exemple sur SW-RH :

```
SW-RH(config)# interface range fa0/5 - 23
SW-RH(config-if-range)#  switchport mode access
SW-RH(config-if-range)#  switchport access vlan 999
SW-RH(config-if-range)#  shutdown
SW-RH(config-if-range)# exit
```

Les ports inutilisés représentent un risque : un intrus pourrait brancher un équipement non autorisé et accéder au réseau. Deux protections sont appliquées simultanément :

- `shutdown` désactive physiquement le port : aucun équipement branché dessus ne peut communiquer
- `switchport access vlan 999` l'assigne au VLAN poubelle : si le port est réactivé par erreur, l'équipement branché aboutit dans un réseau sans routage et sans accès au reste de l'infrastructure

#### Sous-interfaces routeur R-NL (router-on-a-stick)

Les commandes sont entrées en mode configuration global sur R-NL :

```
R-NL(config)# interface gig0/0
R-NL(config-if)#  no shutdown
R-NL(config-if)# exit
R-NL(config)# interface gig0/0.10
R-NL(config-subif)#  encapsulation dot1q 10
R-NL(config-subif)#  ip address 192.168.10.1 255.255.255.0
R-NL(config-subif)# exit
R-NL(config)# interface gig0/1
R-NL(config-if)#  no shutdown
R-NL(config-if)# exit
R-NL(config)# interface gig0/1.20
R-NL(config-subif)#  encapsulation dot1q 20
R-NL(config-subif)#  ip address 192.168.20.1 255.255.255.0
R-NL(config-subif)# exit
R-NL(config)# interface gig0/1.30
R-NL(config-subif)#  encapsulation dot1q 30
R-NL(config-subif)#  ip address 192.168.30.1 255.255.255.0
R-NL(config-subif)# exit
```

- `no shutdown` : les interfaces physiques d'un routeur Cisco sont éteintes par défaut, contrairement aux switches où elles sont actives par défaut
- `encapsulation dot1q 10` : lie la sous-interface au VLAN 10 via le standard 802.1Q. Sans cette commande, la sous-interface est aveugle aux trames taguées VLAN 10
- `ip address` : assigne l'adresse IP de passerelle pour ce VLAN

**Choix d'architecture :** deux interfaces physiques distinctes (Gig0/0 vers SW-RH, Gig0/1 vers SW-INFO-DIR) ont été utilisées plutôt qu'une seule. Si le même sous-réseau apparaissait sur deux interfaces différentes, le routeur ne saurait pas par quelle interface router (ambiguïté fatale dans la table de routage).

### 3.4 Tests de connectivité

La validation a suivi une méthode progressive du plus simple au plus complexe :

**Ping intra-VLAN** (PC-RH-1 vers PC-RH-2) : succès, TTL=128. Le trafic reste au niveau du switch, aucun routeur traversé : le TTL reste à sa valeur initiale Windows (128).

**Ping vers la passerelle** (PC-RH-1 vers 192.168.10.1) : succès, TTL=255. Ici c'est le routeur qui répond et donc qui définit le TTL. La valeur initiale du TTL d'un équipement Cisco est de 255 et le paquet arrivant à destination sans passer par un autre équipement de couche 3, il reste à 255. Le résultat valide le lien trunk entre SW-RH et R-NL ainsi que la sous-interface Gig0/0.10.

**Ping inter-VLAN** (PC-RH-1 vers PC-INFO-1) : succès, TTL=127. Le paquet traverse R-NL : le TTL est décrémenté de 1 par le routeur. Le résultat valide le routage inter-VLAN complet.

**Ping inter-VLAN vers VLAN 30** (PC-RH-1 vers PC-DIR-1) : 3 paquets sur 4 transmis : le premier paquet est perdu. Il s'agit d'un comportement normal : le premier paquet est perdu pendant la résolution ARP (le PC cherche l'adresse MAC de sa passerelle pour la première fois). Une fois l'adresse MAC en cache, les paquets suivants passent immédiatement.

### 3.5 Anomalies rencontrées et corrigées

| Anomalie | Symptôme | Diagnostic | Correction |
|---|---|---|---|
| Sous-interface Gig0/0.20 créée sur Gig0/0 au lieu de Gig0/1 | `show ip interface brief` affichait Gig0/0.20 avec 192.168.20.1 | Lecture attentive de la sortie — deux sous-interfaces sur la même interface physique pour des réseaux distincts | `no interface gig0/0.20` puis recréation sur Gig0/1.20 |
| `switchport trunk allowed vlan` absent sur Gig0/1 des deux switches | `show interfaces trunk` affichait VLANs allowed : 1-1005 sur Gig0/1 (valeur par défaut sur Cisco) | Comparaison Fa0/24 (correct) vs Gig0/1 (1-1005) dans la même sortie | `switchport trunk allowed vlan 10,20,30` ajouté sur Gig0/1 |
| Passerelle incorrecte sur PC-INFO-1 (198.168.20.1) | Ping inter-VLAN depuis PC-INFO-1 échoue — ping intra-VLAN réussit | Diagnostic progressif : passerelle joignable mais PC-INFO-1 ne peut pas aller au-delà → problème côté PC | Correction de la passerelle dans IP Configuration du PC |

---

## 4. Phase 2 — Accès distant sécurisé par VPN WireGuard

### 4.1 Théorie : pourquoi un VPN ?

Un salarié de NordLogistique en télétravail doit accéder aux ressources internes de l'entreprise. Sans VPN, ses données transitent en clair sur internet — n'importe quel attaquant capable d'intercepter le trafic peut lire le contenu. Un VPN crée un tunnel chiffré : même si le trafic est intercepté, l'attaquant ne voit que des données illisibles.

WireGuard combine deux types de chiffrement pour assurer à la fois la sécurité de l'établissement du tunnel et la performance du transport des données.

La première phase utilise un chiffrement asymétrique (Curve25519). Chaque machine possède une paire de clés : une clé privée (ne quitte jamais la machine) et une clé publique (distribuable librement). Les deux machines échangent leurs clés publiques et dérivent mathématiquement une clé de session commune, sans jamais faire transiter cette clé sur le réseau. C'est ce qu'on appelle le Perfect Forward Secrecy : même si une clé de session est compromise, elle ne permet pas de déchiffrer les sessions passées.

Une fois la clé de session dérivée, les données sont chiffrées avec un algorithme symétrique (ChaCha20-Poly1305) qui est rapide et efficace pour chiffrer de grands volumes de données. Poly1305 assure en parallèle l'intégrité des paquets.

WireGuard utilise UDP plutôt que TCP pour transporter le tunnel. Encapsuler du TCP dans du TCP crée le problème du "TCP-over-TCP meltdown" : les deux couches réagissent indépendamment aux pertes de paquets, leurs mécanismes de retransmission s'accumulent et dégradent les performances. WireGuard utilise UDP et assure lui-même l'intégrité via Poly1305.

### 4.2 Architecture du tunnel

```
Salarié (télétravail)                       Internet                          DMZ NordLogistique

        Kali Linux                                                                              Debian DMZ
  10.0.0.1 (tunnel)         ←── UDP 51820 chiffré ──→        10.0.0.2 (tunnel)
192.168.56.100 (eth0)                                                       192.168.56.103 (enp0s8)
```

### 4.3 Déploiement du tunnel

#### Installation

```bash
apt install wireguard
```

`apt install wireguard` installe WireGuard et ses dépendances, dont `wg-quick` qui est un outil qui automatise le démarrage et l'arrêt du tunnel en une seule commande (création de l'interface, assignation de l'IP, ajout des routes). La commande est à exécuter sur les deux machines.

#### Génération des clés (sur chaque machine séparément)

```bash
wg genkey | tee /etc/wireguard/private.key | wg pubkey > /etc/wireguard/public.key
chmod 600 /etc/wireguard/private.key
```

Décomposition de la commande de génération :

- `wg genkey` : génère une clé privée Curve25519 aléatoire et l'écrit sur stdout
- `| tee /etc/wireguard/private.key` : tee lit stdin, écrit dans le fichier ET laisse passer le flux vers stdout simultanément. La clé privée est sauvegardée ET transmise à la commande suivante
- `| wg pubkey` : lit la clé privée sur stdin et dérive mathématiquement la clé publique correspondante
- `> /etc/wireguard/public.key` : redirige la clé publique vers son fichier
- `chmod 600 /etc/wireguard/private.key` : rend la clé privée lisible uniquement par son propriétaire. Une clé privée accessible à d'autres utilisateurs système est une faille de sécurité.

Stdin et stdout sont les flux standard d'entrée et de sortie d'une commande Linux :

- stdin (standard input) : ce qu'une commande reçoit en entrée (par défaut le clavier)
- stdout (standard output) : ce qu'une commande produit en sortie (par défaut le terminal)
- Le pipe `|` connecte le stdout d'une commande au stdin de la suivante

**Principe fondamental :** les clés sont générées sur chaque machine séparément. Une clé privée qui transite sur le réseau (même via SSH) est une clé privée potentiellement compromise. Chaque machine génère sa propre paire, et seule la clé publique est échangée.

#### Échange des clés publiques

WireGuard ne dispose pas de mécanisme de découverte automatique des pairs. Chaque machine doit connaître à l'avance la clé publique de l'autre. C'est un choix de conception : simplicité et surface d'attaque minimale.

```bash
# Sur Kali — stocker la clé publique de Debian
echo "y1hJK54S7ekx0i+G+/hfw+aANdXTneQgawi53Hu/DWU=" > /etc/wireguard/peer_debian.pub

# Sur Debian — stocker la clé publique de Kali
echo "nZdEvheFBAJMuHdKR/PHhY+ilhqRzHFBuPqOHqwKOl4=" > /etc/wireguard/peer_kali.pub
```

En production, l'échange de clés publiques se ferait via un canal sécurisé : email chiffré ou gestionnaire de secrets.

#### Fichiers de configuration

Le fichier de configuration wg0.conf définit l'identité de la machine dans le tunnel (bloc `[Interface]`) et les informations sur le pair distant (bloc `[Peer]`). Il est créé manuellement sur chaque machine avec un éditeur de texte en ligne de commande :

```bash
nano /etc/wireguard/wg0.conf
```

Une fois créé, il est lu automatiquement par `wg-quick` au démarrage du tunnel.

**Sur Kali :**

```ini
[Interface]
PrivateKey = kABBTElSvhl08mlQbnx2Fop7AvW63o5VnOPRie92H0M=
Address = 10.0.0.1/24
ListenPort = 51820

[Peer]
PublicKey = y1hJK54S7ekx0i+G+/hfw+aANdXTneQgawi53Hu/DWU=
AllowedIPs = 10.0.0.2/32
Endpoint = 192.168.56.103:51820
```

**Sur Debian :**

```ini
[Interface]
PrivateKey = EPMTt1r2ms/eFs5N7IvanfW1DuGHT0MFersnrsM/qX8=
Address = 10.0.0.2/24
ListenPort = 51820

[Peer]
PublicKey = nZdEvheFBAJMuHdKR/PHhY+ilhqRzHFBuPqOHqwKOl4=
AllowedIPs = 10.0.0.1/32
Endpoint = 192.168.56.100:51820
```

Explication de chaque directive :

- `PrivateKey` : clé privée locale (contenu du fichier /etc/wireguard/private.key)
- `Address = 10.0.0.1/24` : IP de l'interface tunnel avec masque /24. Le /24 est nécessaire pour que la table de routage sache que les paquets vers 10.0.0.x doivent passer par l'interface wg0
- `ListenPort = 51820` : port UDP d'écoute (convention WireGuard)
- `PublicKey` : clé publique du pair distant
- `AllowedIPs = 10.0.0.2/32` : filtre de sécurité. Seul le trafic venant de ou allant vers cette IP exacte (/32 = une seule adresse) est accepté via ce pair. À distinguer du Address /24 qui définit le réseau local
- `Endpoint` : IP réelle et port du pair distant (comment le joindre physiquement avant que le tunnel soit établi)

#### Démarrage du tunnel

```bash
wg-quick up wg0
```

`wg-quick up wg0` exécute automatiquement : la création de l'interface réseau wg0, le chargement de la configuration, l'assignation de l'IP tunnel et l'activation de l'interface avec MTU 1420. Le MTU (Maximum Transmission Unit) est la taille maximale d'un paquet en octets qu'une interface peut transmettre en une seule fois. La valeur standard Ethernet est 1500 octets. WireGuard réduit cette valeur à 1420 sur l'interface wg0 car chaque paquet encapsulé dans le tunnel reçoit des en-têtes supplémentaires (UDP, IP, WireGuard) qui occupent environ 60 à 80 octets.

**Validation :** ping 10.0.0.2 depuis Kali — 7/7 paquets reçus, tunnel opérationnel.

### 4.4 Démonstration Wireshark

La capture a été réalisée sur l'interface eth0 de Kali (réseau Host-Only 192.168.56.x : c'est sur cette interface que transitent physiquement les paquets UDP WireGuard), avec le filtre d'affichage `udp.port == 51820`.

**Phase 1 — Établissement du tunnel (Handshake)**

Au lancement du premier ping vers 10.0.0.2, deux paquets apparaissent immédiatement avant les données :

- **Handshake Initiation** (Kali vers Debian) : Wireshark identifie le protocole WireGuard et affiche le type de message. C'est la phase Curve25519 : les deux machines négocient et dérivent la clé de session commune sans jamais la faire transiter sur le réseau.
- **Handshake Response** (Debian vers Kali) : confirmation que le tunnel est établi.

**Phase 2 — Transport des données**

Les paquets suivants apparaissent avec le type "Transport Data" et une indication de taille (datalen=96). Le panneau hexadécimal en bas de Wireshark affiche des octets aléatoires : il est impossible d'y lire quoi que ce soit. Wireshark voit l'enveloppe UDP mais ne peut pas déchiffrer le contenu. C'est la confirmation qu'il est bien chiffré par ChaCha20.

**Comparaison avec un ping en clair**

En lançant un ping direct vers 192.168.56.103 (sans tunnel, filtre `icmp`), Wireshark décode entièrement le paquet : Ethernet II → IP → ICMP, avec les informations lisibles "Echo (ping) request, seq=1, ttl=64". Le panneau hexadécimal affiche des données structurées et interprétables.

La différence est immédiate et visuelle : le trafic en clair est entièrement lisible par n'importe quel observateur réseau. Le trafic WireGuard ne révèle rien sur le protocole interne ni le contenu. Un attaquant interceptant ce trafic verrait exactement la même chose : des paquets UDP vers le port 51820, avec un contenu opaque.

### 4.5 Problème rencontré et résolu

| Problème | Cause | Résolution |
|---|---|---|
| Permission refusée lors de `wg genkey` | `sudo` ne se propage pas dans un pipeline : `tee` et `>` s'exécutaient sans droits root | Passer en root complet avec `sudo su -` avant la séquence |

---

## 5. Phase 3 — Routage internet et résilience de l'infrastructure

### 5.1 Théorie : NAT/PAT

Les postes internes de NordLogistique utilisent des adresses IP privées (192.168.x.x) définies par la RFC1918. Ces adresses ne sont pas routables sur internet : un routeur internet refuserait de transmettre un paquet venant de 192.168.10.10 car cette adresse n'est pas unique au monde.

Le NAT (Network Address Translation) résout ce problème : le routeur remplace l'IP privée du poste par l'IP publique de l'entreprise avant d'envoyer le paquet sur internet. Quand la réponse revient, le routeur consulte sa table de traduction pour retrouver à quel poste interne elle est destinée et effectue la traduction inverse.

Le PAT (Port Address Translation), aussi appelé NAT overload, est la variante utilisée dans 99% des PME : une seule IP publique est partagée entre tous les postes internes. Pour distinguer les flux, le routeur réécrit deux champs dans chaque paquet : l'IP source (privée → publique) et le port source (remplacé par un port unique assigné par le routeur). Le routeur maintient une table NAT qui associe chaque paire (IP privée : port source) à un port public, ce qui lui permet de savoir à qui retourner chaque réponse.

Lecture de la table NAT avec `show ip nat translations` :

| Colonne | Signification |
|---|---|
| Inside local | IP privée réelle du poste interne |
| Inside global | IP publique vue depuis internet (après traduction) |
| Outside local | IP de la destination vue depuis l'intérieur |
| Outside global | IP de la destination réelle sur internet |

**Trois variantes NAT :**

- **NAT statique** : 1 IP privée associée à 1 IP publique fixe permanente. Utilisé pour les serveurs exposés (web, mail). Syntaxe : `ip nat inside source static [IP privée] [IP publique]`
- **NAT dynamique** : un pool d'IPs publiques est disponible, l'attribution est temporaire et à la demande. Rare en PME.
- **PAT (NAT overload)** : N IPs privées partagent 1 IP publique via les ports. C'est le cas standard PME. Syntaxe : `ip nat inside source list [ACL] interface [outside] overload`

La règle PAT fait référence à une ACL (Access Control List) qui liste les adresses IP sources autorisées à être traduites. Une ACL standard (numéros 1-99) filtre uniquement sur l'IP source : c'est celle utilisée ici. Une ACL étendue (numéros 100-199) permettrait de filtrer également sur la destination, le port et le protocole.

Le wildcard mask est utilisé dans les ACL Cisco pour définir la plage d'IPs concernées. Il se calcule ainsi : 255.255.255.255 − masque normal. Pour un réseau /24 : 255.255.255.255 − 255.255.255.0 = 0.0.0.255. Le 0 signifie "ce bit doit correspondre exactement", le 255 signifie "ce bit peut être n'importe quoi".

### 5.2 Configuration NAT/PAT sur R-NL

#### Étape 1 — Interface WAN

Commandes entrées en mode configuration global sur R-NL :

```
R-NL(config)# interface gig0/2
R-NL(config-if)#  ip address 203.0.113.1 255.255.255.0
R-NL(config-if)#  no shutdown
R-NL(config-if)#  ip nat outside
R-NL(config-if)# exit
```

- `ip address 203.0.113.1 255.255.255.0` : IP de l'interface WAN simulée
- `ip nat outside` : déclare cette interface comme côté "internet" — les paquets sortant par cette interface auront leur IP source traduite

Le Server0 (serveur web externe simulé) est connecté à Gig0/2 avec l'IP 203.0.113.2 et la passerelle 203.0.113.1. La passerelle 203.0.113.1 est nécessaire pour que le serveur puisse répondre aux paquets dont l'IP destination a été traduite par R-NL.

#### Étape 2 — ACL définissant les sources à traduire

Commandes entrées en mode configuration global sur R-NL :

```
R-NL(config)# access-list 1 permit 192.168.10.0 0.0.0.255
R-NL(config)# access-list 1 permit 192.168.20.0 0.0.0.255
R-NL(config)# access-list 1 permit 192.168.30.0 0.0.0.255
```

L'ACL 1 (standard) liste les trois sous-réseaux internes autorisés à être traduits. Le wildcard 0.0.0.255 couvre les 256 adresses du sous-réseau.

#### Étape 3 — Règle PAT

Commande entrée en mode configuration global sur R-NL :

```
R-NL(config)# ip nat inside source list 1 interface gig0/2 overload
```

Décomposition :

- `ip nat inside source` : configure la traduction des adresses sources venant de l'intérieur
- `list 1` : fait référence à l'ACL 1 définie ci-dessus. Seules les IPs de cette liste sont traduites
- `interface gig0/2` : l'IP publique utilisée pour la traduction est celle de cette interface (203.0.113.1)
- `overload` : active le mode PAT. Plusieurs connexions simultanées partagent la même IP publique, distinguées par les numéros de port

#### Étape 4 — Déclarer les interfaces inside

Commandes entrées en mode configuration global sur R-NL :

```
R-NL(config)# interface gig0/0.10
R-NL(config-subif)#  ip nat inside
R-NL(config-subif)# exit
R-NL(config)# interface gig0/1.20
R-NL(config-subif)#  ip nat inside
R-NL(config-subif)# exit
R-NL(config)# interface gig0/1.30
R-NL(config-subif)#  ip nat inside
R-NL(config-subif)# exit
```

`ip nat inside` sur chaque sous-interface déclare que le trafic venant de ces interfaces provient du réseau interne et doit être traduit quand il sort vers l'interface outside.

#### Validation

Commande entrée en mode privilégié sur R-NL, après un ping depuis un PC interne vers 203.0.113.2 :

```
R-NL# show ip nat translations
```

Après un ping depuis PC-RH-1 vers 203.0.113.2, cette commande affiche les entrées de la table NAT avec les colonnes Inside local / Inside global / Outside local / Outside global. Les entrées sont dynamiques et disparaissent après quelques secondes d'inactivité. Il s'agit d'un comportement normal.

### 5.3 Positionnement IDS/IPS dans l'architecture

L'infrastructure déployée assure la segmentation interne et le filtrage du trafic sortant, mais ne détecte pas les intrusions. Un IDS (Intrusion Detection System) ou un IPS (Intrusion Prevention System) compléterait naturellement cette architecture.

Sans système de détection, une attaque qui passe les ACL du routeur atteint directement les postes des salariés sans déclencher aucune alerte. Un IDS observe le trafic et alerte en cas de comportement suspect sans intervenir : c'est un système passif, connecté via un port miroir qui lui envoie une copie du trafic. Un IPS va plus loin : placé en coupure active dans le flux réseau, il peut bloquer en temps réel le trafic identifié comme malveillant. La différence fondamentale est que l'IDS détecte et alerte, l'IPS détecte et agit.

Les deux systèmes utilisent deux modes de détection : par signature (comparaison avec une base d'attaques connues, efficace mais aveugle aux zero-day) et par anomalie (comparaison avec une baseline de trafic normal, détecte les comportements inhabituels mais génère davantage de faux positifs).

Dans l'architecture NordLogistique, un IPS se placerait entre R-NL et les switches d'accès. Le trafic entrant a déjà été filtré une première fois par les ACL du routeur, donc l'IPS analyserait ce qui a passé ce premier filtre avant que ça atteigne les postes des salariés. En pratique, il est conseillé de déployer d'abord en mode IDS pour observer le trafic et affiner les règles, puis de basculer en mode IPS une fois la baseline établie, car un IPS mal configuré risque de bloquer du trafic légitime et de paralyser la production.

**Exemples d'outils :** Suricata (open source, à la fois IDS et IPS, déjà croisé dans les labs Splunk BOTS v1), Snort (open source, référence historique).

### 5.4 Diagnostic de pannes réseau

#### Méthodologie

Le diagnostic réseau suit toujours deux règles non négociables, quelle que soit l'intuition initiale :

**Règle 1 — Ordre des couches OSI : toujours du bas vers le haut.**
L1 (physique) → L2 (liaison) → L3 (réseau) → L4 (transport) → L7 (application). Vérifier L1 avant L3 évite de perdre du temps à chercher un problème de routage alors qu'un câble est simplement débranché.

Les couches 5 (Session) et 6 (Présentation) ne font pas l'objet d'un diagnostic isolé car leurs problèmes se manifestent en pratique au niveau applicatif (L7) et sont traités à ce niveau.

**Règle 2 — Ordre des équipements : PC → Switch → Routeur.**
On suit le chemin du paquet depuis sa source. Si deux PCs sont touchés simultanément, le problème vient d'un équipement en amont, pas des postes eux-mêmes.

| Couche | Ce qu'on vérifie | Commande principale |
|---|---|---|
| L1 — Physique | Interface up/down, câble branché | `show ip interface brief` |
| L2 — Liaison | VLAN correct, trunk configuré | `show vlan brief`, `show interfaces trunk` |
| L3 — Réseau | IP, masque, passerelle, routes, NAT | `ping`, `show ip route`, `show ip nat translations` |
| L4 — Transport | Port ouvert, pare-feu bloque | `telnet [ip] [port]` |
| L7 — Application | Service démarré, répond correctement | `curl`, navigateur |

**Note importante :** `show vlan brief` n'affiche que les ports en mode access : les ports trunk n'y apparaissent pas. Pour les trunks : `show interfaces trunk`. `show ip interface brief` est disponible sur les routeurs ET les switches Cisco.

**Note importante 2 :** Les quatre pannes diagnostiquées dans ce lab couvraient les couches L1, L2 et L3. Les couches L4 (Transport) et L7 (Application) font partie de la méthodologie complète de diagnostic OSI mais n'ont pas été mises en pratique ici. De plus les pannes ont été introduites, puis un délai de 24h a été laissé afin d'oublier suffisamment de détails sur la panne.

#### Exercice de diagnostic — 4 pannes réelles

**Panne 1 — Interface en shutdown (L1)**

*Symptôme :* PC-RH-1 ne ping plus rien, pas même sa passerelle.

*Diagnostic :*

Le PC est inspecté en premier : IP, masque et passerelle sont corrects. La carte réseau est active. Le problème vient d'un équipement en amont.

SW-RH est inspecté avec `show ip interface brief` : Fa0/1 et Fa0/2 sont up (ports PCs RH normaux), **Gig0/1 est administratively down** (le trunk vers R-NL est anormal).

On confirme avec `show interfaces Gig0/1 switchport` : Administrative Mode trunk, Operational Mode **down**.

*Cause identifiée :* Gig0/1 de SW-RH est en shutdown : le lien entre SW-RH et R-NL est coupé. Panne sur la couche L1.

*Correction :*

```
SW-RH(config)# interface GigabitEthernet0/1
SW-RH(config-if)# no shutdown
```

`no shutdown` annule le shutdown. `no` devant une commande Cisco IOS supprime cette commande de la configuration.

*Validation :* ping PC-RH-1 vers 192.168.10.1 : succès.

---

**Panne 2 — Mauvaise passerelle (L3)**

*Symptôme :* PC-INFO-1 ping les machines du VLAN 20 mais ne ping plus les autres VLANs ni internet.

*Diagnostic :*

Le ping intra-VLAN fonctionne : L1 et L2 côté PC sont corrects. La communication intra-VLAN ne passe pas par la passerelle : les machines du même réseau se joignent directement via le switch au niveau L2. Le problème est donc en L3, côté PC ou routeur. On inspecte le PC en premier car il est la source du paquet.

Inspection du PC-INFO-1 via Desktop → IP Configuration : IP 192.168.20.10, masque 255.255.255.0, **passerelle 192.168.20.254** au lieu de 192.168.20.1.

*Explication du symptôme :* quand PC-INFO-1 veut joindre une machine hors de son réseau, il envoie le paquet à sa passerelle. Mais 192.168.20.254 n'existe pas : personne ne répond à cette adresse. En revanche, pour joindre PC-INFO-2 (même sous-réseau), la passerelle n'est pas consultée, donc la communication fonctionne.

*Cause identifiée :* mauvaise passerelle saisie manuellement. En production, ce type d'erreur survient lors d'une faute de frappe ou si le serveur DHCP distribue une mauvaise passerelle par défaut. Panne sur la couche L3.

*Correction :* Desktop → IP Configuration → Default Gateway → 192.168.20.1.

*Validation :* ping PC-INFO-1 vers PC-RH-1 : succès.

---

**Panne 3 — VLAN retiré du trunk (L2)**

*Symptôme :* PC-DIR-1 et PC-DIR-2 ne pinguent plus rien hors VLAN 30.

*Diagnostic :*

Deux PCs sont touchés simultanément : le problème vient d'un équipement en amont. On commence par inspecter SW-INFO-DIR.

`show ip interface brief` : Gig0/1 up : L1 correct.

`show interfaces trunk` :

```
Port     Vlans allowed on trunk
Fa0/24   10,20,30
Gig0/1   10,20 
```

*Cause identifiée :* VLAN 30 est absent des VLANs autorisés sur le trunk Gig0/1 de SW-INFO-DIR. Les trames VLAN 30 ne peuvent pas passer vers le routeur. Panne sur la couche L2.

*Correction :*

```
SW-INFO-DIR(config)# interface gig0/1
SW-INFO-DIR(config-if)# switchport trunk allowed vlan add 30
```

`switchport trunk allowed vlan add 30` ajoute le VLAN 30 à la liste existante sans écraser les autres VLANs. Sans le mot-clé `add`, la commande remplacerait toute la liste par "30 uniquement" (les VLANs 10 et 20 disparaîtraient). C'est une erreur classique en production.

*Validation :* `show interfaces trunk` : Gig0/1 affiche 10,20,30. Ping PC-DIR-1 vers PC-RH-1 : succès.

---

**Panne 4 — Règle NAT supprimée (L3/NAT)**

*Symptôme :* aucun PC ne peut accéder au serveur web externe (203.0.113.2).

*Diagnostic :*

Tous les PCs sont touchés simultanément : le problème est sur le routeur. On inspecte R-NL couche par couche.

L1 — `show ip interface brief` : toutes les interfaces up. C'est correct.

L2 — Les sous-interfaces sont opérationnelles. C'est correct.

L3 — `show ip route` : entrée "C" (Connected) pour 203.0.113.0/24 via Gig0/2. R-NL sait où se trouve la destination. La table de routage est correcte.

L3/NAT — `show running-config` : interfaces inside/outside sont correctement déclarées, les ACL sont présentes. En revanche, **la ligne `ip nat inside source list 1 interface gig0/2 overload` est absente**.

*Cause identifiée :* sans cette règle, le routeur ne traduit pas les adresses : les paquets partent avec leur IP privée source (192.168.x.x). Elles ne sont pas routables sur internet. Panne en couche L3/NAT.

*Correction :*

```
R-NL(config)# ip nat inside source list 1 interface gig0/2 overload
```

*Validation :* ping PC-RH-1 vers 203.0.113.2 : succès (le premier paquet est perdu pendant l'initialisation de la table NAT mais c'est un comportement normal sur Packet Tracer).

---

#### Bilan des pannes

| Panne | Couche | Cause | Commande clé de diagnostic | Correction |
|---|---|---|---|---|
| 1 | L1 | Gig0/1 SW-RH en shutdown | `show ip interface brief` | `no shutdown` |
| 2 | L3 | Mauvaise passerelle PC-INFO-1 | IP Configuration PC | Correction passerelle |
| 3 | L2 | VLAN 30 retiré du trunk SW-INFO-DIR | `show interfaces trunk` | `switchport trunk allowed vlan add 30` |
| 4 | L3/NAT | Règle PAT supprimée sur R-NL | `show running-config` | `ip nat inside source list 1 interface Gig0/2 overload` |

### 5.5 Analyse globale

L'infrastructure déployée apporte une sécurité concrète par rapport à la situation initiale : les départements sont isolés les uns des autres, l'accès à internet est réglementé et l'accès aux ressources de l'entreprise depuis l'extérieur se fait via un tunnel chiffré. En cas de compromission d'un poste, l'isolation par VLAN limite la propagation latérale car il est possible de contrôler précisément le trafic autorisé entre chaque VLAN. Il sera également possible d'instaurer des règles d'accès à internet par VLAN, et toute machine non assignée à un VLAN existant se retrouvera complètement isolée, sans accès nulle part. Enfin, le tunnel WireGuard garantit que les données échangées entre un salarié en télétravail et le réseau interne restent chiffrées et illisibles pour un éventuel attaquant.

Les 3 phases de ce lab sont complémentaires car elles s'enchaînent dans un ordre logique, permettant de couvrir et sécuriser tous les flux de l'entreprise : la phase 1 sécurise le réseau interne de l'entreprise. La seconde permet de gérer les flux entrants et la troisième les flux sortants. Chaque étape est donc essentielle pour assurer un contrôle de l'ensemble des données qui transitent au sein de l'entreprise.

---

## 6. Bonnes pratiques appliquées

1. **Convention de nommage explicite** (SW-RH, R-NL, PC-RH-1) : tout technicien qui reprend le dossier identifie immédiatement chaque équipement
2. **`no ip domain-lookup`** permet d'éviter les blocages de 30 secondes sur fautes de frappe en CLI
3. **`enable secret` plutôt que `enable password`** : `enable secret` stocke le mot de passe hashé en MD5, tandis qu'`enable password` le stocke en clair. `enable secret` est donc toujours préférable.
4. **Bannière MOTD** : elle affiche un avertissement légal à chaque connexion, ce qui est obligatoire avant toute action judiciaire sur une connexion non autorisée.
5. **Native VLAN changé vers VLAN inutilisé (999)** : protection contre le VLAN hopping (technique où un attaquant réussit à envoyer du trafic vers un VLAN auquel il n'est pas censé avoir accès)
6. **Ports inutilisés désactivés ET dans VLAN poubelle** : c'est de la défense en profondeur (isolation logique + physique)
7. **Restriction des VLANs autorisés sur les trunks** : seuls les VLANs nécessaires transitent
8. **Clés WireGuard générées sur chaque machine séparément** : la clé privée ne quitte jamais sa machine
9. **`copy running-config startup-config` après chaque bloc** pour assurer la persistance au redémarrage
10. **Diagnostic progressif systématique** : L1 → L2 → L3, PC → Switch → Routeur

---

## 7. Limites et points d'amélioration

**ACL inter-VLAN absentes.** Le routeur laisse passer tout le trafic inter-VLAN sans restriction. En production, des ACL étendues contrôleraient plus finement les flux, par exemple le département RH ne devrait pas pouvoir accéder aux serveurs de l'Informatique sur tous les ports.

**Authentification Cisco basique.** Les mots de passe utilisés (`enable secret` type 5 — MD5) sont acceptables en lab mais insuffisants en production. La recommandation actuelle est le type 9 (SHA-256). Cependant il n'est pas supporté dans Packet Tracer.

**`service password-encryption` type 7 réversible.** Le chiffrement type 7 peut être inversé avec des outils publics. En production, tous les mots de passe sensibles doivent utiliser des mécanismes de hashage forts.

**WireGuard sans rotation des clés.** Dans ce lab, les clés sont permanentes. En production, une rotation périodique est recommandée pour limiter l'impact d'une compromission.

**IDS/IPS :** il n'y a pas de système de détection d'intrusion actuellement. Suricata en mode IDS pourrait être un premier déploiement recommandé, avant de basculer en IPS une fois la baseline établie.

**Documentation :** formaliser la méthode de diagnostic OSI dans un runbook pour les équipes internes pourrait permettre de faciliter le dépannage à l'avenir.

---

## 8. Conclusion

Ce projet documente le déploiement d'une infrastructure réseau complète pour NordLogistique, couvrant la segmentation, l'accès distant et le routage internet. Il m'a permis de découvrir comment concevoir et sécuriser une infrastructure réseau PME en prenant en compte l'ensemble des flux : internes, entrants et sortants. Au-delà de la configuration des équipements, j'ai pu appréhender concrètement le fonctionnement des switches et routeurs Cisco, et découvrir des concepts fondamentaux comme le trunk, le NAT et le PAT. La partie diagnostic m'a permis de mettre en pratique le modèle OSI sur des pannes réelles, ce qui m'a aidé à mieux comprendre comment les couches interagissent concrètement, au-delà de la théorie.

---

*Write-up rédigé dans le cadre d'un parcours de reconversion en cybersécurité*
