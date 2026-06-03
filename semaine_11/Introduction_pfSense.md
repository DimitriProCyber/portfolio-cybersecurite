# Déploiement pfSense et politique de filtrage réseau

**03 juin 2026**

**Environnement :** Home lab VirtualBox — Kali Linux · pfSense 2.8.1 · Metasploitable 2  
**Objectif :** Déployer un pare-feu réseau dédié sur machine séparée, configurer une politique de filtrage whitelist, et valider son efficacité par des tests réels.  
**Outils :** pfSense 2.8.1-RELEASE, curl, ssh, nmap  
**Niveau :** Lab guidé — Niveau 1


## 1. Contexte

Dans un réseau d'entreprise, un pare-feu logiciel installé sur chaque poste ne suffit pas. Pour contrôler efficacement le trafic entre plusieurs machines ou entre le réseau interne et l'extérieur, il faut un pare-feu en **coupure** — c'est-à-dire une machine dédiée positionnée de sorte que tout le trafic réseau transite physiquement par elle.

pfSense est un pare-feu/routeur open source basé sur FreeBSD, distribué gratuitement par Netgate. Il offre des fonctionnalités comparables à des solutions commerciales (Cisco ASA, Fortinet) et est largement utilisé par les PME et en environnement de lab.

Un pare-feu se doit d'être sur une machine séparée de celles qu'il protège car cela lui permet d'être en position de coupure du réseau : il sépare physiquement différentes parties du réseau. En cas de compromission d'une machine, le trafic vers les autres machines passe obligatoirement par le pare-feu, qui peut le bloquer selon les règles définies, isolant ainsi machines les unes des autres. De plus, si le pare-feu était directement sur une des machines qu'il est censé protéger, lorsque cette machine voudrait communiquer avec le réseau, ses communications ne passeraient pas par celui-ci.


## 2. Architecture du lab

### 2.1 Schéma réseau

```
Internet (simulé — pas d'accès réel)
                                 |
[VirtualBox — réseau Host-Only 192.168.56.x]
       |                                |                                  |
  [Kali eth0]  [pfSense WAN em0]  [Metasploitable 2]
192.168.56.100  192.168.56.105    192.168.56.101
 (désactivé)                   |
                                 [pfSense]
                                  routage
                                       |
                       [pfSense LAN em1]
                             192.168.1.1
                                       |
      [Réseau interne VirtualBox "pfsense-lan"]
                                       |
                               [Kali eth2]
                            192.168.1.100
             (interface active pendant le lab)
```

### 2.2 Interfaces réseau

| Machine | Interface | Réseau VirtualBox | IP | Rôle |
|---|---|---|---|---|
| pfSense | em0 (WAN) | Host-Only 192.168.56.x | 192.168.56.105/24 (statique) | Côté non-fiable |
| pfSense | em1 (LAN) | Réseau interne "pfsense-lan" | 192.168.1.1/24 | Côté protégé — gateway |
| Kali | eth2 | Réseau interne "pfsense-lan" | 192.168.1.100/24 (DHCP) | Machine testeur |
| Metasploitable 2 | eth0 | Host-Only 192.168.56.x | 192.168.56.101/24 | Cible vulnérable |

### 2.3 Pourquoi désactiver eth0 sur Kali

Kali dispose de deux interfaces réseau. Sans intervention, eth0 (192.168.56.100) lui donne un accès direct à Metasploitable (192.168.56.101) sur le même réseau Host-Only — pfSense ne voit pas ce trafic et ne peut pas le filtrer.

Pour forcer tout le trafic à passer par pfSense, eth0 est désactivée :

```bash
sudo ip link set eth0 down
```

La table de routage résultante confirme que pfSense est le seul chemin :

```
default via 192.168.1.1 dev eth2
192.168.1.0/24 dev eth2 proto kernel scope link src 192.168.1.100
```

`default via 192.168.1.1` : tout trafic vers une destination inconnue est envoyé à pfSense.  
`192.168.1.0/24 dev eth2` : seul le réseau LAN est accessible directement.

Si eth0 n'avait pas été désactivé, pfSense n'aurait pas vu le trafic entre Kali et Metasploitable 2 car les deux machines auraient eu un accès direct via le réseau Host-Only. Cela démontre que le positionnement du pare-feu est essentiel pour éviter de se retrouver avec des accès qui ne sont pas contrôlés et protégés. S'il existe ne serait-ce qu'un seul chemin qui permet de contourner le pare-feu, alors en cas de compromission l'attaquant le trouvera et l'utilisera pour s'étendre sur le réseau sans être détecté par le pare-feu.


## 3. Installation et configuration

### 3.1 Installation de pfSense

La version open source pfSense CE n'est plus distribué en ISO direct depuis 2023. L'installation se fait via le Netgate Installer (compte gratuit sur netgate.com), qui télécharge les composants en ligne : un accès internet temporaire est donc nécessaire pendant l'installation uniquement.

**Configuration VM VirtualBox :**

| Paramètre | Valeur | Raison |
|---|---|---|
| Type | BSD / FreeBSD 64-bit | pfSense est basé sur FreeBSD |
| RAM | 1 Go | OS spécialisé routage/filtrage — pas d'interface graphique lourde |
| Disque | 10 Go VDI | Suffisant pour l'OS et les logs |
| Adapter 1 (installation) | NAT temporaire | Accès internet requis pour l'installeur en ligne |
| Adapter 1 (post-install) | Host-Only | Interface WAN simulée |
| Adapter 2 | Réseau interne "pfsense-lan" | Interface LAN isolée |

**Paramètres d'installation :** système de fichiers ZFS, stripe (disque unique), pfSense CE 2.8.1 (version communautaire gratuite).

**Problèmes rencontrés :**
- VM créée automatiquement en 32-bit → apparition d'une erreur *"CPU doesn't support long mode"* lors du lancement → recréée en FreeBSD 64-bit
- Après installation, VM redémarrait sur l'ISO encore attaché → ISO détaché, redémarrage sur disque

### 3.2 Configuration initiale

Après installation, pfSense démarre sur une console texte. La WebGUI n'est accessible que depuis le LAN, une fois les interfaces configurées. La console permet ce bootstrap initial via deux options :
- **Option 1** — Assign Interfaces : associer em0 au WAN et em1 au LAN
- **Option 2** — Set interface IP address : configurer les IPs de chaque interface

**Paramètres de l'assistant de configuration :**

| Paramètre | Valeur | Raison |
|---|---|---|
| Timezone | Europe/Paris | Heure locale |
| DNS | vide | Pas d'accès internet en lab |
| RFC1918 blocking WAN | **Désactivé** | Le WAN est un réseau privé simulé (192.168.56.x) — l'activer bloquerait tout le trafic lab |
| Bogon blocking | Activé | Bloque les IPs non assignées par l'IANA — bonne pratique |

**Note :** En production, le WAN est connecté à internet (IPs publiques). Le blocage RFC1918 doit rester activé — des IPs privées arrivant depuis internet sont anormales et indiquent une tentative de spoofing.

### 3.3 IP WAN statique

L'IP WAN attribuée par DHCP VirtualBox (192.168.56.105) doit être fixée en statique avant toute création de règles car une règle ciblant une IP qui change au prochain redémarrage devient immédiatement obsolète.

**Procédure (console pfSense, Option 2, interface WAN) :**

| Paramètre | Valeur |
|---|---|
| Configure IPv4 via DHCP | no |
| New WAN IPv4 address | 192.168.56.105 |
| Subnet bit count | 24 |
| Upstream gateway | 192.168.56.1 |
| Default gateway | yes |
| Configure IPv6 via DHCP | no |
| DHCP server on WAN | no |
| Revert to HTTP | no |

**Gateway 192.168.56.1 :** VirtualBox joue le rôle de routeur sur le réseau Host-Only et prend toujours l'adresse .1. C'est vers lui que pfSense envoie tout trafic destiné à sortir du réseau 192.168.56.x.


## 4. Politique de filtrage

### 4.1 Principes

Deux approches existent pour la politique de filtrage :

- **Blacklist** : tout est autorisé par défaut, on bloque ce qu'on connaît de mauvais. Le risque est de laisser passer automatiquement une menace inconnue.
- **Whitelist** : tout est interdit par défaut, on n'autorise que ce qui est explicitement nécessaire. La règle finale "deny all" bloque tout le reste, y compris les menaces inconnues.

Ce lab applique une politique **whitelist** — principe du moindre privilège.

### 4.2 Règles créées (interface LAN)

Les règles sont évaluées dans l'ordre **haut → bas**. La première règle qui correspond au trafic s'applique et les suivantes sont ignorées, quelle que soit leur contenu.

| Ordre | Action | Protocol | Source | Destination | Port | Log | Description |
|---|---|---|---|---|---|---|---|
| 1 | Pass (auto) | any | any | LAN Address | 443, 80 | — | Anti-Lockout Rule |
| 2 | Block | TCP | 192.168.1.100 | 192.168.56.101 | 80 (HTTP) | ✓ | Block Kali HTTP to Metasploitable |
| 3 | Pass | TCP | 192.168.1.100 | 192.168.56.101 | 22 (SSH) | ✓ | Allow Kali SSH to Metasploitable |
| 4 | Block | any | any | any | any | ✓ | Block all LAN to any |
| 5 | Pass (désactivée) | IPv4 | LAN subnets | any | any | — | Default allow LAN to any rule |

Dans cette configuration l'ordre des règles est critique car il peut déterminer si les machines peuvent communiquer entre elles ou si tout le trafic est bloqué. Par exemple, si la règle 4 "Block all LAN to any" se retrouve avant la 3ème règle "Allow Kali SSH to Metasploitable", lorsque Kali cherchera à se connecter au port 22 de Metasploitable, pfSense appliquerait la règle Block all en premier et bloquerait la connexion SSH sans jamais évaluer la règle Allow qui suit. Le même raisonnement s'applique entre la règle 2 et la règle 5 (désactivée ici) : si "Default allow LAN to any rule" était activée et se retrouvait placée avant "Block Kali HTTP to Metasploitable", alors Kali pourrait joindre Metasploitable en HTTP et la règle serait caduque.

### 4.3 Stateful filtering

pfSense ne juge pas chaque paquet de manière indépendante. Il maintient une **table d'états** : dès qu'une connexion est autorisée, les paquets de retour sont automatiquement acceptés sans réévaluer les règles.

Conséquence pratique lors des tests : après la création d'une règle de blocage, les connexions déjà établies avant la règle continuaient à fonctionner. Il a fallu vider la table d'états (`Diagnostics → States → Reset States`) pour forcer pfSense à réévaluer le trafic selon les nouvelles règles.


## 5. Validation

### 5.1 Test 1 — Blocage HTTP (règle 2)

```bash
curl -v http://192.168.56.101
```

`curl` : outil de transfert de données en ligne de commande  
`-v` : mode verbose — affiche les détails de la connexion (tentatives, headers, erreurs)  
`http://192.168.56.101` : cible le serveur web de Metasploitable sur le port 80

**Résultat :**
```
* Trying 192.168.56.101:80...
* connect to 192.168.56.101 port 80 failed: Connection terminée par expiration du délai d'attente
* Failed to connect to 192.168.56.101 port 80 after 133307 ms: Could not connect to server
```

Le résultat de la commande `curl` est un timeout de 133s car on utilise une fonction Block plutôt que Reject dans la règle. La fonction Block permet au pare-feu d'ignorer le paquet et de faire comme s'il ne l'avait jamais reçu, alors que Reject aurait renvoyé une erreur directement à l'expéditeur lui indiquant que son paquet avait été bloqué. La fonction Block est préférable en production car elle ne donne aucune information à un potentiel attaquant.

### 5.2 Test 2 — Autorisation SSH (règle 3)

```bash
ssh msfadmin@192.168.56.101
```

`ssh` : protocole de connexion distante chiffrée  
`msfadmin` : compte utilisateur sur Metasploitable  
`@192.168.56.101` : adresse IP de la cible

**Résultat :** la connexion est établie et on obtient un prompt Metasploitable.

**Vérification dans pfSense (`Firewall → Rules → LAN — colonne States`) :**

| Règle | States | Interprétation |
|---|---|---|
| Block Kali HTTP to Metasploitable | 0/1 KiB | A bloqué les tentatives HTTP |
| Allow Kali SSH to Metasploitable | 1/8 KiB | A traité la connexion SSH |
| Block all LAN to any | 0/33 KiB | A bloqué 33 KiB de trafic non autorisé |
| Default allow LAN to any rule | 0/0 B | Désactivée — aucun trafic |

### 5.3 Test 3 — Scan Nmap et observation des logs

```bash
nmap -sS -Pn 192.168.56.101
```

`nmap` : outil de découverte réseau et d'audit de sécurité  
`-sS` : SYN scan — envoie un paquet TCP SYN sur chaque port sans compléter le Three-Way Handshake. Rapide et discret.  
`-Pn` : désactive le host discovery (ping préalable) — considère la cible comme active et scanne directement. Nécessaire ici car pfSense bloque l'ICMP.  
`192.168.56.101` : adresse IP de Metasploitable

**Résultat Nmap :**
```
999 filtered ports (no-response)
22/tcp open ssh
```

**Logs firewall pendant le scan (`Status → System Logs → Firewall → Dynamic View`) :**

```
❌ Jun 3 00:58:18  LAN  192.168.1.100:52952 → 192.168.56.101:6646  TCP:S
❌ Jun 3 00:58:18  LAN  192.168.1.100:52952 → 192.168.56.101:3920  TCP:S
❌ Jun 3 00:58:18  LAN  192.168.1.100:52952 → 192.168.56.101:5054  TCP:S
[... centaines d'entrées similaires en quelques secondes ...]
✅ Jun 3 00:58:18  LAN  192.168.1.100:52952 → 192.168.56.101:22    TCP:S
```

Les logs révèlent que de nombreuses tentatives de connexion ont eu lieu, la majorité ayant échoué et qu'une a été réalisée avec succès. Le fait qu'il y ait eu 1000 tentatives en quelques secondes, et que chaque tentative ait été réalisée sur un port différent, indique à un analyste SOC que quelqu'un a cherché à scanner le réseau à l'aide d'un outil spécialisé. L'élément `TCP:S` indique que l'outil a effectué son scan grâce à l'envoi de paquets `SYN` dans le but d'établir une connexion TCP. Les paquets ont été interceptés par pfSense grâce à la règle 4.

Concernant le résultat Nmap, l'attaquant potentiel voit qu'une connexion (SSH) est possible sur la machine qu'il a scanné, mais que le scan des 999 autres ports n'a pas donné de réponse. Il ne sait pas si ses paquets ont été filtrés ou s'ils ont été perdus.


## 6. Analyse

Cet exercice permet de démontrer plusieurs choses applicables directement dans un contexte professionnel :

- La politique de whitelist apporte un gage de sécurité supérieur à celle de la blacklist : il est en effet bien plus sécurisant de bloquer l'ensemble des connexions et de n'autoriser que celles qui sont nécessaires. Cela limite les erreurs potentielles, laissant des connexions ouvertes par inadvertance. De plus, il est plus simple de n'autoriser que les connexions nécessaires que de devoir bloquer une par une tous les ports inutiles : cela prendra plus de temps car le volume sera bien plus important et le risque d'erreur d'inadvertance sera augmenté.

- Les logs firewall permettent de détecter les tentatives de connexion vers chaque machine du réseau. Il est important de les activer afin de garder une trace systématique des connexions qui s'établissent ou tentent de s'établir. Lors d'une compromission ou toute tentative associée, ces traces serviront pour l'investigation forensique, et permettront de retracer le chemin potentiel de l'attaquant sur le réseau.

- Avant le déploiement de tout outil dans un contexte de production, il est important de comprendre son fonctionnement mais également le raisonnement derrière son utilisation. Ce lab m'a permis de réaliser une première approche de pfSense et de comprendre le fonctionnement de base du pare-feu. Cependant j'ai également eu l'occasion de réfléchir à *pourquoi* chaque décision était prise : l'importance de l'ordre des règles et l'impact d'un ordre différent, choix de Block plutôt que Reject, nécessité de désactiver eth0 dans le contexte de ce lab et plus largement l'impact d'une interface réseau permettant une connexion qui passe outre le pare-feu.


## 7. Recommandations

En contexte de production, les éléments suivants seraient à mettre en place :

**1. Segmentation réseau (DMZ)**  
La segmentation réseau permet de limiter les risques en cas de compromission : un serveur ou un système de messagerie aura besoin d'avoir un accès à internet, cependant cela va augmenter les risques. Le fait de le mettre dans une zone séparée du LAN de l'entreprise, qui n'a aucun besoin d'accéder à internet, permet d'assurer une sécurité supplémentaire. Toutes les connexions qui transiteront entre le LAN et la zone séparée devront passer par le pare-feu et seront surveillées selon les règles appliquées : on ne pourra pas aller n'importe où ni n'importe comment.

**2. Accès WebGUI**  
L'interface d'administration pfSense est accessible uniquement depuis le LAN par défaut : l'accès WAN est bloqué. En production, il est plus sécurisant de restreindre l'accès WebGUI à une adresse IP d'administration spécifique plutôt qu'à tout le LAN (`192.168.1.10/32` plutôt que `LAN subnets`).

**3. Mots de passe**  
Le mot de passe par défaut `admin/pfsense` doit être changé immédiatement après installation pour assurer la sécurité du pare-feu. Dans ce lab, `admin/password` a été utilisé. Ce choix est acceptable uniquement en environnement de lab isolé.

**4. Supervision des logs (SIEM)**  
pfSense dispose d'un espace de stockage local limité pour les logs. En production, il faudra configurer l'export vers un serveur syslog centralisé ou un SIEM (Splunk, Elastic) pour la conservation long terme et la corrélation d'événements.

**5. Synchronisation NTP**  
Lors d'une investigation forensique, si les horloges des machines ne sont pas alignées, la récolte d'information devient impossible si un log indique 14h pour un événement alors qu'un autre indique 16h. Il est donc primordial de synchroniser l'heure entre machines réseau pour s'assurer de pouvoir reconstituer la chronologie d'une attaque.


---

*Write-up rédigé dans le cadre d'une formation cybersécurité*
