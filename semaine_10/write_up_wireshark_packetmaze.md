# Wireshark — PacketMaze : Investigation Réseau

**16 mai 2026**

**Plateforme :** CyberDefenders  
**Challenge :** PacketMaze  
**Difficulté :** Medium  
**Catégorie :** Network Forensics  
**Outil principal :** Wireshark 4.x  
**Fichier analysé :** `UNODC-GPC-001-003-JohnDoe-NetworkCapture-2021-04-29.pcapng` (37 Mo, 45 024 paquets)

---

## 1. Contexte

Un serveur interne d'entreprise a été signalé pour une activité réseau inhabituelle, avec plusieurs connexions sortantes vers des IPs externes inconnues. Une analyse initiale suggère une possible exfiltration de données.  
Le rôle de l'analyste SOC ici est de déterminer la source et le moyen de compromission, ainsi que de confirmer l'exfiltration de données si elle a eu lieu.

---

## 2. Méthodologie

L'investigation suit la méthode SOC en 5 étapes appliquée à l'analyse de captures réseau :

1. **Vue d'ensemble** — `Statistics → Protocol Hierarchy` + `Statistics → Conversations`
2. **Timeline chronologique** — lecture des échanges dans l'ordre temporel avant toute analyse de détail
3. **Filtrage par protocole** — isolation des protocoles en clair en priorité (FTP, HTTP)
4. **Follow Stream** — reconstitution des échanges complets entre deux hôtes
5. **Documentation des IoCs** — timestamp, numéro de paquet, preuve extraite

Les protocoles en clair sont investigués en priorité car ils permettent de voir directement le contenu des échanges, contrairement aux protocoles chiffrés comme TLS où uniquement les métadonnées sont visibles.

---

## 3. Résultats

### 3.1 Vue d'ensemble — Protocol Hierarchy

**Commande :** `Statistics → Protocol Hierarchy`

| Protocole | % Paquets | Nature |
|-----------|-----------|--------|
| TCP | 94.8% | Transport principal |
| TLS (sur TCP) | 11.3% | Chiffré — contenu illisible |
| FTP-Data | 19.0% | **En clair — priorité** |
| FTP contrôle | 0.2% | Commandes en clair |
| HTTP | 0.01% | En clair |
| UDP total | 4.4% | Dont QUIC, Teredo, Data non identifié |
| Data UDP (non identifié) | 0.5% | Protocole inconnu de Wireshark |

Le protocole FTP-Data est le protocole qui sera investigué en premier. Dans le contexte d'une investigation sur une exfiltration, un protocole qui permet un échange de données et qui est en clair est une cible prioritaire pour l'investigation, car il permettra peut-être de confirmer rapidement cette hypothèse.  
Data UDP non identifié signifie que Wireshark ne reconnaît aucun protocole dans ces échanges. Ce trafic mérite également une attention car il aurait pu être instauré manuellement par un attaquant. Cependant, il est difficile à investiguer car sans connaître le protocole utilisé, on ne sait pas comment les données sont structurées et on ne peut pas les interpréter.

---

### 3.2 Vue d'ensemble — Conversations IPv4

**Commande :** `Statistics → Conversations → onglet IPv4`, trié par volume décroissant

Machine sous investigation : **192.168.1.26** (MAC : `c8:09:a8:57:47:93`, Windows 10 x64). Les IPs qui conversent le plus avec cette machine sont :

| IP | Volume | Sens dominant | Protocole | Résolution DNS |
|----|--------|---------------|-----------|----------------|
| 192.168.1.20 | 17 Mo | Sortant (A→B) | FTP | Machine interne |
| 185.70.41.130 | 10 Mo | Entrant (B→A) | TLS | protonmail.com |
| 185.70.41.35 | 3 Mo | Entrant | TLS | protonmail.com |
| 172.67.162.206 | 1 Mo | 17 947 paquets, peu de données | TLS + ICMP | dfir.science (Cloudflare) |

Ces IPs ont retenu mon attention pour deux raisons : il y a des volumes d'échanges de paquets importants entre la machine sous investigation et l'adresse IP en question et/ou un volume d'échange de données important.  
Les échanges TLS ne peuvent être lus directement car ils sont chiffrés.  
Un volume élevé de paquets avec peu de données vers 172.67.162.206 est inhabituel et mérite investigation. Cela peut indiquer des tentatives de connexion répétées ou un comportement anormal.

---

### 3.3 Investigation FTP

#### Credentials compromis

**Commande :** `ftp` → clic droit → `Follow TCP Stream`

Le filtre `ftp` appliqué dans Wireshark révèle des échanges entre 192.168.1.26 et 192.168.1.20. Le paquet 486 (t=35.835s) marque le début de la session. Clic droit → Follow TCP Stream reconstitue l'intégralité de la session de contrôle FTP.

```
220 Welcome to Hacker FTP service.
AUTH TLS → 530 Please login with USER and PASS.
AUTH SSL  → 530 Please login with USER and PASS.
USER kali
331 Please specify the password.
PASS AfricaCTF2021
230 Login successful.
257 "/home/kali" is the current directory
CWD Documents
250 Directory successfully changed.
```

La bannière "Hacker FTP service" indique qu'il s'agit d'un serveur non légitime car son administrateur l'a intentionnellement configuré avec ce nom.

Le refus de AUTH TLS et AUTH SSL signifie que le serveur n'accepte pas les connexions chiffrées, forçant ainsi une connexion en clair et exposant par conséquent les credentials et le contenu des échanges à toute personne ayant accès au trafic réseau.

---

#### Transferts de fichiers

**Commande :** `ftp` → lecture chronologique des streams

| Commande FTP | Fichier | Taille | Sens | Paquet |
|--------------|---------|--------|------|--------|
| STOR | 20210429_152321.jpg | 8 519 ko | .26 → .20 | 606 |
| STOR | 20210429_152157.jpg | 8 018 ko | .26 → .20 | 7 069 |
| RETR | accountNum.zip | 239 bytes | .20 → .26 | 11 835 |

*Rappel vocabulaire FTP :*  
`STOR` = le client envoie (upload) vers le serveur  
`RETR` = le client télécharge (download) depuis le serveur  
`PASV` = mode passif — le serveur ouvre un port pour la connexion de données

Le fichier le plus suspect est `accountNum.zip` car au vu de son nom il contient probablement des données financières importantes. Le fichier circule de 192.168.1.20 vers 192.168.1.26, ce qui signifie que 192.168.1.26 est probablement la machine depuis laquelle l'attaquant opère.

---

#### Structure du serveur FTP — Dossier non-standard

**Commande :** `ftp-data` → sélectionner un paquet de petite taille → panneau détail

En continuant la lecture chronologique des streams FTP, la commande `LIST` envoyée par le client (paquet 530) déclenche l'envoi du listing du répertoire `/home/kali` par le serveur 192.168.1.20. Ce listing est visible via le filtre `ftp-data` en sélectionnant un paquet de petite taille dans le panneau détail.

Listing de `/home/kali` extrait de la commande `LIST` :

```
drwxr-xr-x  Feb 23 06:37  Desktop
drwxr-xr-x  Apr 29 16:42  Documents
drwxr-xr-x  Feb 23 06:37  Downloads
drwxr-xr-x  Feb 23 06:37  Music
drwxr-xr-x  Feb 23 06:37  Pictures
drwxr-xr-x  Feb 23 06:37  Public
drwxr-xr-x  Feb 23 06:37  Templates
drwxr-xr-x  Feb 23 06:37  Videos
dr-xr-x---  Apr 20 17:53  ftp
```

Le dossier `ftp` est considéré comme non-standard car il ne s'agit pas d'un dossier natif de Kali. Sa création le 20 avril, 9 jours avant la capture, suggère que l'attaquant s'était introduit depuis au moins 9 jours dans le système au moment de son attaque.

---

#### Métadonnées EXIF des images

**Commande :** `File → Export Objects → FTP-Data` → Tout enregistrer → analyser avec `exifmeta.com`

Les fichiers JPG identifiés dans les transferts FTP sont extraits via `File → Export Objects → FTP-Data → Tout enregistrer`. Les métadonnées EXIF sont ensuite analysées via un outil en ligne (`exifmeta.com`).

*EXIF = Exchangeable Image File Format : métadonnées techniques automatiquement intégrées dans un fichier image par l'appareil photo (modèle, date/heure, coordonnées GPS).*

| Métadonnée | Valeur |
|------------|--------|
| Fabricant | LG Electronics |
| Modèle appareil | LM-Q725K |
| Date de création | 2021-04-29 15:21:57 |
| Altitude GPS | 0 m (pas de coordonnées GPS exploitables) |

Ces métadonnées permettent d'identifier le modèle de l'appareil utilisé, et parfois sa position GPS. Cela contribue à l'identification de l'attaquant dans le cadre d'une investigation forensique.

---

### 3.4 Investigation DNS

**Commande :** `dns`

Trafic majoritairement légitime (Microsoft, Google, Akamai). Domaine notable :

**`dfir.science`** résolu vers :
- `104.21.89.171` (Cloudflare)
- `172.67.162.206` (Cloudflare)

*Cloudflare est un CDN (Content Delivery Network) qui fait proxy devant de nombreux sites. Les IPs retournées ne correspondent pas au serveur réel de dfir.science.*

**Serveur DNS utilisé par 192.168.1.26 :**
- IPv4 : `192.168.1.10`
- IPv6 : `fe80::c80b:adff:feaa:1db7`

Pour identifier l'adresse IPv6 du serveur DNS (192.168.1.10), on récupère d'abord son adresse MAC `ca:0b:ad:ad:20:ba` depuis Ethernet II d'un paquet DNS où .10 est source. On applique ensuite le filtre `eth.addr == ca:0b:ad:ad:20:ba && ipv6` pour isoler les paquets IPv6 émis par cette même machine. Son adresse IPv6 apparaît alors dans le champ Source Address : `fe80::c80b:adff:feaa:1db7`.

Le DNS est analysé même quand le trafic applicatif est chiffré car il permet de voir vers quels domaines la machine a essayé de se connecter. La présence de `dfir.science` (Digital Forensics and Incident Response) dans le trafic DNS est notable car ce domaine, lié à la cybersécurité forensique, peut indiquer que l'attaquant cherchait à obtenir des informations sur les techniques forensiques sachant qu'il allait être investigué, ou qu'il s'agissait d'un point de contact externe.

---

### 3.5 Investigation HTTP

**Commande :** `http`

Le filtre `http` révèle 18 paquets en clair. Parmi eux, une requête `GET /` émise par 192.168.1.26 vers `dfir.science` (paquet 26264). Pour voir le contenu de ce paquet : clic droit → Follow TCP Stream.

**Connexion vers dfir.science :**

```
GET / HTTP/1.1
Host: dfir.science
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/90.0.4430.93

HTTP/1.1 301 Moved Permanently
Location: https://dfir.science/
Date: Fri, 30 Apr 2021 01:04:39 GMT
Server: cloudflare
```

Autres échanges HTTP : SwissSign (certificat racine PKI) et OCSP (vérification de validité de certificat) — trafic système normal, non suspect.

*OCSP = Online Certificate Status Protocol : mécanisme permettant à un navigateur de vérifier en temps réel si un certificat TLS est valide.*

Le code HTTP 301 indique que le serveur redirige de manière permanente vers `https://dfir.science/`, confirmant que `dfir.science` force le HTTPS. Le User-Agent révèle que la requête vient d'un Windows NT 10.0 x64, ce qui confirme le type de machine utilisé.

---

### 3.6 Investigation TLS — Métadonnées des sessions chiffrées

**Commande :** `tls.handshake.type == 1`

Le filtre `tls.handshake.type == 1` isole uniquement les Client Hello d'une session TLS.

*Le Client Hello est le premier message d'une session TLS. Il contient en clair : le SNI (nom de domaine de destination), le Client Random (valeur unique identifiant la session), et la version TLS.*

Destinations identifiées via SNI :

| Domaine (SNI) | Observations |
|---------------|-------------|
| protonmail.com / mail.protonmail.com | Nombreuses sessions répétées |
| dfir.science | Sessions TLS — toutes échouées (TCP Retransmission) |
| www.7-zip.org | Téléchargement d'outil |
| Microsoft / Google / Akamai | Trafic système normal |

**Première session TLS ProtonMail :**

```
Paquet      : 17992
Date        : 30/04/2021
Destination : protonmail.com → 185.70.41.35
Client Random : 24e92513b97a0348f733d16996929a79be21b0b1400cd7e2862a732ce7775b70
```

On note le Client Random même si on ne peut pas déchiffrer le trafic, car il pourra dans une investigation future permettre d'identifier les échanges et de les déchiffrer s'il y a une saisie judiciaire. De nombreuses sessions ProtonMail sont suspectes dans ce contexte car il s'agit d'un service de messagerie chiffré de bout en bout permettant aux attaquants d'extraire des données anonymement.

---

### 3.7 Investigation UDP — Trafic non identifié

**Commande :** `data`

Le filtre `data` appliqué dans Wireshark isole le trafic UDP sans protocole reconnu (298 paquets vers deux IPs externes). Les IPs sont ensuite enrichies via VirusTotal pour évaluer leur réputation.

| IP destination | Port dst | Volume | Enrichissement VirusTotal |
|----------------|----------|--------|--------------------------|
| 24.35.154.189 | 55038 | Majoritaire | Fidelity Communication Int. (US) — non flaggée en 2021 |
| 24.39.217.246 | 54150 | Minoritaire | Charter Communications (US) — fichiers suspects associés récemment |

Tentatives de connexion TCP vers les deux IPs : toutes échouées (TCP Retransmission).

**Trafic Teredo :**  
**Commande :** `eth.addr == c8:09:a8:57:47:93 && ipv6`  
Adresse IPv6 Teredo de .26 : `2001:0:34a2:52f8:c2e:2c57:948f:27b7` → `40.65.246.52` port 3544  
Volumes faibles — non retenu comme vecteur d'exfiltration.

*Teredo = protocole Microsoft permettant d'encapsuler de l'IPv6 dans de l'UDP pour traverser des réseaux IPv4.*

Du trafic UDP vers des ports non-standards sans protocole identifié est potentiellement initié par un attaquant, ce qui le rend suspect. Cependant, comme il n'est pas reconnu, il n'est pas lisible ni interprétable, ce qui limite cette piste pour l'investigation.  
Bien que non flaggées au moment de la capture, des fichiers malveillants ont été associés à 24.39.217.246 lors d'analyses ultérieures sur VirusTotal, renforçant la suspicion sur cette IP.

---

## 4. Tableau des IoCs

| Type | Valeur | Source | Référence |
|------|--------|--------|-----------|
| IP investiguée | 192.168.1.26 | Wireshark | — |
| MAC investiguée | c8:09:a8:57:47:93 | Ethernet II | — |
| OS / navigateur | Windows 10 x64, Chrome 90 | HTTP User-Agent | Paquet 26264 |
| IP serveur FTP | 192.168.1.20 | FTP stream | — |
| MAC serveur FTP | 08:00:27:a6:1f:86 (PCS Systemtechnik, US) | Ethernet II | — |
| Credentials FTP | kali / AfricaCTF2021 | FTP stream | Paquets 497/500 |
| Bannière FTP | "Hacker FTP service" | FTP stream | Paquet 486 |
| Fichier suspect | accountNum.zip (239 bytes) | FTP RETR | Paquet 11835 |
| Fichiers uploadés | 20210429_152321.jpg / 20210429_152157.jpg | FTP STOR | Paquets 606, 7069 |
| Appareil photo | LG Electronics LM-Q725K | EXIF | — |
| Dossier non-standard | /home/kali/ftp | FTP LIST | Créé 20/04/2021 17:53 |
| Domaine suspect | dfir.science | DNS + HTTP | Paquets 26243/26264 |
| IPs Cloudflare (dfir.science) | 104.21.89.171 / 172.67.162.206 | DNS response | Paquet 26252 |
| Connexion HTTP | GET / dfir.science → 301 | HTTP stream | 30/04/2021 01:04:39 UTC |
| Sessions ProtonMail | protonmail.com (185.70.41.35/.130) | TLS SNI | Multiples |
| Client Random TLS | 24e92513b97a0348f733d16996929a79be21b0b1400cd7e2862a732ce7775b70 | TLS Client Hello | Paquet 17992 |
| UDP suspect | 24.35.154.189:55038 | UDP Data | Multiple |
| UDP suspect | 24.39.217.246:54150 | UDP Data | Multiple |
| Serveur DNS IPv6 | fe80::c80b:adff:feaa:1db7 | DNS | — |

---

## 5. Analyse

### Chronologie

**20/04/2021, 17:53** — Création du dossier `/home/kali/ftp` sur 192.168.1.20  
→ L'apparition d'un dossier non-standard nommé à l'aide du protocole ayant servi à l'extraction des données indique que l'attaquant était déjà présent à cette date sur le système.

**29/04/2021, 15:21** — Photos prises avec un LG LM-Q725K (smartphone)  
→ Ces données aident à identifier l'attaquant.

**29/04/2021, 15:51** — Connexion FTP, `STOR` de 2 `.jpg`, `RETR accountNum.zip`  
→ L'attaquant décide de passer à l'action en envoyant 2 fichiers `.jpg` et en téléchargeant le fichier `accountNum.zip`. L'extraction de données a lieu à ce moment-là.

**30/04/2021, 01:04** — `GET /` vers `dfir.science`, code HTTP 301, tentatives TLS échouées  
→ L'attaquant essaye d'accéder à `dfir.science` mais échoue. On ne peut pas être sûr de ses motivations exactes à ce stade.

**30/04/2021, 01:07** — Multiples sessions TLS vers ProtonMail  
→ Il y a eu un échange important entre .26 et ProtonMail (10 Mo entrants, 171 ko sortants). Le contenu étant chiffré et le volume entrant largement supérieur au sortant, .26 semble avoir téléchargé des données depuis ProtonMail plutôt qu'en avoir envoyé. On ne peut ni confirmer ni infirmer un envoi de données vers l'extérieur.

### Hypothèse principale

Deux machines sont compromises avec des rôles distincts : **192.168.1.20** héberge un serveur FTP malveillant ("Hacker FTP service"), mis en place au moins depuis le 20 avril 2021. **192.168.1.26** est la machine depuis laquelle l'attaquant opère — elle transfère des fichiers JPG vers .20, récupère `accountNum.zip` (données financières probables), tente d'accéder à `dfir.science` pour des raisons non confirmées, et échange des données avec ProtonMail.

Les éléments qui supportent cette hypothèse sont : la création du dossier non-standard `/home/kali/ftp`, les transferts FTP documentés, les volumes d'échange avec ProtonMail, et les tentatives de connexion vers dfir.science.

Elle ne peut pas être confirmée à 100% car : le contenu des échanges ProtonMail est chiffré, le trafic UDP vers 24.35.154.189 et 24.39.217.246 est indéchiffrable, et la durée réelle de la compromission nécessiterait des captures ou logs antérieurs au 20 avril.

---

## 6. Recommandations

**Actions immédiates :**

- Isoler 192.168.1.20 et 192.168.1.26 du réseau dans l'attente d'une investigation complète
- Investiguer les logs et captures réseau antérieurs au 20 avril pour déterminer la durée réelle de la compromission
- Changer les credentials du compte `kali` sur 192.168.1.20 — l'attaquant ayant accès au compte système, pas seulement au serveur FTP
- Prévenir les collaborateurs dont les données ont potentiellement fuité afin qu'ils sécurisent leurs informations

**Mesures préventives :**

- Interdire FTP sur le réseau et bloquer le port 21 — remplacer par SFTP ou FTPS pour réduire la surface d'attaque
- Mettre en place des règles d'alertes SIEM pour détecter les intrusions et tentatives d'intrusion
- Appliquer le principe du moindre privilège sur toutes les machines
- Segmenter le réseau pour limiter les mouvements latéraux en cas de compromission

---

## 7. Conclusion

Cette investigation a permis d'identifier deux machines compromises (192.168.1.20 et 192.168.1.26) impliquées dans une opération d'exfiltration de données via FTP en clair, avec transfert d'un fichier financier suspect (`accountNum.zip`) et de possibles communications ultérieures via ProtonMail. Plusieurs éléments restent non confirmés : le contenu des échanges chiffrés, la nature du trafic UDP non identifié, et la durée réelle de la compromission avant la capture.  
Cette investigation m'a permis de consolider la méthodologie d'analyse réseau SOC : priorisation des protocoles non chiffrés, corrélation multi-protocoles, et documentation rigoureuse des IoCs et de leurs limites.

---

## Compétences mobilisées

- Analyse de capture réseau : Protocol Hierarchy, Conversations, Follow Stream, Export Objects
- Identification et priorisation des protocoles en clair vs chiffrés
- Extraction et analyse de métadonnées EXIF
- Enrichissement d'IoCs via VirusTotal et MAC lookup
- Lecture de métadonnées TLS (SNI, Client Random) sans déchiffrement
- Corrélation MAC → IPv4 → IPv6
- Raisonnement SOC : vue d'ensemble → hypothèse → preuve → limite

---

*Write-up rédigé dans le cadre d'une formation cybersécurité 22 semaines (mars–août 2026)*  
*Portfolio : [github.com/DimitriProCyber/portfolio-cybersecurite](https://github.com/DimitriProCyber/portfolio-cybersecurite)*
