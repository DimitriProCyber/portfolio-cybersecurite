# Investigation SOC : Attaque Po1s0n1vy contre imreallynotbatman.com

**13 mai 2026**

**Plateforme :** Splunk BOTS v1 (installation locale)  
**Type :** Investigation SOC — Défacement web + Ransomware  
**Niveau :** Analyste SOC N1  


## 1. Contexte

BOTS v1 documente une attaque simulée contre Wayne Corp (la société de Batman) perpétrée par le groupe APT Po1s0n1vy. Dans ce scénario, le site web de Wayne Corp est : `imreallynotbatman.com`. Le site est hébergé sur un serveur Windows IIS 8.5 (Internet Information Services) en interne (`192.168.250.70`), faisant tourner le Content Management System (CMS) Joomla.
Une alerte Suricata de criticité haute, de type Web Application Attack, a motivé cette investigation. L'objectif est de déterminer ce qui s'est passé, qui a attaqué, comment et quel est l'impact.


## 2. Méthodologie

### Étape 1 — Volume et périmètre

Avant toute investigation, un analyste SOC commence par inventorier ses sources de données afin de déterminer les informations à sa disposition. Il reconnaît les logs qui lui seront utiles et sait où il pourra chercher les informations pertinentes au fur et à mesure de son investigation. Il pourra également déterminer les limites de l'investigation et justifier l'absence de certaines informations si nécessaire.
L'analyste obtient également une vue d'ensemble du dataset dans lequel il va travailler.

```spl
-- Inventaire des sourcetypes et hôtes disponibles
index="botsv1" | stats count by sourcetype
index="botsv1" | stats count by host

-- Fenêtre temporelle du dataset
index="botsv1" | sort _time | head 1
index="botsv1" | sort -_time | head 1
```

**Explication des commandes :** `stats count by sourcetype` agrège tous les événements et les compte par type de source — ce qui donne une carte de ce que contient le dataset. `sort _time | head 1` trie par ordre chronologique croissant et ne garde que le premier événement, révélant ainsi le début du dataset. `sort -_time` fait l'inverse (le `-` signifie décroissant) pour trouver la fin.

**Résultat :** 955 807 événements, 20 sourcetypes, 7 hôtes. Fenêtre : 10 août 2016 05:28 → 28 août 2016 20:27. Sourcetypes clés : `stream:http`, `iis`, `suricata`, `xmlwineventlog`, `stream:smb`.


### Étape 2 — Identification des IPs suspectes

On commence par analyser le trafic HTTP vers le site ciblé afin de repérer les adresses IP avec un nombre de requêtes élevé. Les IP ayant un trafic élevé et anormal avec le site sont les plus susceptibles d'être celles responsables de l'attaque. Cela permettra ensuite de concentrer l'investigation autour de ces adresses.

```spl
-- Volume de requêtes par IP source vers le site ciblé
index="botsv1" sourcetype="stream:http" site="imreallynotbatman.com"
| stats count by src_ip
| sort -count
```

**Explication :** `sourcetype="stream:http"` cible les logs de trafic réseau HTTP capturés. `site="imreallynotbatman.com"` filtre uniquement le trafic destiné au site investigué. `stats count by src_ip` compte le nombre de requêtes par adresse IP source — les IPs avec un volume anormalement élevé sont les premières suspectes. `sort -count` trie du plus au moins fréquent.

**Résultat :** Deux IPs dominent : `40.80.148.42` (17 437 requêtes) et `23.22.63.114` (1 235 requêtes).

**Enrichissement OSINT — VirusTotal**

Les deux IPs sont soumises à VirusTotal pour enrichissement contextuel :

- `40.80.148.42` : 0/92 antivirus, AS 8075 Microsoft Corp. Score clean mais comportement malveillant confirmé dans les logs.
- `23.22.63.114` : 0/92 antivirus, **Community Score -10**, 5 fichiers malveillants communiquant avec cette IP, AS 14618 Amazon AWS.

**Attribution via VirusTotal — onglet Relations (`23.22.63.114`) :** L'onglet Relations liste les domaines qui ont résolu vers cette IP. On y trouve `po1s0n1vy.com` et `www.po1s0n1vy.com` — infrastructure du groupe APT **Po1s0n1vy**. On découvre également une série de domaines typosquattant Wayne Corp (`waynecorinc.com`, `wanecorpinc.com`, `wynecorpinc.com`...) — domaines quasi-identiques au vrai domaine, utilisés pour du spear phishing ciblé contre les employés Wayne Corp.

Ce résultat démontre que se contenter du score de détection uniquement peut être trompeur. Sur la base de cet indicateur on pourrait conclure que les deux adresses IP sont fiables. Cependant le comportement de `40.80.148.42` reste très suspect, et l'onglet Relations permet clairement d'affirmer à ce stade que `23.22.63.114` est une adresse IP hostile.


### Étape 3 — Analyse croisée multi-sourcetypes

#### 3.1 Caractérisation de `40.80.148.42`

Il est important de croiser les sources `stream:http` et `iis` car elles apportent chacune des informations différentes. `stream:http` permet d'intercepter les paquets qui transitent sur le réseau et de reconstituer les échanges HTTP complets, alors que `iis` est le journal tenu par le serveur web IIS qui enregistre les requêtes qu'il a reçues et traitées. `iis` permet d'accéder rapidement aux codes HTTP et aux URLs accédées, alors que `stream:http` permet de voir le contenu de la requête.

```spl
-- Techniques utilisées par l'IP suspecte
index="botsv1" sourcetype="stream:http" site="imreallynotbatman.com" src_ip="40.80.148.42"
| stats count by http_method, uri
| sort -count
```

**Explication :** On filtre sur l'IP suspecte pour isoler uniquement son trafic. `stats count by http_method, uri` crée une table de toutes les combinaisons méthode HTTP + URL utilisées, triées par volume — ce qui révèle les patterns d'attaque (masse de POST vers une même URL = injection, URLs contenant `../` = Path Traversal).

**Résultat :** 11 923 POST vers `/joomla/index.php/component/search/` — injection via le moteur de recherche Joomla. Tentatives Path Traversal détectées : `/etc/passwd%00.jpg`, `/windows/win.ini%00.jpg`. Le header HTTP révèle l'outil utilisé : **Acunetix Web Vulnerability Scanner WVS/10.0**.

Pour compléter cette analyse, on croise avec les logs IIS afin de voir les codes HTTP réels retournés par le serveur et reconstituer la chronologie précise de la session admin :

```spl
-- Chronologie de la session admin depuis 40.80.148.42
index="botsv1" sourcetype="iis" c_ip="40.80.148.42"
| search cs_uri_stem="/joomla/administrator*"
| table _time, cs_method, cs_uri_stem, sc_status
| sort _time
```

**Explication :** `sourcetype="iis"` cible les logs applicatifs du serveur web. `c_ip` est le champ IIS pour l'IP cliente (équivalent de `src_ip` dans stream:http). `cs_uri_stem` contient l'URL demandée — le wildcard `*` après `/joomla/administrator` capture toutes les URLs sous ce chemin, y compris les ressources eXtplorer. `sc_status` est le code HTTP retourné par le serveur.

**Résultat :** À **23:48:06** — POST 303 (tentative login), suivi immédiatement de GET 200 à 23:48:07 — session admin active. À **23:51** — chargement massif de ressources `com_extplorer` (gestionnaire de fichiers Joomla) : icônes `_chmod`, `_move`, `_edit`, `_filenew`... L'attaquant navigue dans l'interface de gestion de fichiers, ce qui implique qu'il a utilisé eXtplorer pour déposer `agent.php`.

#### 3.2 Caractérisation de `23.22.63.114`

```spl
index="botsv1" sourcetype="stream:http" site="imreallynotbatman.com" src_ip="23.22.63.114"
| stats count by http_method, uri
| sort -count
```

**Résultat :** 1 235 requêtes, toutes vers `/joomla/administrator/index.php` uniquement — pattern de brute force ciblé sur la page de connexion admin Joomla. User-Agent : `Python-urllib/2.7` — script Python automatisé.

Croisement avec IIS pour confirmer les codes HTTP retournés :

```spl
-- Comportement de 23.22.63.114 côté serveur
index="botsv1" sourcetype="iis" c_ip="23.22.63.114"
| stats count by cs_method, cs_uri_stem, sc_status
| sort -count
```

**Explication :** Même logique que pour `40.80.148.42` — on croise stream:http (ce que l'attaquant envoie) avec IIS (ce que le serveur retourne) pour avoir une image complète. `stats count by cs_method, cs_uri_stem, sc_status` regroupe par combinaison méthode + URL + code réponse, ce qui révèle d'un coup le volume et le résultat de chaque type de requête.

**Résultat :** 823 GET + 412 POST vers `/joomla/administrator/index.php` — tous les POST retournent 303 (brute force échoué). En revanche, à partir de **23:55:22** : 194 GET en 200 vers `/joomla/agent.php` — accès confirmé au webshell déposé par `40.80.148.42`.

#### 3.3 Identification du credential compromis

Pour un rapport d'incident, l'identification du mot de passe exact utilisé permet de savoir quel compte a été compromis, de vérifier si le mot de passe respectait les recommandations de sécurité et de déterminer s'il n'est pas réutilisé ailleurs. Pour cela on cherche dans le champ `form_data` qui contient les identifiants soumis dans un formulaire de login.

```spl
-- Extraction des credentials depuis les données de formulaire POST
index="botsv1" sourcetype="stream:http" src_ip="40.80.148.42" http_method="POST" uri="/joomla/administrator/index.php"
| rex field=form_data "passwd=(?<password>[^&]+)"
| table _time, password
| sort _time
```

**Explication :** `form_data` est le champ Splunk qui contient les données brutes soumises dans un formulaire HTTP POST — typiquement `username=admin&passwd=batman&...`. `rex` applique une expression régulière directement sur ce champ : `passwd=` est le point de départ, `(?<password>...)` capture ce qui suit dans un nouveau champ nommé `password`, et `[^&]+` signifie "tous les caractères sauf `&`" — ce qui s'arrête exactement à la fin de la valeur du mot de passe.

**Résultat :** POST avec `passwd=batman` à **23:48:05** depuis `40.80.148.42`. Pour confirmer que ce mot de passe est bien celui qui a fonctionné, on corrèle avec les logs IIS :

```spl
-- Confirmation session admin active après le POST batman
index="botsv1" sourcetype="iis" c_ip="40.80.148.42"
| search cs_uri_stem="/joomla/administrator*"
| table _time, cs_method, cs_uri_stem, sc_status
| sort _time
```

**Résultat :** GET 200 sur `/joomla/administrator/index.php` à **23:48:07** — soit 2 secondes après le POST avec `batman`. Un login échoué redirige vers la page de login (303), un login réussi charge le dashboard (200). La session admin active immédiatement après confirme que `batman` est le mot de passe correct. **Credential compromis : `admin` / `batman`.**

#### 3.4 Confirmation du dépôt et accès au webshell

```spl
-- Accès au webshell agent.php
index="botsv1" sourcetype="iis" cs_uri_stem="/joomla/agent.php"
| table _time, c_ip, cs_method, sc_status
| sort _time
```

**Explication :** On cherche dans les logs IIS (`sourcetype="iis"`) toutes les requêtes vers `agent.php`. `c_ip` est l'IP cliente, `cs_method` la méthode HTTP, `sc_status` le code réponse serveur. Un code 200 confirme que le fichier existe et est accessible.

**Résultat :** Premier accès à `agent.php` à **23:55:22** depuis `23.22.63.114` — 4 minutes après qu'`40.80.148.42` a utilisé eXtplorer. Les deux IPs appartiennent très probablement au même groupe : la première ouvre la porte, la seconde l'exploite.


### Étape 4 — Exécution de commandes via webshell (Sysmon)

Sysmon (System Monitor) est un service Windows qui journalise chaque processus créé sur la machine. Si un attaquant a exécuté des commandes, il en aura gardé la trace. Nous allons chercher un EventID 1 qui signifie la création d'un processus, ce qui permet de déterminer si l'attaquant a utilisé un webshell.

Les champs Sysmon ne sont pas parsés automatiquement dans ce dataset — les données sont stockées en XML brut dans le champ `_raw`. L'extraction nécessite donc l'utilisation de `rex` pour récupérer les valeurs manuellement.

```spl
-- Identification des EventIDs disponibles (vérification préalable)
index="botsv1" sourcetype="xmlwineventlog"
| rex field=_raw "EventID>(?<eid>\d+)<"
| stats count by eid
| sort -count
```

**Explication :** Comme les champs ne sont pas parsés, on utilise `rex` avec une expression régulière sur `_raw` (le texte brut de l'événement). Le pattern `EventID>(?<eid>\d+)<` cherche le texte `EventID>`, capture tous les chiffres suivants (`\d+` = un ou plusieurs chiffres) dans un champ `eid`, et s'arrête au `<` suivant — correspondant à la structure XML `<EventID>1</EventID>`.

**Résultat :** EventID 7 (168 374 — chargement DLL), EventID 3 (99 320 — connexion réseau), **EventID 1 (767 — ProcessCreate)**. On cible EventID 1 pour voir les processus créés.

Avant de filtrer sur le webshell, on fait une vue d'ensemble de toutes les chaînes parent → enfant pour identifier les anomalies :

```spl
-- Vue d'ensemble des processus créés — identification d'anomalies
index="botsv1" sourcetype="xmlwineventlog"
| search "EventID>1<"
| rex field=_raw "Name='Image'>(?<Image>[^<]+)<"
| rex field=_raw "Name='ParentImage'>(?<ParentImage>[^<]+)<"
| stats count by ParentImage, Image
| sort -count
```

**Explication :** On extrait `Image` (processus créé) et `ParentImage` (processus qui l'a lancé) depuis le XML brut, puis on agrège par combinaison parent/enfant. L'objectif est d'identifier des chaînes anormales — sur un serveur web, `w3wp.exe` (IIS) ou `php-cgi.exe` (PHP) ne devraient jamais lancer `cmd.exe`.

**Résultat :** La combinaison `php-cgi.exe` → `cmd.exe` (17 occurrences) ressort comme anomalie majeure — PHP n'a aucune raison légitime de lancer un shell système. C'est la signature caractéristique d'un webshell actif.

```spl
-- Commandes exécutées via le webshell
index="botsv1" sourcetype="xmlwineventlog"
| search "EventID>1<"
| rex field=_raw "Name='Image'>(?<Image>[^<]+)<"
| rex field=_raw "Name='ParentImage'>(?<ParentImage>[^<]+)<"
| rex field=_raw "Name='CommandLine'>(?<CommandLine>[^<]+)<"
| search ParentImage="*php-cgi.exe*"
| table _time, ParentImage, Image, CommandLine
| sort _time
```

**Explication :** `search "EventID>1<"` filtre sur les ProcessCreate en cherchant cette chaîne exacte dans le texte brut — on sait désormais que c'est la structure XML réelle. Les trois `rex` extraient respectivement : `Image` (processus créé), `ParentImage` (processus parent), `CommandLine` (commande exacte avec arguments). `[^<]+` signifie "tout caractère sauf `<`" — capture la valeur jusqu'à la balise fermante XML. `search ParentImage="*php-cgi.exe*"` filtre sur les processus dont le parent est le moteur PHP — signature d'un webshell actif.

**Résultat :** 17 événements — séquence de commandes exécutées par l'attaquant :

| Heure | Commande | Interprétation |
|---|---|---|
| 23:55:22 | `cmd.exe /c echo 24365` | Test connectivité webshell |
| 23:55:24 | `cmd.exe /c dir 2>&1` | Reconnaissance — contenu répertoire |
| 23:55:26 | `cmd.exe /c ls 2>&1` | Test OS — erreur (commande Linux) |
| 23:55:33 | `cmd.exe /c ifconfig 2>&1` | Reconnaissance réseau — erreur (Linux) |
| 23:56:18 | `cmd.exe /c 3791.exe 2>&1` | Exécution malware depuis `C:\inetpub\wwwroot\joomla\` |
| 00:20:10 | `cmd.exe /c move ..\1.jpeg 2.jpeg` | Préparation defacement |
| 00:20:33 | `cmd.exe /c move 2.jpeg imnotbatman.jpg` | Remplacement image site |

Sur un shell Windows/Linux, `2>&1` demande l'affichage des messages d'erreur dans le résultat. L'attaquant peut alors voir ce qui fonctionne ou non.
La présence des commandes `ls` et `ifconfig` indique que l'attaquant ne sait pas s'il se trouve sur un système Windows ou Linux — il est en train de récupérer de l'information sur son environnement.

L'exécution de `3791.exe` à 23:56:18 est suspecte — un fichier avec un nom aléatoire de 4 chiffres exécuté depuis le dossier web. On cherche toutes ses occurrences dans Sysmon pour comprendre son comportement :

```spl
-- Analyse de 3791.exe — toutes les machines et commandes associées
index="botsv1" sourcetype="xmlwineventlog"
| search "3791.exe"
| rex field=_raw "Name='ComputerName'>(?<ComputerName>[^<]+)<"
| rex field=_raw "Name='Image'>(?<Image>[^<]+)<"
| rex field=_raw "Name='CommandLine'>(?<CommandLine>[^<]+)<"
| table _time, ComputerName, Image, CommandLine
| sort _time
```

**Explication :** On cherche `3791.exe` dans tous les événements Sysmon sans filtrer sur un EventID — pour voir non seulement quand il est créé (EventID 1) mais aussi toutes ses apparitions dans les logs. `ComputerName` permettrait d'identifier si le fichier s'est propagé à d'autres machines.

**Résultat :** 69 événements, tous depuis `C:\inetpub\wwwroot\joomla\3791.exe` — confiné au serveur `.70`. Le fichier se relance lui-même (`cmd.exe /c "3791.exe 2>&1"`) et reste actif jusqu'au 11 août 00:21. `ComputerName` non parsé dans ce dataset — propagation à d'autres machines non confirmable via cette requête.

#### Identification du fichier de defacement

Les commandes `move` révèlent qu'un fichier `1.jpeg` était déjà présent sur le serveur avant le defacement. Pour retrouver son origine, on cherche un téléchargement HTTP sortant depuis le serveur :

```spl
-- Téléchargements de fichiers image depuis le serveur vers l'extérieur
index="botsv1" sourcetype="stream:http" src_ip="192.168.250.70"
| where like(uri, "%.jpeg") OR like(uri, "%.jpg")
| table _time, src_ip, dest_ip, uri, http_method
| sort _time
```

**Explication :** Cette fois `.70` est en `src_ip` — c'est le serveur qui initie la connexion, donc qui télécharge quelque chose depuis l'extérieur. `where like(uri, "%.jpeg")` filtre sur l'URI en cherchant les requêtes vers des fichiers `.jpeg` — le `%` est le wildcard SQL utilisé par la commande `where` (équivalent du `*` de `search`, mais applicable à un champ spécifique).

**Résultat :** `.70` télécharge `/poisonivy-is-coming-for-you-batman.jpeg` depuis `23.22.63.114` à **00:06:21** et **00:13:46**. `23.22.63.114` est donc aussi le serveur de staging hébergeant le fichier de defacement.


### Étape 5 — Impact réseau interne

L'analyste SOC cherche systématiquement un mouvement latéral afin de pouvoir indiquer dans son rapport si la compromission se limite à une machine ou si elle s'étend à d'autres machines sur le réseau. Il s'agit d'une information essentielle pour déterminer la gravité de l'attaque.

```spl
-- Alertes Suricata sur les IPs internes suspectes
index="botsv1" sourcetype="suricata" | search "192.168.250.100"
| stats count by alert.signature, src_ip, dest_ip | sort -count

index="botsv1" sourcetype="suricata" | search "192.168.2.50"
| stats count by alert.signature, src_ip, dest_ip | sort -count

-- Trafic SMB interne
index="botsv1" sourcetype="stream:smb"
| stats count by src_ip, dest_ip | sort -count
```

**Explication :** Suricata est un IDS (système de détection d'intrusion) réseau — il compare le trafic à des signatures d'attaques connues. `alert.signature` contient le nom de la règle déclenchée. Le sourcetype `stream:smb` capture le trafic SMB (Server Message Block) — le protocole Windows de partage de fichiers, vecteur classique de propagation latérale entre machines d'un même réseau.

**Résultat :** `192.168.250.100` émet des alertes **Cerber ransomware** en direction de serveurs C2 externes via Tor (`85.93.0.0`, `85.93.4.54`) — machine interne infectée. `192.168.2.50` génère 50 871 connexions SMB vers `.100` et 45 178 vers `.20`, avec des alertes RDP DoS et CVE-2015-1635 vers `.70` — machine infectée propageant activement l'infection sur le réseau interne.

Pour tenter de prouver le lien entre la compromission de `.70` et l'infection de `.50`, on cherche des connexions TCP directes entre ces deux machines après l'activation du webshell :

```spl
-- Tentative de preuve du mouvement latéral .70 → .50
index="botsv1" sourcetype="stream:tcp"
| search src_ip="192.168.250.70" dest_ip="192.168.2.50"
| table _time, src_ip, dest_ip, dest_port
| sort _time
```

**Explication :** `stream:tcp` capture les connexions TCP brutes — plus bas niveau que SMB ou HTTP. Si `.70` a initié une connexion vers `.50` après la compromission (via le webshell ou `3791.exe`), elle devrait apparaître ici. `dest_port` permettrait d'identifier le protocole utilisé (445 = SMB, 4444 = reverse shell Metasploit classique).

**Résultat :** Aucun résultat — aucune connexion TCP directe de `.70` vers `.50` trouvée. Le vecteur de compromission de `.50` reste non prouvé dans les données disponibles.


## 3. Résultats

### Chronologie complète

| Heure | Événement | Source |
|---|---|---|
| 23:37 | Scan Acunetix depuis `40.80.148.42` | stream:http |
| 23:45–23:46 | Brute force depuis `23.22.63.114` (412 tentatives) | stream:http |
| 23:48:05 | Login admin réussi — `admin/batman` | stream:http + IIS |
| 23:51 | Navigation eXtplorer — dépôt `agent.php` | IIS |
| 23:55:22 | Premier accès webshell depuis `23.22.63.114` | IIS |
| 23:55–23:56 | Reconnaissance système via webshell | Sysmon EventID 1 |
| 23:56:18 | Exécution `3791.exe` | Sysmon EventID 1 |
| 00:06:21 | Téléchargement `poisonivy-is-coming-for-you-batman.jpeg` | stream:http |
| 00:20:10–33 | Defacement — remplacement image site | Sysmon EventID 1 |
| Indéterminé | Infection Cerber sur `.100`, propagation SMB depuis `.50` | Suricata + stream:smb |


## 4. Analyse

### Cyber Kill Chain

1. **Reconnaissance —** L'attaquant scanne automatiquement le site avec Acunetix pour identifier les vulnérabilités exploitables du CMS Joomla.
2. **Weaponization —** Pour son attaque, l'attaquant a préparé un script Python automatisé (brute force), un `agent.php` et un fichier `.jpeg` à déposer une fois l'accès au serveur obtenu.
3. **Delivery —** Le site `imreallynotbatman.com` a été compromis par brute force avec succès grâce aux identifiants `admin/batman`.
4. **Exploitation —** Depuis l'espace administrateur, l'attaquant dépose un webshell via eXtplorer pour maintenir un accès persistant au serveur.
5. **Installation —** Le fichier `3791.exe` est installé via le webshell et se relance lui-même en boucle.
6. **Command & Control —** Le ransomware Cerber cherche à contacter un serveur externe depuis `192.168.250.100` via Tor.
7. **Actions on objectives —** L'attaquant réussit à déposer un fichier `.jpeg` de defacement et à infecter une machine interne avec le ransomware Cerber.

### Points de défaillance

Cette attaque a été permise par plusieurs points de sécurité défaillants. Tout d'abord le mot de passe administrateur qui ne respectait pas les recommandations de sécurité. L'interface administrateur qui autorise les tentatives de connexion illimitées et ne demande pas une authentification à double facteur (MFA) constitue également un point défaillant. Le gestionnaire eXtplorer ne devrait pas être actif sur une machine en production, et les machines sur le réseau ne sont pas séparées les unes des autres. Enfin, il n'y a aucune détection de brute force active, ce qui a permis à l'attaquant de tester tout ce qu'il voulait sans être bloqué.

### Limites de l'investigation

Le lien de compromission entre `.70` et `.50` n'a pas pu être prouvé — aucune connexion directe trouvée dans `stream:tcp` ni `stream:smb`. `192.168.250.20` a été identifiée comme cible SMB mais n'a pas été analysée. Le comportement réseau de `3791.exe` n'a pas été retracé et son hash MD5 n'a pas été extrait.


## 5. Indicateurs de Compromission (IoCs)

| Type | Valeur | Rôle |
|---|---|---|
| IP externe | `40.80.148.42` | Scanner Acunetix / dépôt webshell |
| IP externe | `23.22.63.114` | Brute force / staging / C2 |
| IP externe | `85.93.4.54` | Serveur C2 Cerber |
| Domaine | `po1s0n1vy.com` | Infrastructure APT Po1s0n1vy |
| Fichier | `agent.php` | Webshell — `/joomla/` |
| Fichier | `3791.exe` | Malware — `C:\inetpub\wwwroot\joomla\` |
| Fichier | `poisonivy-is-coming-for-you-batman.jpeg` | Fichier de defacement |
| Credential | `admin` / `batman` | Compte Joomla compromis |
| IP interne | `192.168.250.100` | Machine infectée Cerber |
| IP interne | `192.168.2.50` | Machine infectée — propagation SMB |


## 6. Recommandations

Le premier vecteur d'entrée étant un mot de passe trivial, la priorité immédiate est de réinitialiser le compte `admin` avec un mot de passe fort d'au moins 16 caractères, et d'activer le MFA sur l'interface d'administration Joomla. Tant que ces deux mesures ne sont pas en place, n'importe quel outil de brute force peut reproduire l'attaque en quelques minutes.

L'accès à `/joomla/administrator/` devrait être restreint par whitelist d'adresses IP — seuls les postes d'administration légitimes devraient pouvoir y accéder. eXtplorer doit être désactivé : un gestionnaire de fichiers accessible depuis l'interface admin n'a aucune justification en production et représente un risque majeur de dépôt de fichiers malveillants.

Les machines `192.168.250.100` et `192.168.2.50` doivent être isolées du réseau immédiatement pour stopper la propagation de Cerber. La segmentation réseau est insuffisante — le protocole SMB ne devrait pas être routable entre le serveur web et les postes de travail internes, ce qui aurait limité la propagation du ransomware.

À moyen terme, des règles SIEM devraient être déployées pour alerter automatiquement sur des patterns de brute force (10+ POST 303 consécutifs depuis une même IP) et sur des chaînes de processus anormales en production (`php-cgi.exe` lançant `cmd.exe`).


## 7. Conclusion

Cet incident est à considérer comme majeur : compromission de l'interface d'administration, dépôt de webshell, propagation sur le réseau interne et détection d'un ransomware actif constituent un ensemble de menaces à traiter en urgence. L'investigation a prouvé que le site et le réseau de Wayne Corp ont bien été compromis par le groupe APT Po1s0n1vy. La provenance du ransomware reste incertaine, certains liens de compromission n'ont pas pu être établis et le rôle de `3791.exe` n'a pas pu être déterminé. La sécurité d'un CMS en production ne peut pas reposer uniquement sur les paramètres par défaut — il est essentiel de s'assurer que les règles de base sont respectées et d'appliquer le principe du moindre privilège. Certaines pistes ont été explorées tardivement dans cette investigation — la recherche des identifiants compromis aurait dû intervenir dès la confirmation du brute force réussi, avant de passer à l'étape suivante.

---

*Write-up rédigé dans le cadre d'une formation cybersécurité*  
*Objectif : Analyste SOC N1 / Technicien sécurité IT*
