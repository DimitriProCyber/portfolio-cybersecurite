# Splunk BOTS v1 · Scénario 2 : Ransomware Cerber

**25 mai 2026**

**Plateforme :** Splunk BOTS v1 (Boss of the SOC)  
**Difficulté :** Intermédiaire  
**Niveau :** Analyste SOC N1


## 1. Contexte

Le 24 août 2016, Bob Smith, employé de Wayne Corporation, a trouvé une clé USB dans le parking de l'entreprise. Il l'a branchée sur son poste de travail (`we8105desk`) et a ouvert un fichier qu'elle contenait. À son retour au bureau, ses enceintes jouaient de la musique, son fond d'écran avait changé et ses fichiers étaient inaccessibles.

En tant qu'analyste SOC N1, l'objectif est de reconstituer l'intégralité de l'attaque : vecteur d'entrée, chaîne d'exécution, communications réseau, payload, étendue des dégâts et propagation sur le réseau interne.

Le baiting USB représente un risque réel en entreprise : en déposant une clé dans un parking ou une zone commune, un attaquant contourne l'intégralité des défenses périmètriques (pare-feu, filtrage web, IDS réseau) puisque le vecteur est physique. Les études terrain montrent des taux de branchement élevés — le facteur humain reste la faille la plus difficile à corriger. Une fois la clé connectée, l'attaquant dispose d'un accès direct au réseau interne. Combiné à un ransomware, l'impact peut être total : chiffrement des postes et serveurs, paralysie complète de l'activité, pression financière forte pour payer la rançon et relancer les opérations rapidement.


## 2. Méthodologie

L'investigation suit la méthodologie SOC en 8 étapes, appliquée chronologiquement :

1. Identifier la machine compromise
2. Reconstruire le vecteur d'entrée
3. Suivre la chaîne d'exécution
4. Identifier les communications réseau malveillantes
5. Trouver le téléchargement du payload
6. Évaluer les dégâts locaux
7. Identifier la propagation réseau
8. Cartographier le C2 final

**Sourcetypes utilisés :**

| Sourcetype | Rôle dans l'investigation |
|---|---|
| `xmlwineventlog` | Logs Sysmon (processus, connexions réseau, modifications fichiers) |
| `WinRegistry` | Registre Windows (identification clé USB) |
| `stream:dns` | Requêtes DNS (identification des domaines C2) |
| `stream:http` | Trafic HTTP (téléchargement du payload) |
| `fgt_utm` | FortiGate UTM (détection malware côté pare-feu) |
| `stream:smb` | Trafic SMB (propagation réseau vers serveur de fichiers) |
| `WinEventLog` | Logs Windows natifs (fichiers chiffrés sur serveur) |
| `suricata` | Alertes IDS (signatures ransomware) |


## 3. Résultats

### Étape 1 — Machine compromise

**Objectif :** identifier l'IP réseau réelle du poste de Bob.

On utilise l'EventID 3 car il est dédié aux connexions réseau sortantes et enregistre l'IP telle qu'elle apparaît sur le réseau physique au moment de l'établissement de la connexion.

```splunk
index=botsv1 sourcetype=xmlwineventlog host=we8105desk
| rex field=_raw "EventID>(?<eid>\d+)<"
| rex field=_raw "'SourceIp'>(?<srcip>[^<]+)<"
| where eid=3
| stats count by srcip
```

**Explication de la requête :**
- `host=we8105desk` : filtre sur le poste de Bob
- `rex field=_raw "EventID>(?<eid>\d+)<"` : extrait le numéro d'EventID depuis le XML brut car `xmlwineventlog` n'est pas parsé nativement par Splunk
- `rex field=_raw "'SourceIp'>(?<srcip>[^<]+)<"` : extrait l'IP source contenue dans le champ SourceIp du XML
- `where eid=3` : ne garde que les connexions réseau sortantes (EventID 3 Sysmon)
- `stats count by srcip` : compte les occurrences par IP pour identifier la plus active

**Résultat :** l'IP trouvée est `192.168.250.100`, confirmée comme étant celle de Bob grâce au filtre `host=we8105desk`.


### Étape 2 — Vecteur d'entrée

**Objectif :** identifier la clé USB et le fichier malveillant ouvert par Bob.

Le registre Windows conserve automatiquement une trace des périphériques branchés. On filtre sur le champ `FriendlyName` pour récupérer le nom lisible de la clé USB.

```splunk
index="botsv1" sourcetype="WinRegistry" FriendlyName
| sort _time
```

**Explication :** `FriendlyName` est le champ du registre Windows qui contient le nom lisible d'un périphérique USB. En filtrant sur ce mot-clé, on récupère l'entrée créée au moment du branchement de la clé.

**Résultat clé USB :** `MIRANDA_PRI`

```splunk
index="botsv1" sourcetype="xmlwineventlog" host="we8105desk"
| rex field=_raw "EventID>(?<eid>\d+)<"
| rex field=_raw "'Image'>(?<Image>[^<]+)<"
| rex field=_raw "'ParentImage'>(?<ParentImage>[^<]+)<"
| rex field=_raw "'User'>(?<User>[^<]+)<"
| rex field=_raw "'CommandLine'>(?<CommandLine>[^<]+)<"
| where eid=1 AND User="WAYNECORPINC\bob.smith"
| table _time, User, Image, ParentImage, CommandLine
| sort _time
```

**Explication :**
- `sourcetype="xmlwineventlog"` : sélectionne les logs Sysmon — ce sourcetype contient les événements Windows en XML brut, non parsé nativement par Splunk
- `host="we8105desk"` : filtre sur le poste de Bob uniquement
- `rex field=_raw "EventID>(?<eid>\d+)<"` : extrait le numéro d'EventID depuis le XML brut. `\d+` capture un ou plusieurs chiffres, `(?<eid>...)` nomme le résultat dans un champ appelé `eid`
- `rex field=_raw "'Image'>(?<Image>[^<]+)<"` : extrait le chemin du processus lancé (ex: `C:\Windows\System32\cmd.exe`). `[^<]+` capture tout caractère sauf `<`, ce qui permet de s'arrêter à la balise fermante XML
- `rex field=_raw "'ParentImage'>(?<ParentImage>[^<]+)<"` : extrait le processus parent — celui qui a lancé le processus en question. Permet de reconstituer la hiérarchie d'exécution
- `rex field=_raw "'User'>(?<User>[^<]+)<"` : extrait le compte Windows sous lequel le processus a été lancé
- `rex field=_raw "'CommandLine'>(?<CommandLine>[^<]+)<"` : extrait la ligne de commande complète, incluant les arguments — révèle le fichier ouvert ou exécuté
- `where eid=1 AND User="WAYNECORPINC\bob.smith"` : ne garde que les créations de processus (EventID 1) sous le compte de Bob
- `table _time, User, Image, ParentImage, CommandLine` : affiche uniquement les colonnes utiles pour l'analyse
- `sort _time` : trie par ordre chronologique pour reconstituer la séquence d'exécution

EventID 1 Sysmon correspond à la création de processus. En filtrant sur `bob.smith` et en triant chronologiquement, le premier processus suspect révèle le fichier ouvert depuis la clé USB (lecteur `D:\`).

**Résultat fichier malveillant :** `Miranda_Tate_unveiled.dotm` (template Word avec macros, lecteur `D:\`)


### Étape 3 — Chaîne d'exécution

**Objectif :** reconstituer la séquence complète des processus depuis l'ouverture du fichier jusqu'au chiffrement.

Reconstituer la chaîne d'exécution est essentiel car un malware peut utiliser des programmes légitimes du système pour s'exécuter et se propager. Cela pose problème pour la détection : un antivirus qui voit un outil natif s'ouvrir ne fera pas le lien avec le malware.

La même requête que l'étape 2 (EventID 1, tri chronologique) révèle la chaîne complète :

```
18:43:12 — WINWORD.EXE (lancé par explorer.exe)
             └─ ouvre Miranda_Tate_unveiled.dotm depuis D:\
18:43:21 — cmd.exe (lancé par WINWORD.EXE)
             └─ wscript.exe → 20429.vbs (AppData\Roaming)
             └─ cmd.exe avec CommandLine obfusquée (VBScript)
18:48:21 — cmd.exe (lancé par wscript.exe)
             └─ 121214.tmp (AppData\Roaming) [payload intermédiaire]
             └─ osk.exe (lancé par 121214.tmp) [living off the land]
             └─ taskkill /t /f /im "121214.tmp" [auto-destruction]
18:48:42 — PING.EXE ping -n 1 127.0.0.1 [délai artificiel]
18:49:23 — osk.exe lance :
             └─ vssadmin.exe "delete shadows /all /quiet" [suppression sauvegardes #1]
             └─ wmic.exe "shadowcopy delete" [suppression sauvegardes #2]
             └─ bcdedit.exe "/set {default} bootstatuspolicy ignoreallfailures"
             └─ bcdedit.exe "/set {default} recoveryenabled no"
18:56:51 — iexplore.exe -nohome (lancé par osk.exe) [connexion réseau suspecte]
19:15:11 — notepad.exe "# DECRYPT MY FILES #.txt" [note de rançon]
19:15:12 — wscript.exe "# DECRYPT MY FILES #.vbs"
19:15:29 — osk.exe → cmd.exe → taskkill /t /f /im "osk.exe" [auto-destruction osk]
20:17:33 — ping we9041srv.waynecorpinc.local [identification serveur de fichiers]
20:17:35 — w32tm.exe /stripchart /computer:we9041srv.waynecorpinc.local
```

**Techniques notables identifiées :**

| Technique | Description | Processus impliqué |
|---|---|---|
| Living off the land | Utilisation d'un outil légitime du système pour mener l'attaque, sans déposer de nouvel exécutable suspect | `osk.exe` |
| Double suppression des sauvegardes | Suppression des copies instantanées Windows pour empêcher la restauration des fichiers à leur état avant chiffrement | `vssadmin` + `wmic` |
| Blocage de la récupération au démarrage | Empêche le système de détecter les erreurs au démarrage et de lancer toute procédure de récupération | `bcdedit` x2 |
| Auto-destruction du payload | Suppression des fichiers malveillants après exécution pour empêcher leur analyse | `taskkill` |


### Étape 4 — Communications réseau malveillantes

**Objectif :** identifier les domaines C2 contactés par le ransomware.

Avant toute connexion réseau, la machine résout le nom de domaine via DNS. En analysant `stream:dns`, on a accès à tous les domaines contactés par le poste de Bob, notamment les serveurs Command and Control (C2).

```splunk
index="botsv1" sourcetype="stream:dns" src_ip="192.168.250.100"
| stats count by query{}
| where NOT match(query{}, "microsoft|windows|waynecorpinc.local|arpa|wpad")
| sort -count
```

**Explication :**
- `src_ip="192.168.250.100"` : filtre sur les requêtes DNS émises par le poste de Bob
- `query{}` : champ multivalué dans `stream:dns` contenant le nom de domaine demandé (le `{}` indique un champ multivalué dans Splunk)
- `where NOT match(...)` : élimine le bruit légitime — Microsoft, Windows, domaine interne Wayne Corp, requêtes DNS inversées (`arpa`), proxy auto-détection (`wpad`)
- `sort -count` : les domaines les plus contactés apparaissent en premier

**Vérification VirusTotal :** les deux domaines suspects identifiés sont malveillants : `solidaritedeproximite.org` héberge des fichiers `.dotm` détectés par 48 moteurs sur 66, et `cerberhhyed5frqa.xmfir0.win` est signalé par 10 vendors sur 91 avec de nombreuses détections associées.

**Résultats :**

| Domaine | Timestamp premier contact | Statut VirusTotal |
|---|---|---|
| `solidaritedeproximite.org` | 24/08/2016 18:48:12 | Malveillant (48/66) |
| `cerberhhyed5frqa.xmfir0.win` | 24/08/2016 19:15:12 | Malveillant (10/91 + nombreuses détections) |


### Étape 5 — Payload téléchargé

**Objectif :** identifier le fichier malveillant téléchargé depuis le C2.

On utilise `fgt_utm` plutôt que `stream:http` car le FortiGate UTM analyse le contenu au niveau du pare-feu réseau : il voit l'intégralité du flux réel, même quand `stream:http` ne capture pas la transaction complète.

```splunk
index=botsv1 sourcetype=fgt_utm srcip=192.168.250.100 hostname=solidaritedeproximite.org
| sort _time
```

**Résultats :**

| IOC | Valeur |
|---|---|
| Fichier téléchargé | `mhtr.jpg` |
| Technique d'obfuscation | Stéganographie — technique qui consiste à dissimuler des données dans un fichier anodin (ici un exécutable caché dans une image `.jpg`) pour contourner les solutions de sécurité basées sur l'extension de fichier |


### Étape 6 — Dégâts locaux

**Objectif :** compter les fichiers chiffrés sur le poste de Bob.

EventID 2 Sysmon enregistre les modifications du timestamp d'un fichier. Cerber modifie le timestamp de chaque fichier qu'il chiffre, ce qui génère un EventID 2 — c'est le signal de détection utilisé ici.

```splunk
index=botsv1 sourcetype=xmlwineventlog host=we8105desk
| rex field=_raw "EventID>(?<eid>\d+)<"
| rex field=_raw "'TargetFilename'>(?<tfn>[^<]+)<"
| where eid=2
| eval extension = mvindex(split(tfn, "."), -1)
| where match(tfn, ".*bob\\.smith\\.WAYNECORPINC.*")
| where extension="txt"
| dedup tfn
| stats count
```

**Explication des commandes SPL spécifiques :**
- `eval extension = mvindex(split(tfn, "."), -1)` : extrait l'extension du fichier. `split(tfn, ".")` découpe le nom à chaque point et produit une liste. `mvindex(..., -1)` prend le dernier élément de cette liste (l'extension)
- `dedup tfn` : élimine les doublons — un même fichier peut apparaître plusieurs fois si Sysmon a enregistré plusieurs modifications successives
- `where match(tfn, ".*bob\\.smith\\.WAYNECORPINC.*")` : filtre sur le profil de Bob uniquement. Les `\\.` échappent le point, qui est un caractère spécial en regex

**Résultat :** 401 fichiers `.txt` distincts chiffrés, tous localisés dans `C:\Users\bob.smith.WAYNECORPINC\Desktop\` et ses 131 sous-dossiers.


### Étape 7 — Propagation réseau

**Objectif :** quantifier les PDFs chiffrés sur le serveur de fichiers `we9041srv`.

**Identification du serveur :** le hostname `we9041srv` a été découvert à l'étape 3 via un ping lancé par `osk.exe` à 20:17:33. Son IP a été confirmée en analysant les destinations SMB depuis le poste de Bob :

```splunk
index=botsv1 sourcetype=stream:smb src_ip=192.168.250.100
| stats count by dest_ip
```

`stream:smb` ne suffit pas ici car il ne parse pas les noms de fichiers — aucun champ exploitable n'est disponible. On bascule sur `WinEventLog` côté serveur, qui enregistre nativement les accès aux fichiers partagés via le champ `Relative_Target_Name`.

```splunk
index=botsv1 sourcetype=wineventlog host=we9041srv user=bob.smith *.pdf Access_Mask=0x12019F
| table Relative_Target_Name
```

**Explication :**
- `user=bob.smith` : s'assure que les accès proviennent bien du compte de Bob
- `*.pdf` : filtre sur les fichiers PDF uniquement
- `Access_Mask=0x12019F` : valeur hexadécimale Windows correspondant à un accès en lecture + écriture. Un ransomware lit le fichier, le chiffre, puis écrase le contenu original — cela génère systématiquement un accès en écriture
- `Relative_Target_Name` : champ Windows contenant le chemin relatif du fichier accédé sur le partage

**Résultat :** 257 fichiers `.pdf` ont été accédés en lecture et écriture depuis le poste de Bob. Au vu du contexte, il est raisonnable de conclure que ces fichiers ont été chiffrés par Cerber.


### Étape 8 — C2 final et signature Suricata

**Objectif :** identifier le dernier domaine contacté après le chiffrement et la signature IDS associée.

```splunk
index=botsv1 sourcetype=suricata src_ip=192.168.250.100 event_type=alert
| table _time, alert.signature
| sort _time
```

**Pourquoi `event_type=alert` :** Suricata génère plusieurs types d'événements (`dns`, `http`, `tls`, `flow`, `alert`). Seul `alert` correspond à une règle IDS déclenchée — les autres types sont des logs réseau passifs.

**Résultats :**

| Timestamp | Signature |
|---|---|
| 2016-08-24 18:49:24 | ETPRO TROJAN Ransomware/Cerber Checkin 2 |
| 2016-08-24 18:50:25 | ET POLICY Possible External IP Lookup ipinfo.io |
| 2016-08-24 19:15:12 | ETPRO TROJAN Ransomware/Cerber Onion Domain Lookup |
| 2016-08-24 19:15:12 | ETPRO TROJAN Ransomware/Cerber Onion Domain Lookup |

**Signature retenue :** `ETPRO TROJAN Ransomware/Cerber Onion Domain Lookup` — son timestamp (19:15:12) correspond au moment où `wscript.exe` exécute `# DECRYPT MY FILES #.vbs`, la note de rançon, qui marque la fin du chiffrement.


## 4. Analyse

### Kill Chain Cerber

| Phase Cyber Kill Chain | Action | IOC |
|---|---|---|
| Reconnaissance | — | — |
| Livraison | Clé USB déposée dans le parking (baiting) | `MIRANDA_PRI` |
| Exploitation | Macro Word exécutée à l'ouverture | `Miranda_Tate_unveiled.dotm` |
| Installation | VBScript → payload temporaire | `20429.vbs` → `121214.tmp` |
| Commande & Contrôle | Résolution DNS premier C2 | `solidaritedeproximite.org` |
| Actions sur objectifs | Téléchargement du cryptor via stéganographie | `mhtr.jpg` |
| Actions sur objectifs | Living off the land — détournement de processus légitime | `osk.exe` |
| Actions sur objectifs | Destruction des sauvegardes et blocage de la récupération | `vssadmin` + `wmic` + `bcdedit` |
| Actions sur objectifs | Chiffrement local | 401 fichiers `.txt` — `C:\Users\bob.smith.WAYNECORPINC\Desktop\` |
| Actions sur objectifs | Propagation SMB vers serveur de fichiers | `we9041srv` |
| Actions sur objectifs | C2 post-chiffrement via réseau Tor | `cerberhhyed5frqa.xmfir0.win` |

### Points d'attention

**Living off the land :** technique consistant à utiliser des outils légitimes du système pour mener l'attaque, sans déposer de nouvel exécutable suspect. Elle est particulièrement difficile à détecter car un antivirus considère l'exécution d'un outil natif comme un comportement normal, sans faire le lien avec le malware.

**Double suppression des sauvegardes :** Cerber supprime les copies instantanées Windows (`vssadmin` + `wmic shadowcopy delete`) pour empêcher toute restauration des fichiers à leur état avant chiffrement. L'impact opérationnel est critique : sans sauvegardes, l'entreprise n'a pas d'autre option que de payer la rançon ou de tout reconstruire.

**Stéganographie :** technique consistant à dissimuler des données dans un fichier anodin. Ici, un exécutable malveillant est caché dans une image `.jpg`. Cette approche contourne les solutions de sécurité basées sur l'extension de fichier : un `.jpg` est jugé inoffensif par défaut et ne déclenche aucune analyse approfondie.


## 5. IOC (Indicateurs de Compromission)

| Type | IOC | Valeur |
|---|---|---|
| Hostname poste infecté | Hostname | `we8105desk` |
| IP poste infecté | IPv4 | `192.168.250.100` |
| Utilisateur | Compte Windows | `WAYNECORPINC\bob.smith` |
| Clé USB | FriendlyName registre | `MIRANDA_PRI` |
| Vecteur initial | Fichier Word avec macros | `Miranda_Tate_unveiled.dotm` |
| Script malveillant | VBScript | `AppData\Roaming\20429.vbs` |
| Payload intermédiaire | Exécutable temporaire | `121214.tmp` |
| Payload ransomware | Processus détourné | `osk.exe` |
| Note de rançon | Fichiers | `# DECRYPT MY FILES #.txt` / `.vbs` |
| Domaine C2 n°1 | FQDN | `solidaritedeproximite.org` |
| Payload cryptor | Fichier image (stéganographie) | `mhtr.jpg` |
| Domaine C2 final | FQDN | `cerberhhyed5frqa.xmfir0.win` |
| Serveur de fichiers | Hostname | `we9041srv.waynecorpinc.local` |
| Fichiers `.txt` chiffrés | Poste Bob | 401 |
| PDFs chiffrés | Serveur `we9041srv` | 257 |
| Signature IDS | Suricata | `ETPRO TROJAN Ransomware/Cerber Onion Domain Lookup` |


## 6. Recommandations

Afin de prévenir ce type d'attaque et d'en limiter l'impact si elle venait à se produire malgré tout, plusieurs recommandations peuvent être appliquées :

- **Politique USB :** sensibiliser les employés au risque de brancher une clé USB inconnue. L'entreprise peut interdire le branchement de tout périphérique USB non référencé, en se limitant à des clés professionnelles utilisées exclusivement sur les postes de l'entreprise. Pour les cas légitimes nécessitant l'utilisation d'une clé externe, des solutions dites de "salle blanche" existent : une machine hors réseau est dédiée à l'analyse des supports extérieurs, permettant de vérifier leur contenu avant tout transfert.

- **Désactivation des macros Office :** un fichier `.dotm` est un template Word contenant des macros — des scripts automatisés exécutés à l'ouverture du fichier. Si les macros sont désactivées par défaut dans la politique Office de l'entreprise, ce type de fichier devient inoffensif. Il est possible de maintenir les macros actives pour les fichiers signés numériquement par l'entreprise et provenant d'emplacements de confiance, sans impacter les usages légitimes.

- **Sauvegardes hors ligne :** la sauvegarde hors ligne est aujourd'hui un incontournable de la sécurité en entreprise. Un support physiquement déconnecté du réseau ne peut pas être atteint par un ransomware lors de sa propagation. La règle des 3-2-1 est la référence : 3 copies des données, sur 2 supports différents, dont 1 hors site.

- **Segmentation réseau :** diviser le réseau en zones isolées regroupant les machines ayant les mêmes besoins de communication, avec des règles de filtrage strictes entre zones. Dans ce scénario, l'absence de segmentation a permis à Cerber de se propager librement du poste de Bob vers le serveur de fichiers via SMB, sans aucune restriction.

- **Surveillance des processus système :** un outil comme Sysmon, couplé à des règles d'alerte dans un SIEM, permet de détecter les comportements anormaux : `osk.exe` (clavier virtuel Windows) qui lance `cmd.exe` ou `vssadmin` n'est jamais légitime. Cette surveillance constitue un filet de sécurité complémentaire pour détecter les attaques de type living off the land.


## 7. Conclusion

Cette investigation a permis de reconstituer l'intégralité de l'attaque Cerber sur le réseau Wayne Corporation : du branchement de la clé USB jusqu'au chiffrement de 401 fichiers locaux et 257 PDFs sur le serveur de fichiers. La gravité est critique — l'entreprise s'est retrouvée paralysée, ses sauvegardes détruites, sans possibilité de récupération immédiate. Cet incident illustre une limite fondamentale des défenses périmètriques : une fois le vecteur physique utilisé, pare-feu et filtrage web ne servent à rien. La détection repose alors entièrement sur la surveillance interne (logs, SIEM, IDS) et la rapidité de réponse du SOC.

---

*Write-up rédigé dans le cadre d'une formation cybersécurité autodidacte.*  
