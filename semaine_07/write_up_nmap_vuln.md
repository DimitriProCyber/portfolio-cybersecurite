**Scan Nmap — Metasploitable 2**

**19 Avril 2026**

**Objectif :** recherche de vulnérabilités à l'aide de l'outil Nmap

**Environnement :**

- Kali Linux : 192.168.56.100
- Metasploitable 2 : 192.168.56.101
- Réseau isolé VirtualBox (labnet)

**Contexte :**

Dans le cadre d'une formation en cybersécurité, avec pour objectif le passage de certification CompTIA Security+, j'ai réalisé un audit de reconnaissance avancé sur Metasploitable 2, une machine volontairement vulnérable.
L'objectif était d'identifier les services exposés, détecter les vulnérabilités connues, et produire un rapport structuré tel qu'attendu en contexte professionnel.

**Commandes utilisées :**

- *sudo nmap -A 192.168.56.101 -oN scan_complet.txt* : -A permet de lancer un scan complet (agressive scan) qui combine 4 options en une : détection de l'OS (-O), détection des versions services (-sV), scripts NSE par défaut (-sC) et traceroute.
  NSE : Nmap Script Engine. Il s'agit d'un moteur de scripts intégré à Nmap. Il existe des centaines de scripts permettant d'automatiser des tâches comme : détecter des vulnérabilités connues, tester des authentifications, récupérer des informations sur les services. Ils sont fournis par défauts, mais les utilisateurs peuvent rédiger leur propres scripts également (LUA).
  Traceroute : fournit à l'utilisateur des informations sur le chemin des paquets de données sur le réseau.
  
- *sudo nmap --script vuln 192.168.56.101 -oN scan_vuln.txt* : --script vuln lance une catégorie de scripts NSE cherchant activement les failles connues sur chaque service détecté. Une fois la faille détectée, le script va également chercher à l'exécuter afin de démontrer que la machine est vulnérable.

**Résultats :**

*Surface d'attaque - services exposés :*

Ce que Nmap -A a révélé sur Metasploitable 2 :

OS détécté : Linux 2..6.9 - 2.6.33 (kernel ancien, 2010)

Services critiques identifiés :

Port | Service | Version | Risque
:---: | :---: | :--- | :---
21 | FTP | vsftpd 2.3.4 | Backdoor connue (CVE-2011-2523)
21 | FTP | Connexion anonyme autorisée | Accès sans mot de passe
22 | SSH | OpenSSH 4.7p1 | Version obsolète
23 | Telnet | Linux telnetd | Trafic en clair
25 | SMTP | Postfix | VRFY activé (énumération users)
25 | SMTP | SSLv2 supporté | Protocole mort depuis 2011
53 | DNS | BIND 9.4.2 | Version obsolète
80 | HTTP | Apache 2.2.8 | Non chiffré
139/445 | SMB | Samba 3.0.20 | CVE-2007-2447 (exécution de code)
1524 | Shell | **Metasploitable root shell** | Shell root ouvert sur le réseau
3306 | MySQL | 5.0.51a | Potentiellement sans authentification
5432 | PostgreSQL | 8.3.0 |  
5900 | VNC | Protocol 3.3 | Pas de chiffrement
6667 | IRC | UnrealIRCd | Backdoor connue
8180 | HTTP | Tomcat 5.5 | Interface admin exposée

Observation marquante : port 1524 = shell root directement accessible. Sur un vrai système c'est catastrophique car l'attaquant a un accès complet immédiat.

*Vulnérabilités confirmées :*

Ce que Nmap --script vuln a révélé :

CVE | Service/Port | Criticité | Ce que ça permet
:---: | :---: | :--- | :---
CVE-2011-2523 | FTP/21 vsftpd 2.3.4 | Critique | Shell root — exploit confirmé par Nmap
CVE-2014-3566 | SMTP/25, PostgreSQL/5432 | Élevé | POODLE — déchiffrement SSL MitM
CVE-2015-4000 | SMTP/25 | Élevé | Logjam — downgrade TLS vers chiffrement cassable
CVE-2014-0224 | PostgreSQL/5432 | Élevé | CCS Injection — hijack session TLS
Java RMI | RMI/1099 | Élevé | Exécution de code à distance
DH faible | Multiple | Moyen | Écoute passive possible
CSRF | HTTP/80 DVWA | Moyen | Formulaires sans protection
SQLi potentielle | HTTP/80 Mutillidae | Moyen | Injection SQL sur ~30 URLs
JSESSIONID sans HttpOnly | Tomcat/8180 | Moyen | Vol de cookie session
http-trace activé | HTTP/80 | Moyen | Fuite d'en-têtes/cookies
Répertoires /admin exposés | HTTP/80 | Moyen | Énumération interface admin

**Analyse :**

*Vulnérabilité prioritaire : CVE-2011-2523 (vsftpd 2.3.4 backdoor) :*

Explication niveau 1:

Le serveur FTP installé sur cette machine contient une porte dérobée introduite intentionnellement par un attaquant en 2011. Toute personne connaissant cette faille peut prendre le contrôle total de la machine en quelques secondes, sans mot de passe.

Explication niveau 2 - technique :

vsftpd 2.3.4 contient une backdoor activée lorsqu'un utilisateur se termine par ":)". Le serveur ouvre alors un shell root sur le port 6200/TCP. Nmap a confirmé l'exploitation de la backdoor : "uid=0(root) gid=0(root)". CVSS V3 = 9.8 (Critique).

*Problème systémique identifié :*

Au-delà des CVE individuelles, ce système présente une surface d'attaque caractéristique d'une PME non maintenue :

- Protocoles obsolètes (Telnet, SSLv2, FTP anonyme)
- Aucune segmentation réseau
- Services inutiles exposés (IRC, Java RMI, VNC non chiffrés)
- Certificats SSL expirés depuis 2010

**Recommandations :**

Priorité | Action | Justification
:---: | :--- | :---
Immédiate | Désactiver vsftpd 2.3.4 / mettre à jour | Backdoor exploitable sans authentification
Immédiate | Fermer port 1524 | Shell root exposé en clair 
Immédiate | Désactiver Telnet → remplacer par SSH | Trafic credentials en clair 
Immédiate | Désactiver FTP anonyme | Accès sans authentification 
Court terme | Mettre à jour OpenSSL | POODLE, Logjam, CCS Injection 
Court terme | Désactiver SSLv2/SSLv3 | Protocoles cryptographiquement cassés 
Court terme | Audit des services actifs | Réduire la surface d'attaque 
Moyen terme | Segmentation réseau | Limiter la propagation latérale 

**Conclusion :**

Ce système présente un niveau de risque incompatible avec toute utilisation en production. Une remédiation complète nécessiterait une réinstallation depuis une base saine plutôt qu'une correction service par service.




*Write-up rédigé dans le cadre d'un home lab éducatif. Toutes les manipulations ont été effectuées sur un réseau isolé avec des machines dédiées à cet usage.*
