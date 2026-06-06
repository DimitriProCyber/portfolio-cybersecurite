# Déploiement et sécurisation d'une infrastructure réseau trois zones avec pfSense

**06 juin 2026**

**Environnement :** Home lab VirtualBox · pfSense CE 2.8.1 · Kali Linux · Debian 13 "Trixie"  
**Objectif :** Déployer et sécuriser une infrastructure réseau trois zones (LAN / DMZ / WAN) avec pfSense CE selon les bonnes pratiques ANSSI, en partant de zéro, dans un contexte PME simulé.
**Niveau :** Niveau 2 — reconstruction from scratch  


## 1. Contexte

NordLogistique est une PME de 45 employés basée dans le Nord de la France, spécialisée dans la gestion d'entrepôts. Suite à une tentative d'intrusion via un ancien routeur non sécurisé, la direction a décidé de refondre complètement son infrastructure réseau.

L'entreprise souhaite également exposer un site vitrine sur internet, hébergé en interne. Cette contrainte impose d'ouvrir un accès depuis l'extérieur vers un serveur web via NAT, tout en protégeant le réseau interne des connexions entrantes.

**Mission :** déployer une architecture réseau sécurisée from scratch, segmentée en trois zones distinctes, selon les bonnes pratiques ANSSI, et valider chaque mesure de sécurité par des tests concrets.

La segmentation réseau apporte une meilleure protection en cas d'intrusion. Chaque sous-réseau est protégé des autres car le trafic y est filtré : on autorise que ce qui est nécessaire (principe du moindre privilège), le reste étant bloqué. Ca limite les possibilité d'un attaquant de se propager ou d'extraire des données, et les tentatives bloquées sont enregistrées ce qui permet de documenter l'attaque.


## 2. Architecture réseau

### 2.1 Principe de segmentation trois zones

L'architecture déployée repose sur trois zones réseau isolées, chacune avec un niveau de confiance différent :

| Zone | Réseau | Rôle | Niveau de confiance |
|------|--------|------|---------------------|
| WAN | 192.168.56.0/24 | Internet simulé (Kali Host-Only) | Non fiable |
| LAN | 192.168.1.0/24 | Postes utilisateurs internes | Fiable |
| DMZ | 192.168.2.0/24 | Serveur web exposé | Intermédiaire |

Le serveur web étant exposé à internet est par conséquent plus vulnérable, c'est pour ça qu'on cherche à l'isoler du réseau interne de l'entreprise en le plaçant en DMZ (DeMilitarized Zone). Du fait de son exposition, c'est lui qui sera ciblé en priorité par un attaquant, et s'il est corrompu on limitera considérablement les possibilités de propagation vers les autres machines du réseau.

### 2.2 Schéma réseau

```
Internet (simulé par Kali Host-Only 192.168.56.x)
                                    │
   [pfSense WAN] — em0 — 192.168.56.105/24
                                   │
   ┌──────────┴───────────────┐
            │                                              │
[pfSense LAN]                       [pfSense DMZ]
em1 — 192.168.1.1/24    em2 — 192.168.2.1/24
                 │                                         │
  Kali (poste admin)                debian-dmz
      192.168.1.100                     192.168.2.10
(DHCP range .100-.199)    (réservation statique)
                                                     Apache2 + SSH
```

### 2.3 VMs et interfaces VirtualBox

| VM | Rôle | Interface VirtualBox | IP |
|----|------|---------------------|----|
| pfSense CE 2.8.1 | Pare-feu 3 zones | em0=Host-Only / em1=pfsense-lan / em2=pfsense-dmz | 192.168.56.105 / 192.168.1.1 / 192.168.2.1 |
| Kali Linux | Poste admin + internet simulé | eth0=Host-Only / eth2=pfsense-lan | 192.168.56.100 / 192.168.1.100 |
| Debian 13 "Trixie" | Serveur web DMZ | enp0s3=pfsense-dmz | 192.168.2.10 |


## 3. Méthodologie

### 3.1 Démarche générale

Le déploiement a suivi une approche structurée en cinq blocs :

1. **Architecture réseau** : configuration des interfaces pfSense et adressage IP.
2. **Politique de filtrage** : définition des règles firewall par zone selon le principe de la whitelist.
3. **Services réseau** : réservation DHCP statique par adresse MAC pour le serveur web et NAT Port Forwarding vers la DMZ.
4. **Hardening** : durcissement de l'interface d'administration pfSense.
5. **Tests de validation** : vérification du bon fonctionnement de chaque règle et analyse des logs.

### 3.2 Principe whitelist appliqué

Le principe de la whitelist revient à tout bloquer par défaut, pour ensuite autoriser uniquement ce qui est nécessaire au bon fonctionnement de l'entreprise (principe du moindre privilège). Cette politique est plus sûre que la politique de la blacklist qui revient à bloquer un par un les services non nécessaires, car le volume de travail étant souvent bien plus conséquent, on s'expose plus facilement à des oublis. Ici, tout paquet ne correspondant à aucune règle d'autorisation est automatiquement bloqué par la règle "deny all" placée en dernière position.


## 4. Configuration déployée

### 4.1 Aliases créés

Une politique de filtrage peut rapidement contenir plusieurs règles ciblant le même objectif (par exemple trois règles séparées pour autoriser l'accès à internet grâce à HTTP, HTTPS et DNS). Les aliases permettent de regrouper des ports, adresses IP ou URL entre eux, permettant de réduire le nombre de règles à écrire. La politique de filtrage est ainsi plus lisible et facile à maintenir.

| Alias | Type | Contenu | Justification |
|-------|------|---------|---------------|
| RFC1918 | Networks | 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 | Regroupe toutes les IPs privées — utilisé avec invert match pour cibler uniquement les IPs publiques |
| Web_Ports | Ports | 80 (HTTP), 443 (HTTPS), 53 (DNS) | Ports nécessaires pour naviguer sur internet |
| DMZ_Ports | Ports | 80 (HTTP), 443 (HTTPS) | Ports HTTP/HTTPS vers le serveur web — sans DNS (inutile vers un serveur web) |
| C2_Ports | Ports | 9001 (Tor ORPort), 9030 (Tor DirPort), 6667 (IRC) | Ports caractéristiques des communications Command & Control |
| Admins_Ports | Ports | 22 (SSH), 443 (HTTPS) | Ports d'administration |

### 4.2 Règles LAN (dans l'ordre d'évaluation)

L'ordre dans lequel les règles sont placées est critique car pfSense les évaluent de haut en bas et s'arrête à la première règle qui correspond au paquet. 

| Priorité | Action | Source | Destination | Port | Description | Justification |
|----------|--------|--------|-------------|------|-------------|---------------|
| 1 | Pass | 192.168.1.100 | 192.168.1.1 | 8443 | Allow admin WebGUI from Kali only | Seul le poste admin accède à l'interface pfSense |
| 2 | Pass | LAN subnets | 192.168.1.1 | 53 (DNS) | Allow LAN to pfSense DNS | Résolution DNS locale via pfSense |
| 3 | Block | LAN subnets | !RFC1918 | C2_Ports | Block LAN to WAN C2 Ports | Bloque les communications vers des serveurs C2 externes |
| 4 | Pass | LAN subnets | !RFC1918 | Web_Ports | Allow LAN to WAN web and DNS | Navigation internet autorisée |
| 5 | Pass | LAN subnets | DMZ subnets | DMZ_Ports | Allow LAN to DMZ HTTP/HTTPS | Accès au serveur web interne |
| 6 | Block | LAN subnets | DMZ subnets | Any | Block LAN to DMZ any | Interdit tout autre accès vers la DMZ |
| 7 | Block | LAN subnets | Any | Any | Block all LAN to any | Deny all — bloque tout le reste |

Ici par exemple, il est impératif de placer la règle 3 qui bloque l'accès aux serveurs C2 (Command and Control) externes avant la règle 4, car en cas de compromission d'un poste interne tentant de contacter un serveur C2 à l'insu de l'utilisateur, si la règle "Allow LAN to WAN web and DNS" est lue en première, le pare-feu va arrêter son scan de règle ici car la règle correspondra, permettant alors au paquet d'être expédié. La règle "Block LAN to WAN C2 Ports" ne sera jamais lue.

### 4.3 Règles DMZ (dans l'ordre d'évaluation)

| Priorité | Action | Source | Destination | Port | Description | Justification |
|----------|--------|--------|-------------|------|-------------|---------------|
| 1 | Pass | DMZ subnets | !RFC1918 | Web_Ports | Allow DMZ to WAN web and DNS | Le serveur web peut accéder à internet pour les mises à jour |
| 2 | Block | DMZ subnets | 192.168.2.1 | 53 (DNS) | Block DMZ DNS noise - no log | Élimine le bruit DNS sans polluer les logs |
| 3 | Block | DMZ subnets | LAN subnets | Any | Block DMZ to LAN | Interdit tout mouvement latéral vers le réseau interne |
| 4 | Block | DMZ subnets | Any | Any | Block DMZ to any | Deny all — bloque tout le reste |

📝 *Expliquer pourquoi bloquer le mouvement latéral DMZ → LAN est critique : que se passe-t-il si un attaquant compromet le serveur web ?*

### 4.4 Réservation DHCP statique — debian-dmz

Un serveur exposé sur internet doit avoir une IP fixe pour deux raisons : la règle NAT doit pointer vers une IP stable, et les logs doivent être cohérents dans le temps.

La réservation a été configurée via l'adresse MAC de debian-dmz :

```
MAC : 08:00:27:a7:08:23 → IP : 192.168.2.10
```

### 4.5 NAT Port Forwarding

Le NAT Port Forwarding permet à un utilisateur externe d'accéder au serveur web en DMZ sans connaître son IP interne. pfSense reçoit la requête sur son IP WAN et la redirige vers debian-dmz.

```
Requête externe → 192.168.56.105:80 (WAN pfSense)
                        ↓ NAT
              192.168.2.10:80 (debian-dmz Apache)
```

| Paramètre | Valeur |
|-----------|--------|
| Interface | WAN |
| Protocol | TCP |
| Destination | WAN address, port 80 |
| Redirect vers | 192.168.2.10, port 80 |

### 4.6 Hardening WebGUI pfSense

Trois mesures appliquées pour réduire la surface d'attaque de pfSense lui-même :

**Mesure 1 — Port personnalisé**  
Port WebGUI déplacé de 443 vers **8443**. Réduit le risque d'attaques opportunistes automatisées qui testent les ports standards. Note : cette mesure relève de la *security through obscurity* — elle réduit le bruit mais ne remplace pas une règle firewall.

**Mesure 2 — Accès restreint à une IP**  
La règle Anti-Lockout automatique a été désactivée après création d'une règle manuelle autorisant uniquement 192.168.1.100 (poste admin Kali) à accéder à la WebGUI sur le port 8443. Tout autre poste du LAN est bloqué.

> **Ordre de manipulation critique :** créer la règle d'autorisation AVANT de désactiver l'Anti-Lockout, sous peine de se couper l'accès à pfSense.

**Mesure 3 — Vérification mDNS/Avahi**  
Le package Avahi (implémentation mDNS sur pfSense) n'est pas installé par défaut. Vérification effectuée via System → Package Manager → Installed Packages : aucun package installé. Surface d'attaque nulle sur ce vecteur.

---

## 5. Résultats des tests de validation

| Test | Méthode | Résultat attendu | Résultat obtenu |
|------|---------|-----------------|-----------------|
| Accès HTTP via NAT (internet → Apache) | `curl http://192.168.56.105` depuis Kali eth0 | Page Apache Debian | ✅ Page Apache obtenue |
| Accès HTTP LAN → DMZ direct | `curl http://192.168.2.10` depuis Kali eth2 | Page Apache Debian | ✅ Page Apache obtenue |
| Mouvement latéral DMZ → LAN | `ssh webadmin@192.168.1.100` depuis debian-dmz | Timeout | ✅ Connection timed out |
| Port C2 bloqué | `curl --interface eth2 http://192.168.56.105:9001` | Bloqué | ⚠️ Voir analyse ci-dessous |
| Signature scan Nmap dans logs | `nmap -sS 192.168.56.105` depuis Kali eth0 | TCP:S en rafale dans logs WAN | ✅ Signature visible |
| WebGUI accessible uniquement sur 8443 | `curl -k https://192.168.1.1:8443` | Page pfSense | ✅ Accès confirmé |
| DNS LAN → pfSense | `nslookup google.com 192.168.1.1` | Requête atteint pfSense | ✅ SERVFAIL reçu (normal sans internet) |

### Analyse — Test port C2 non conclusif

La règle "Block LAN to WAN C2 Ports" utilise un invert match sur RFC1918 pour cibler uniquement les IPs publiques. Dans ce lab, l'IP WAN de pfSense (192.168.56.105) est une IP privée — la règle ne s'applique donc pas à ce trafic. Le résultat "failed to connect" obtenu s'explique par l'absence de service sur le port 9001, pas par le firewall.

**Limite du lab :** sans accès internet réel ou simulation d'IP publique, ce test ne peut pas être conclusif. En production, le test serait effectué vers une IP publique réelle.

---

## 6. Analyse des logs firewall

### 6.1 Signature de scan Nmap

Extrait des logs lors du scan `nmap -sS 192.168.56.105` :

```
Action  Interface  Règle                        Source                  Destination              Protocol
Block   WAN        Default deny rule IPv4       192.168.56.100:64130    192.168.56.105:1309      TCP:S
Block   WAN        Default deny rule IPv4       192.168.56.100:64130    192.168.56.105:9944      TCP:S
Block   WAN        Default deny rule IPv4       192.168.56.100:64130    192.168.56.105:5989      TCP:S
Block   WAN        Default deny rule IPv4       192.168.56.100:64132    192.168.56.105:1812      TCP:S
[... ~999 entrées similaires en moins d'une seconde ...]
```

**Trois indicateurs caractéristiques d'un scan automatisé :**

📝 *Lister et expliquer les 3 signatures : volumétrie (grand nombre de paquets en très peu de temps), ports variés et non séquentiels, protocole TCP:S (SYN sans ACK — le handshake n'est jamais complété).*

### 6.2 Blocage mouvement latéral

📝 *Décrire en 2-3 phrases ce qu'on observerait dans les logs si on avait activé le logging sur la règle "Block DMZ to LAN" lors du test SSH depuis debian-dmz.*

### 6.3 Bruit DNS éliminé

Avant la règle "Block DMZ DNS noise - no log", les logs montraient un flux continu de requêtes UDP port 53 depuis debian-dmz vers 192.168.2.1. Ce trafic correspondait aux requêtes DNS automatiques du système d'exploitation, sans rapport avec une activité malveillante.

📝 *Expliquer pourquoi ce bruit est problématique pour un analyste SOC, et comment la règle sans logging résout le problème sans perdre de visibilité sur les vraies menaces.*

---

## 7. Erreurs identifiées et corrigées

### Erreur 1 — Route retour manquante sur debian-dmz

**Symptôme :** `curl http://192.168.56.105` retournait un timeout alors que le NAT était correctement configuré et Apache était en cours d'exécution.

**Diagnostic (méthode OSI bottom-up) :**

```bash
# Étape 1 — vérifier que Kali envoie bien le paquet
ip route get 192.168.56.105
# → via eth0, src 192.168.56.100 ✓

# Étape 2 — isoler le problème : tester LAN→DMZ directement (sans NAT)
curl http://192.168.2.10
# → timeout aussi → problème côté debian-dmz, pas dans le NAT

# Étape 3 — vérifier qu'Apache écoute
ss -tlnp | grep 80
# → *:80 apache2 ✓

# Étape 4 — vérifier la table de routage de debian-dmz
ip route show
# → PAS de route par défaut ← PROBLÈME TROUVÉ
```

**Cause :** lors du montage manuel de l'interface réseau, le bail DHCP n'avait pas été obtenu correctement — debian-dmz recevait les paquets mais ne savait pas vers où renvoyer les réponses.

**Résolution :**
```bash
ip route add default via 192.168.2.1
```

📝 *Expliquer en une phrase le concept de "route retour" : pourquoi un serveur qui reçoit un paquet doit savoir comment répondre, et ce qui se passe si la route manque (timeout côté client, pas "connexion refusée").*

### Erreur 2 — Source/Destination inversées sur règle Allow Web

**Symptôme :** lors de la création de la règle "Allow LAN to WAN web and DNS", l'invert match sur RFC1918 avait été appliqué sur la source au lieu de la destination.

**Impact :** la règle aurait autorisé les IPs publiques (sources) à initier des connexions depuis le LAN — ce qui n'a pas de sens. La règle correcte autorise le LAN à contacter des destinations non-RFC1918 (IPs publiques).

**Résolution :** correction de la configuration source/destination après raisonnement sur le sens du trafic.

### Erreur 3 — Alias DMZ_Ports rationalisé

**Situation initiale :** deux règles séparées pour HTTP et HTTPS vers la DMZ.

**Amélioration :** création de l'alias DMZ_Ports (80/443 sans DNS). Le DNS a été délibérément exclu — contrairement à Web_Ports utilisé pour la navigation internet, un serveur web n'a pas besoin de résoudre des noms de domaine pour servir des pages.

---

## 8. Recommandations

### Mesures prioritaires pour une mise en production

| Priorité | Mesure | Justification |
|----------|--------|---------------|
| Haute | Activer Suricata sur l'interface WAN | Détection d'intrusion en temps réel — alerte sur les scans et tentatives d'exploitation |
| Haute | Certificat TLS valide sur la WebGUI | Le certificat auto-signé actuel génère des avertissements et n'est pas authentifié |
| Haute | Authentification par clé SSH sur pfSense | Remplace l'authentification par mot de passe, plus robuste contre le brute force |
| Moyenne | Syslog distant (ex: Graylog) | Les logs locaux pfSense sont limités à 500 entrées — insuffisant pour une investigation sérieuse |
| Moyenne | Mises à jour automatiques pfSense | Correction des vulnérabilités sans intervention manuelle |
| Basse | Vérification de la persistance de la route par défaut sur debian-dmz | La route ajoutée manuellement doit être vérifiée après redémarrage |

📝 *Ajouter 1-2 recommandations spécifiques au contexte NordLogistique (PME logistique, 45 employés) — par exemple : segmentation WiFi invités, politique de mots de passe, sensibilisation.*

---

## 9. Conclusion

📝 *3-4 phrases : ce que cette infrastructure apporte concrètement à NordLogistique par rapport à leur situation initiale. Mentionner : isolation du serveur web, blocage des communications C2, visibilité via les logs, accès administration restreint. Conclure sur ce que ce lab démontre en termes de compétences.*

---

*Write-up rédigé dans le cadre d'une formation cybersécurité autonome — home lab VirtualBox, juin 2026.*  
*Portfolio complet : [github.com/DimitriProCyber/portfolio-cybersecurite](https://github.com/DimitriProCyber/portfolio-cybersecurite)*
