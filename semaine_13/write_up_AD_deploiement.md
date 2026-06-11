# Déploiement Active Directory : infrastructure d'annuaire pour une PME

**11 juin 2026**

**Environnement :** Home lab VirtualBox — domaine `dpro.lab`  
**Objectif :** Déployer un contrôleur de domaine Windows Server 2022 dans un contexte PME : DC, DNS, DHCP, OUs, GPO, audit et délégation de droits.
**Difficulté :** N1 - Guidé


## Contexte

La grande majorité des entreprises de plus de dix personnes s'appuient sur Microsoft Active Directory pour gérer leurs utilisateurs, leurs machines et leurs droits d'accès. Pour un technicien sécurité ou un administrateur systèmes, savoir déployer et configurer un domaine AD de zéro est une compétence fondamentale.

Ce lab reproduit le déploiement initial d'une infrastructure d'annuaire dans un contexte PME fictif. L'objectif était de passer d'un serveur Windows vierge à un contrôleur de domaine pleinement opérationnel, avec une structure organisationnelle cohérente, des politiques de sécurité appliquées par GPO, de l'audit activé et une délégation de droits correctement configurée.

---

## Environnement technique

| Composant | Valeur |
|---|---|
| Hyperviseur | VirtualBox (réseau Host-Only) |
| Système | Windows Server 2022 Standard Evaluation (expérience de bureau) |
| Nom du serveur | DC01 |
| Domaine | `dpro.lab` |
| Adresse IP fixe | 192.168.56.110 |
| DNS | 127.0.0.1 (le DC se résout lui-même) |

---

## Méthodologie

Le déploiement a suivi un ordre logique dicté par les dépendances techniques : on ne peut pas créer des objets dans un domaine qui n'existe pas encore, et on ne peut pas promouvoir un serveur en contrôleur de domaine sans lui avoir d'abord attribué une IP fixe et un nom stable. Chaque étape conditionne la suivante.

### 1. Création de la VM et installation du système

La VM a été créée dans VirtualBox avec 4 Go de RAM, 2 vCPUs, 60 Go de disque dynamique et une carte réseau en mode Host-Only. Le firmware UEFI a été sélectionné dans les paramètres système de la VM.

Le choix de l'UEFI dans ce contexte se justifie par plusieurs éléments : tout d'abord il est le remplaçant du BIOS et est présent sur tous les matériel depuis 2012. Il supporte des disques avec une meilleure capacité (supérieurs à 2To) ce qui aujourd'hui est courant sur les serveurs d'entreprise. Enfin, il intègre un point de sécurité indispensable en 2026 : le Secure Boot, qui permet d'examiner l'intégrité de la chaîne de démarrage en vérifiant la signature cryptographique du chargeur de démarrage avant de le charger.

L'ISO Windows Server 2022 a été montée via Périphériques → Lecteurs optiques. L'édition retenue est la **Standard avec expérience de bureau**. Il existe une édition Core, sans interface graphique, qui est recommandée en production.

En production, l'édition Core sans interface graphique est préférable car l'absence de composants tel que l'explorateur de fichiers ou le gestionnaire de tâches par exemple, permet de réduire la surface d'attaque potentielle. De plus, de manière générale l'administration du serveur se fait à distance via un PowerShell, donc sans interface graphique. Ici la version Standard a été préférée à Core car il s'agit d'un lab de découverte, qui permet de comprendre visuellement ce qu'on fait avant de chercher à l'automatiser.

Le type d'installation sélectionné est **Personnalisé** (et non Mise à jour), seul choix valide sur un disque vierge. L'installation a duré environ 15 minutes, suivie d'un redémarrage automatique.

### 2. Configuration IP fixe et renommage du serveur

Une fois connecté, la configuration réseau a été modifiée via Gestionnaire de serveur → Serveur local → clic sur l'adresse IP → Propriétés → TCP/IPv4. Les paramètres suivants ont été appliqués : adresse IP `192.168.56.110`, masque `255.255.255.0`, passerelle laissée vide (réseau isolé). Le point critique est la configuration DNS : l'adresse `127.0.0.1` (loopback) a été renseignée comme serveur DNS préféré.

On met le DC en tant que son propre DNS car lors de son démarrage il va chercher à résoudre `dpro.lab`, et il est le seul capable de le faire. Un DNS extérieur ne connaitra pas ce domaine, et il sera donc inaccessible après la promotion du serveur en DC. On s'assure ainsi que le DC interroge son propre DNS au démarrage, quel que soit l'état du réseau autour de lui.

Avant sa promotion, le serveur a également été renommé `DC01` via Gestionnaire de serveur → Serveur local → clic sur le nom de la machine → Modifier. Le redémarrage a été effectué à la suite de ces modifications.

Au moment de la promotion du serveur en DC, Active Directory enregistre son nom dans la structure du domaine. Si on change le nom après la promotion, il faut aller le mettre à jour manuellement dans toutes les dépendances, c'est une action risquée qui peut entraîner de la casse. Pour plus de sécurité, le nom du DC doit être stable et définitif avant la promotion.

### 3. Installation du rôle AD DS et promotion en contrôleur de domaine

Le rôle **Active Directory Domain Services** a été installé via Gestionnaire de serveur → Gérer → Ajouter des rôles et fonctionnalités → Installation basée sur un rôle → Services AD DS. L'installation du rôle seul ne crée pas encore de domaine : elle installe uniquement les binaires nécessaires. La promotion est l'étape suivante.

Après installation, le lien **"Promouvoir ce serveur en contrôleur de domaine"** est apparu dans le Gestionnaire de serveur. La configuration retenue : nouvelle forêt, domaine racine `dpro.lab`, niveau fonctionnel Windows Server 2016, avec DNS intégré et Catalogue global cochés, RODC (Read Only Domain Controller) décoché.

Le catalogue global est un catalogue qui regroupe des éléments provenant de l'ensemble de la forêt. C'est en quelque sorte un annuaire central : quand un utilisateur se connecte ou fait une recherche dans l'annuaire, Windows interroge le catalogue global pour trouver l'objet sans avoir à interroger chaque domaine de la foret. Sans catalogue global sur le premier DC d'une foret, les ouvertures de session et recherches dans l'annuaire échouent (il n'y a pas d'autre DC pour prendre le relais).

L'avertissement concernant la délégation DNS a été ignoré : il signale simplement qu'il n'existe pas de DNS parent auquel déléguer `dpro.lab`, ce qui est normal dans un lab isolé. Après redémarrage, la validation a été faite en ligne de commande PowerShell :

```cmd
ping dpro.lab
```

Résultat obtenu : réponse de `192.168.56.110`, 0% de perte. Le DNS fonctionne et le domaine est résolvable.

### 4. Assouplissement de la politique de mots de passe (contexte lab)

Via Outils → Gestion des stratégies de groupe → clic droit sur **Default Domain Policy** → Modifier → Configuration ordinateur → Stratégies → Paramètres Windows → Paramètres de sécurité → Stratégies de comptes → Stratégie de mot de passe, la complexité a été désactivée et la longueur minimale réduite à 4 caractères. Cela permet d'éviter de créer des mots de passe trop complexe lors de la création de nouveaux comptes : il s'agit d'un exercice en environnement isolé donc les mots de passe sont peu pertinents, et cela permet de voir également comment modifier une telle politique. La commande `gpupdate /force` a été exécutée via un PowerShell pour appliquer immédiatement les changements.

Cette configuration n'est valable qu'en lab. En production, une politique de mots de passe renforcée s'applique (voir section Recommandations).

### 5. Création des Unités d'Organisation

Quatre OUs ont été créées via Outils → Utilisateurs et ordinateurs Active Directory → clic droit sur `dpro.lab` → Nouveau → Unité d'organisation : **Direction**, **RH**, **Informatique**, **Postes**.

Dans Active Directory, un conteneur est un objet qui sert à regrouper d'autres objets (utilisateurs, machines, groupes...). Cependant un conteneur par défaut ne permet pas d'appliquer de politique de GPO (Group Policy Object). Pour cela il faut utiliser un autre type de conteneur : les OUs. Grâce aux OUs il est alors possible d'appliquer des politiques différentes selon les départements.

L'option "Protéger le conteneur contre une suppression accidentelle" a été laissée cochée sur toutes les OUs. En production, supprimer accidentellement une OU contenant des centaines de comptes peut avoir des conséquences désastreuses. Cette protection force une étape de confirmation explicite avant toute suppression.

### 6. Création des comptes utilisateurs et des groupes de sécurité

Trois comptes utilisateurs ont été créés via clic droit sur l'OU cible → Nouveau → Utilisateur, chacun placé dans l'OU correspondant à son département :

| Compte | OU |
|---|---|
| j.dupont | Direction |
| m.martin | RH |
| t.bernard | Informatique |

La convention de nommage `prenom.nom` est un standard courant en entreprise : elle est lisible, non ambiguë, et facilite l'audit des logs : un event ID 4624 avec `j.dupont` est immédiatement interprétable sans table de correspondance.

Trois groupes de sécurité ont ensuite été créés via clic droit sur l'OU cible → Nouveau → Groupe, avec l'étendue **Global** (membres du même domaine mais le groupe peut être utilisé dans toute la forêt) et le type **Sécurité** (permet de gérer les permissions) : `GRP_Direction`, `GRP_RH`, `GRP_Informatique`. Les utilisateurs ont été ajoutés à leurs groupes respectifs via clic droit sur le groupe → Propriétés → Membres → Ajouter.

Cette approche suit le principe RBAC (Role-Based Access Control) : les droits d'accès aux ressources sont attribués aux groupes, pas aux individus. Quand un collaborateur quitte l'entreprise ou change de poste, il suffit de modifier son appartenance aux groupes et les droits suivent automatiquement.

### 7. Création et liaison des GPO

Deux GPO ont été créées via Outils → Gestion des stratégies de groupe → clic droit sur l'OU cible → Créer un objet GPO dans ce domaine et le lier ici.

**GPO_Ecran_Verrouillage** liée à l'OU Informatique, configurée via clic droit → Modifier → Configuration utilisateur → Stratégies → Modèles d'administration → Panneau de configuration → Personnalisation. Les paramètres appliqués sont : économiseur d'écran activé, délai 600 secondes (10 min), protection par mot de passe activée.

Pour cette politique, nous souhaitons que l'utilisateur ait son écran verrouillé après 10 minutes, quel que soit le poste sur lequel il travaille. C'est pour cela qu'on choisit la configuration utilisateur, qui permet de suivre l'utilisateur, plutôt qu'à la configuration ordinateur qui elle permet de cibler la machine quel que soit l'utilisateur connecté.

**GPO_Restriction_PanneauConfig** liée à l'OU RH, configurée via Configuration utilisateur → Stratégies → Modèles d'administration → Panneau de configuration → "Interdire l'accès au Panneau de configuration et à l'application Paramètres" → Activé. L'objectif est d'empêcher des utilisateurs non techniques de modifier la configuration système, de désactiver un antivirus, ou de changer les paramètres réseau.

### 8. Activation de l'audit

L'audit a été activé sur la **Default Domain Policy** via clic droit → Modifier → Configuration ordinateur → Stratégies → Paramètres Windows → Paramètres de sécurité → Stratégies locales → Stratégie d'audit. Trois catégories ont été activées en succès et en échec :

| Catégorie | Event IDs couverts |
|---|---|
| Événements de connexion aux comptes | 4624 (connexion réussie), 4625 (échec) |
| Gestion des comptes | 4720 (création), 4726 (suppression) |
| Événements de connexion | Connexions locales et RDP |
On active l'audit dès le déploiement pour établir une baseline des comportements normaux sur le domaine. De plus, si un incident de sécurité devait se produire, les logs permettront à l'investigateur de retracer le parcours de l'attaquant. Activer l'audit après un incident, c'est trop tard : les traces des actions antérieures sont perdues définitivement.

### 9. Délégation de droits

Via Utilisateurs et ordinateurs Active Directory → clic droit sur l'OU **RH** → Déléguer le contrôle, le compte `t.bernard` a reçu la permission de réinitialiser les mots de passe des utilisateurs de cette OU uniquement.

Le compte de `t.bernard` n'est pas un compte administrateur : il n'a pas à avoir tous les droits sur le domaine. A la place on préfère lui déléguer les droits nécessaires à l'exécution de sa fonction, appliquant ainsi le principe du moindre privilège. Un compte Domain Admins compromis donne un accès total à l'ensemble du domaine : c'est le scénario catastrophe que tout administrateur cherche à éviter

### 10. Installation et configuration du rôle DHCP

Le rôle DHCP a été installé via Gestionnaire de serveur → Gérer → Ajouter des rôles et fonctionnalités → Serveur DHCP. Après installation, l'étape "Terminer la configuration DHCP" a autorisé le serveur dans le domaine AD avec les credentials `DPRO\Administrateur`.

Cette autorisation dans AD n'est pas une formalité : elle empêche un serveur DHCP non autorisé (serveur fantôme ou rogue DHCP) de distribuer des adresses IP incorrectes ou des configurations DNS malveillantes sur le réseau.

L'étendue `LAN_dpro` a été créée via Outils → DHCP → IPv4 → Nouvelle étendue, avec les paramètres suivants :

| Paramètre | Valeur |
|---|---|
| Plage d'adresses | 192.168.56.150 → 192.168.56.200 |
| Durée du bail | 8 jours |
| Serveur DNS transmis aux clients | 192.168.56.110 |
| Suffixe de domaine | dpro.lab |

Ainsi, tout poste qui rejoint le réseau obtient automatiquement une adresse IP et l'adresse du serveur DNS du domaine, sans aucune configuration manuelle.

---

## Résultats

| Élément | État |
|---|---|
| Contrôleur de domaine DC01 | Opérationnel |
| Résolution DNS `dpro.lab` | Validée (`ping dpro.lab` → 192.168.56.110, 0% perte) |
| Structure OU (Direction / RH / Informatique / Postes) | Créée |
| Comptes utilisateurs (j.dupont, m.martin, t.bernard) | Créés dans leurs OUs respectives |
| Groupes de sécurité (GRP_Direction, GRP_RH, GRP_Informatique) | Créés, membres ajoutés |
| GPO_Ecran_Verrouillage (OU Informatique) | Active, verrouillage 10 min |
| GPO_Restriction_PanneauConfig (OU RH) | Active, accès Panneau de config bloqué |
| Audit de sécurité (Default Domain Policy) | Activé — succès et échecs |
| Délégation reset mdp : `t.bernard` sur OU RH | Configurée |
| Rôle DHCP | Installé, autorisé, étendue LAN_dpro active |

---

## Analyse

> **[Quelle étape t'a semblé la plus critique dans ce déploiement — celle où une erreur aurait cassé tout le reste ? Et qu'est-ce que tu ferais différemment dans un contexte professionnel réel par rapport à ce lab ?]**
> *Votre réponse ici (5-8 phrases)*

---

## Recommandations de sécurité

*Ce lab est un déploiement de base dans un contexte de découverte. En environnement de production, les mesures suivantes s'appliqueraient :*

> **[4 à 6 recommandations avec une justification courte chacune. Thèmes suggérés : séparation compte admin / compte utilisateur quotidien — désactivation du compte Administrateur intégré — politique de mots de passe renforcée — LAPS pour les comptes locaux — audit avancé par sous-catégories — sauvegarde System State du DC.]**
> *Vos recommandations ici*

---

## Conclusion

Ce lab couvre le déploiement minimal d'un Active Directory dans un contexte PME : structure OU, comptes, groupes, GPO, audit et délégation. C'est la fondation sur laquelle repose toute l'administration Windows en entreprise — et la base sur laquelle le lab de la semaine 14 ajoutera une couche d'automatisation PowerShell, une politique de mots de passe renforcée selon les recommandations ANSSI, et une jonction de poste Windows au domaine.

---

*Write-up rédigé dans le cadre d'un parcours de reconversion en cybersécurité — portfolio complet sur [github.com/DimitriProCyber](https://github.com/DimitriProCyber)*
