# Active Directory niveau 2 : déploiement d'un environnement PME (50 utilisateurs, 4 départements)

**14 juin 2026**

**Environnement :** Home lab VirtualBox — domaine `dpro.lab`, DC01 (Windows Server 2022) et PC01 (Windows 11 Professionnel).  
**Objectif :** Déployer en autonomie un environnement Active Directory représentatif d'une PME de 50 utilisateurs répartis sur 4 départements, conforme aux recommandations ANSSI (politique de mot de passe, audit, délégation de droits), puis intégrer un poste client au domaine selon deux méthodes.  
**Difficulté :** N2 - Autonomie sur les concepts vus précédemment et guidé sur les nouveaux.


## Contexte

Ce lab fait suite au déploiement Active Directory de niveau 1 réalisé la semaine précédente, où un domaine `dpro.lab` avait été créé avec une structure de base et un nombre limité d'utilisateurs.

L'objectif de ce second lab est de reproduire un scénario réaliste d'administration système pour une PME structurée en plusieurs départements. Concrètement, il s'agit de répondre aux questions suivantes qu'un administrateur réseau se pose régulièrement dans une entreprise de cette taille : comment créer rapidement un grand nombre de comptes utilisateurs sans erreur, comment organiser ces comptes par service, comment déléguer une partie de l'administration courante à une équipe support sans lui donner les pleins pouvoirs, comment imposer une politique de sécurité homogène à toute l'entreprise, comment identifier les comptes qui ne sont plus utilisés, et enfin comment intégrer un poste de travail au domaine.

Pour ce lab nous avons choisi un scénario d'une PME de 50 salariés, répartis dans 4 départements différents. Le rôle simulé est celui d'un administrateur système devant enrichir la base Active Directory déjà en place, à travers la création des comptes et groupes manquants, l'implémentation de politiques de groupe et de sécurité, ainsi que l'intégration d'un poste utilisateur au domaine.


## Environnement technique

L'ensemble du lab repose sur deux machines virtuelles sous VirtualBox, reliées sur un réseau privé de type Host-Only (plage 192.168.56.0/24) :

DC01 : Windows Server 2022, contrôleur de domaine du domaine `dpro.lab`, adresse IP 192.168.56.110
PC01 : Windows 11 Professionnel, poste de travail client, adresse IP 192.168.56.120

DC01 héberge une structure Active Directory déjà initialisée lors du lab N1 : OUs Direction, RH, Informatique et Postes, ainsi que trois comptes utilisateurs (j.dupont, m.martin, t.bernard) et leurs groupes de sécurité associés. Ce lab N2 vient enrichir cette base existante sans la remplacer, en ajoutant les OUs Commerce et Production, 50 nouveaux comptes utilisateurs, leurs groupes correspondants, et en intégrant PC01 au domaine.


## Méthodologie

Le lab est découpé en sept blocs, exécutés dans l'ordre. Chaque bloc correspond à une tâche d'administration courante.

### Bloc 1 — Création de deux nouvelles unités organisationnelles (OU)

**Ce qui a été fait :**

Deux nouvelles OU ont été créées dans Active Directory, nommées Commerce et Production, en complément des OU existantes (Direction, RH, Informatique, Postes).

**Chemin d'accès :**

Outils du Gestionnaire de serveur, Utilisateurs et ordinateurs Active Directory, clic droit sur dpro.lab, Nouveau, Unité d'organisation.

**Pourquoi cette étape ?**

Une OU (Organizational Unit) est un conteneur, c'est-à-dire un objet qui sert à regrouper d'autres objets, sur lequel on peut appliquer des GPO (Group Policy Object) et déléguer des droits d'administration. La création d'une OU par département permet de définir des règles précises qui s'appliquent à tous les salariés de ce département et s'adaptent à leurs besoins métier, ainsi que de confier une partie de l'administration courante à une équipe support sans lui donner les pleins pouvoirs sur l'ensemble du domaine, conformément au principe du moindre privilège.


### Bloc 2 — Création de 50 comptes utilisateurs via PowerShell

**Ce qui a été fait :**

Un script PowerShell (`create_users.ps1`) a permis de créer 50 comptes utilisateurs répartis sur quatre départements : Commerce (15 comptes), Production (20 comptes), Informatique (10 comptes) et Direction (5 comptes).  
Chaque compte suit une convention de nommage par préfixe de département (par exemple `p.martin` pour Commerce, `prod.leroy` pour Production). Un mot de passe initial commun a été défini, avec l'obligation pour chaque utilisateur de le changer à sa première connexion.

**Script utilisé :**

```powershell
$password = ConvertTo-SecureString "Azerty123!" -AsPlainText -Force

$users = @(
    @{Sam="p.martin"; OU="Commerce"},
    @{Sam="prod.leroy"; OU="Production"}
    # ... (50 entrées au total)
)

foreach ($u in $users) {
    New-ADUser -SamAccountName $u.Sam `
               -Name $u.Sam `
               -UserPrincipalName "$($u.Sam)@dpro.lab" `
               -Path "OU=$($u.OU),DC=dpro,DC=lab" `
               -AccountPassword $password `
               -ChangePasswordAtLogon $true `
               -Enabled $true
}
```

**Explication de la commande :**

- `ConvertTo-SecureString` transforme un mot de passe en texte brut en objet SecureString, c'est-à-dire un mot de passe chiffré en mémoire. C'est le format attendu par le paramètre `-AccountPassword` de `New-ADUser`, qui n'accepte jamais de mot de passe en clair.
- `$users` est un tableau d'objets, où chaque élément regroupe le SamAccountName et l'OU de destination d'un utilisateur. C'est la structure de données qui permet de décrire les 50 comptes à créer.
- La boucle `foreach ($u in $users)` parcourt ce tableau élément par élément. À chaque itération, `$u` représente l'utilisateur courant, et `$u.Sam` / `$u.OU` donnent accès à ses propriétés.
- `New-ADUser` est le cmdlet qui crée l'objet utilisateur dans Active Directory. `-SamAccountName` définit l'identifiant unique du compte dans l'annuaire.
- `-UserPrincipalName "$($u.Sam)@dpro.lab"` définit l'identifiant sous forme d'adresse. La syntaxe `$()` est nécessaire pour accéder à une propriété d'objet à l'intérieur d'une chaîne de caractères.
- `-Path "OU=$($u.OU),DC=dpro,DC=lab"` indique l'OU de destination, en notation LDAP, où chaque composant du nom de domaine est précédé de `DC=`.
- `-AccountPassword $password` applique le mot de passe initial préparé en SecureString.
- `-ChangePasswordAtLogon $true` force l'utilisateur à définir lui-même son mot de passe dès sa première connexion.
- `-Enabled $true` active le compte immédiatement après sa création.

**Pourquoi PowerShell plutôt que l'interface graphique ?**

Créer 50 comptes un par un dans l'interface graphique serait long, source d'erreurs de saisie, et impossible à documenter ou à reproduire à l'identique. Un script PowerShell s'exécute en quelques secondes, peut être relu, corrigé et réutilisé pour un autre département ou une autre entreprise. C'est une compétence systématiquement attendue pour un poste d'administrateur systèmes, où la gestion de masse des comptes (arrivées, départs, changements de service) est une tâche récurrente.

**Pourquoi forcer le changement de mot de passe à la première connexion**

Demander un changement de mot de passe à la première connexion permet de faire en sorte que personne, l'administrateur compris, ne connaisse le mot de passe final de l'utilisateur. Ainsi, en plus de protéger le compte, cela garantit qu'en cas d'action indésirable effectuée depuis ce compte, l'utilisateur ne peut pas nier en être l'auteur, ce qui correspond au principe de non-répudiation


### Bloc 3 — Création des groupes de sécurité par département

**Ce qui a été fait :**

Quatre groupes de sécurité de type Global ont été créés, un par département (GRP_Commerce, GRP_Production, GRP_Informatique_N2, GRP_Direction_N2), chacun placé dans l'OU correspondante. Les utilisateurs de chaque département ont été ajoutés au groupe correspondant.

**Cmdlets utilisés :**

```powershell
New-ADGroup -Name "GRP_Commerce" -GroupScope Global -GroupCategory Security `
            -Path "OU=Commerce,DC=dpro,DC=lab"

Add-ADGroupMember -Identity "GRP_Commerce" -Members "p.martin","p.bernard" #etc...
```

**Explication de la commande :**

- `New-ADGroup` crée un objet groupe dans Active Directory.
- `-Name "GRP_Commerce"` définit le nom du groupe dans l'annuaire.
- `-GroupScope Global` signifie que ce groupe peut contenir des membres provenant de n'importe où dans le domaine, et peut être utilisé pour attribuer des droits sur n'importe quelle ressource du domaine. C'est l'étendue classique pour un regroupement par service.
- `-GroupCategory Security` indique qu'il s'agit d'un groupe de sécurité, c'est-à-dire un groupe auquel on peut attribuer des permissions, par opposition à un groupe de distribution qui ne servirait qu'à de la messagerie.
- `-Path "OU=Commerce,DC=dpro,DC=lab"` place le groupe dans l'OU correspondante, en notation LDAP.
- `Add-ADGroupMember -Identity "GRP_Commerce" -Members "p.martin","p.bernard"` ajoute des membres existants au groupe. `-Identity` cible le groupe, `-Members` liste les comptes à ajouter, identifiés par leur SamAccountName, séparés par des virgules.

**Pourquoi utiliser le SamAccountName pour identifier les membres ?**

Le SamAccountName est l'identifiant unique d'un compte dans l'annuaire. Contrairement au nom complet d'une personne, qui peut être partagé par plusieurs employés, le SamAccountName garantit qu'il n'y a aucune ambiguïté sur le compte visé.

**Pourquoi placer les groupes dans les OU métier ?**

La différence fondamentale entre les OU et les groupes, c'est que sur le premier objet seront appliqués des GPO et seront possibles des délégations de droits, alors que le second servira à gérer les permissions sur les ressources. Les deux sont donc des entités distinctes avec des fonctions bien précises. Placer un groupe dans une OU n'a pas d'impact direct sur son fonctionnement, il pourrait être placé n'importe où ailleurs. Cependant, lorsqu'un groupe est associé au même département que l'OU, on préfère le placer dedans pour des questions de visibilité : quand l'administrateur ouvre l'OU, il voit tout ce qui concerne ce département au même endroit.

**Pourquoi le suffixe _N2 sur deux des groupes ?**

Les groupes GRP_Direction et GRP_Informatique existaient déjà depuis le lab N1. Pour éviter un conflit de nommage dans cet environnement de lab, un suffixe _N2 a été ajouté. Dans une entreprise réelle où ces groupes seraient créés une seule fois, ce problème ne se poserait pas.


### Bloc 4 — Délégation de droits à un compte helpdesk

**Ce qui a été fait :**

Un compte `helpdesk` a été créé dans l'OU Informatique. Ce compte a ensuite reçu, via l'assistant de délégation de contrôle, le droit de réinitialiser les mots de passe et de gérer le déverrouillage des comptes pour les OU Commerce, Production et Direction, mais pas pour l'OU Informatique.

**Chemin d'accès :**

Utilisateurs et ordinateurs Active Directory, activer l'affichage des fonctionnalités avancées si nécessaire (menu Affichage), clic droit sur l'OU cible, Déléguer le contrôle. Dans l'assistant : ajouter le compte helpdesk, choisir de créer une tâche personnalisée à déléguer, restreindre aux objets de type Utilisateur, puis cocher dans les permissions générales et spécifiques aux propriétés les droits suivants : réinitialiser le mot de passe, lire l'attribut lockoutTime, écrire l'attribut lockoutTime.

**Vérification :**

La délégation appliquée a été vérifiée via le chemin : clic droit sur l'OU, Propriétés, onglet Sécurité, bouton Avancé. Trois entrées d'autorisation pour le compte helpdesk sont visibles, avec une portée d'application sur les objets utilisateur descendants de l'OU.

**Pourquoi deux droits distincts pour lockoutTime ?**

L'attribut lockoutTime indique si un compte est actuellement verrouillé après plusieurs échecs d'authentification. Le droit de lecture permet au helpdesk de constater qu'un compte est verrouillé. Le droit d'écriture lui permet de remettre cet attribut à zéro, ce qui déverrouille le compte. Les deux droits sont nécessaires : l'un sans l'autre ne permettrait pas de traiter la demande la plus fréquente d'un service support, à savoir un utilisateur bloqué après plusieurs tentatives de mot de passe erronées.

**Pourquoi exclure l'OU Informatique de cette délégation ?**

En cas de compromission du compte `helpdesk`, l'attaquant est capable de prendre le contrôle de n'importe quel compte sur lequel ce compte a des droits. Si l'OU Informatique avait été incluse dans cette délégation, et puisque ses membres disposent de droits potentiellement plus élevés (administration du domaine par exemple), la compromission d'un simple compte support pourrait alors se transformer rapidement en compromission de l'ensemble du système d'information. C'est une application directe du principe du moindre privilège : le compte `helpdesk` ne dispose que des droits strictement nécessaires à sa mission.


### Bloc 5 — Mise en place de trois GPO

**Ce qui a été fait :**

Trois objets de stratégie de groupe (GPO) ont été créés et liés à différents niveaux de l'annuaire.

**Chemin d'accès à la console de gestion des GPO :**

Gestionnaire de serveur, Outils, Gestion des stratégies de groupe.

#### GPO_MotDePasse_ANSSI (liée au domaine dpro.lab) :

**Chemin dans l'éditeur de GPO :**

Configuration ordinateur, Stratégies, Paramètres Windows, Paramètres de sécurité, Stratégies de comptes, Stratégie de mot de passe (et Stratégie de verrouillage du compte pour le second groupe de paramètres).

**Paramètres appliqués :**

Longueur minimale du mot de passe fixée à 12 caractères, complexité activée, historique de 10 mots de passe mémorisés, durée de vie maximale du mot de passe fixée à 0 (illimitée), durée de vie minimale à 0 jour. Côté verrouillage, seuil fixé à 5 tentatives, durée de verrouillage de 30 minutes, et réinitialisation du compteur après 30 minutes.

**Pourquoi une durée de vie maximale de mot de passe fixée à 0 ?**

Actuellement l'ANSSI ne recommande plus de forcer l'expiration des mots de passe. Cela peut sembler contre-intuitif à première vue, mais l'explication est la suivante : à force de changer de mot de passe, les utilisateurs étaient poussés à choisir des combinaisons prévisibles, par exemple en incrémentant un chiffre à la fin. L'ANSSI estime qu'imposer un mot de passe unique mais suffisamment robuste, sans expiration forcée, constitue une politique plus sûre.

**Pourquoi cette GPO est liée au domaine et non à une OU ?**

Une stratégie de mot de passe Active Directory ne peut s'appliquer qu'au niveau du domaine. Une GPO de ce type liée à une OU serait tout simplement ignorée par le système, ce qui constitue une limitation propre à Active Directory et non un choix de configuration.

#### GPO_Audit_Complet (liée au domaine dpro.lab) :

**Chemin dans l'éditeur de GPO :**

Configuration ordinateur, Stratégies, Paramètres Windows, Paramètres de sécurité, Configuration avancée de la stratégie d'audit, Stratégies d'audit.

**Ce qui a été fait :**

L'ensemble des sous-catégories d'audit pertinentes ont été activées en mode Succès et Échec, couvrant la connexion de compte, la gestion des comptes, l'ouverture et la fermeture de session, l'accès au service d'annuaire et le suivi détaillé des processus.

**Pourquoi auditer aussi bien les succès que les échecs ?**

Dans l'inconscient collectif, un succès est synonyme de comportement normal alors qu'une suite d'échecs est considérée comme suspecte. Pourtant un succès n'est pas forcément anodin : une connexion réussie à 3h du matin sur un compte qui ne travaille jamais de nuit peut être le signe d'une intrusion suite à un mot de passe compromis, sans qu'aucun échec n'ait été nécessaire au préalable. À l'inverse, une suite d'échecs peut simplement correspondre à un utilisateur ayant oublié son mot de passe. C'est donc la corrélation entre succès et échecs qui permet de détecter une anomalie, d'où l'importance de conserver une trace des deux.

#### GPO_Restrictions_Utilisateurs (liée aux OU Commerce et Production) :

**Chemin dans l'éditeur de GPO pour le Panneau de configuration :**

Configuration utilisateur, Stratégies, Modèles d'administration, Panneau de configuration, Affichage. Paramètres activés : désactiver le Panneau de configuration et masquer l'onglet Paramètres.

**Chemin dans l'éditeur de GPO pour la restriction de cmd.exe et PowerShell :**

Configuration utilisateur, Stratégies, Paramètres Windows, Paramètres de sécurité, Stratégies de restriction logicielle. Une nouvelle stratégie de restriction logicielle a été créée, puis trois règles de chemin d'accès ont été ajoutées avec un niveau de sécurité Non autorisé, visant les exécutables suivants : `C:\Windows\System32\cmd.exe`, `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` et `C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe`.

**Pourquoi cibler spécifiquement Commerce et Production ?**

Dans le cadre de leurs activités, les départements Commerce et Production n'ont pas besoin d'avoir accès à un interpréteur de commandes. Verrouiller cet accès permet de réduire la surface d'attaque en cas de compromission, par exemple avec un malware qui chercherait à exécuter un script. Les équipes Informatique et Direction conservent cet accès : pour l'Informatique car il s'agit d'un outil de travail quotidien, et pour la Direction car certains outils de gestion peuvent reposer sur des scripts ou macros invoquant un interpréteur de commandes en arrière-plan.

**Pourquoi bloquer également la version SysWOW64 de PowerShell ?**

Windows 64 bits embarque deux versions de PowerShell : la version 64 bits dans System32 et la version 32 bits dans SysWOW64, conservée pour la compatibilité avec d'anciens scripts ou logiciels. Ne bloquer que la version 64 bits laisserait un moyen trivial de contourner la restriction en lançant simplement l'autre version.


### Bloc 6 — Export des comptes inactifs

**Ce qui a été fait :**

Un script PowerShell a permis d'identifier tous les comptes utilisateurs n'ayant jamais ouvert de session ou inactifs depuis plus de 30 jours, puis d'exporter le résultat dans un fichier CSV contenant l'identifiant du compte, sa date de dernière connexion et son emplacement dans l'annuaire.

**Script :**

```powershell
$seuil = (Get-Date).AddDays(-30)

Search-ADAccount -AccountInactive -DateTime $seuil -UsersOnly |
    Get-ADUser -Properties DisplayName, LastLogonDate, Enabled, DistinguishedName |
    Select-Object SamAccountName, LastLogonDate, DistinguishedName |
    Export-Csv -Path "C:\Users\Administrateur\Documents\comptes_inactifs.csv" `
               -NoTypeInformation -Encoding UTF8
```

**Explication des éléments clés :**

- `Search-ADAccount` est un cmdlet spécialisé dans l'interrogation de l'état des comptes Active Directory (inactifs, verrouillés, expirés).
- `-AccountInactive` combiné à `-DateTime $seuil` filtre les comptes n'ayant pas eu d'activité depuis avant cette date.
- Le filtre s'appuie sur l'attribut `lastLogonDate`, qui est répliqué entre les contrôleurs de domaine et donc fiable, contrairement à `lastLogon` qui ne l'est pas.
- `-UsersOnly` exclut les comptes ordinateurs, qui existent aussi dans AD pour chaque machine jointe au domaine et n'ont pas leur place dans un rapport sur les comptes utilisateurs.
- Le résultat est transmis via `|` à `Get-ADUser`, qui récupère les propriétés détaillées non incluses dans le résultat initial.
- `Select-Object` sélectionne les colonnes utiles pour le rapport : SamAccountName, LastLogonDate, DistinguishedName.
- `Export-Csv` écrit le résultat dans un fichier. `-NoTypeInformation` évite une ligne de métadonnées PowerShell illisible par un tableur, et `-Encoding UTF8` garantit l'affichage correct des caractères accentués.

**Résultat obtenu :**

L'export a retourné les 50 comptes créés au Bloc 2, ainsi que les comptes Invité et krbtgt, désactivés par défaut sur tout domaine Active Directory. Aucun des 50 comptes n'a jamais ouvert de session depuis sa création, ce qui est cohérent avec un environnement de lab où les comptes sont créés mais pas encore utilisés. Dans un environnement de production, ce même rapport permettrait d'identifier en un coup d'œil les comptes réellement inactifs depuis 30 jours, qu'il s'agisse de départs non traités ou de comptes de service oubliés, et de cibler une revue d'accès sur ces comptes.

**Pourquoi cette tâche est pertinente dans une entreprise réelle ?**

Un compte inactif depuis longtemps représente un risque de sécurité. Sans utilisateur actif derrière lui, un tel compte peut être compromis et utilisé discrètement, sans qu'aucune activité anormale ne soit remarquée puisque personne ne s'attend à le voir utilisé. C'est typiquement le cas d'un compte de stagiaire dont la mission s'est terminée plusieurs mois auparavant sans que le compte n'ait été désactivé : un attaquant disposant de ses identifiants pourrait s'en servir comme point d'entrée discret dans le système d'information.


### Bloc 7 — Intégration d'un poste de travail au domaine

**Ce qui a été fait :**

Le poste PC01, sous Windows 11 Professionnel, initialement en groupe de travail (WORKGROUP), a été intégré au domaine `dpro.lab`. Cette intégration a été réalisée selon deux méthodes différentes, afin de comparer une approche graphique et une approche en ligne de commande.

#### Méthode 1 : intégration via l'interface graphique

**Chemin d'accès :**

Paramètres, Système, Informations système, section Liens connexes, Domaine ou groupe de travail, bouton Modifier, sélection de l'option Domaine et saisie de `dpro.lab`.

**Déroulement :**

Une fenêtre d'authentification s'est présentée, demandant les identifiants d'un compte autorisé à joindre une machine au domaine. Le compte Administrateur du domaine a été utilisé, sous la forme `administrateur@dpro.lab`. Après validation, le message de confirmation Bienvenue dans le domaine dpro.lab est apparu, suivi d'une demande de redémarrage.

**Vérification :**

Après redémarrage, une ouverture de session avec le compte de domaine `t.bernard` a été testée et a fonctionné, confirmant que PC01 authentifie désormais ses utilisateurs auprès du contrôleur de domaine DC01.

#### Méthode 2 : intégration via PowerShell, après retrait préalable du domaine

PC01 a d'abord été retiré du domaine et remis en groupe de travail, via le même chemin d'accès que précédemment, en se reconnectant avec le compte local `localadmin`. Le poste a ensuite été rejoint au domaine via la commande suivante, exécutée dans PowerShell en tant qu'administrateur :

```powershell
Add-Computer -DomainName "dpro.lab" -Credential administrateur@dpro.lab -Restart
```

**Explication de la commande :**

- `Add-Computer` est le cmdlet PowerShell équivalent à l'opération réalisée en interface graphique : il joint la machine locale à un domaine Active Directory.
- `-DomainName "dpro.lab"` précise le domaine cible à rejoindre.
- `-Credential` demande la saisie interactive des identifiants d'un compte autorisé à joindre une machine au domaine.
- `-Restart` déclenche automatiquement le redémarrage nécessaire à l'application des changements.

**Pourquoi utiliser un compte local pour retirer la machine du domaine ?**

Si l'on utilise un compte de domaine pour retirer PC01 du domaine, le compte qui authentifie la session en cours devient invalide pour la machine au moment même où l'opération s'exécute, puisque PC01 n'appartient plus au domaine. Cela bloquerait l'utilisateur en pleine opération. Un compte local n'est pas dépendant du domaine : il continue de fonctionner quelle que soit l'appartenance de la machine, ce qui élimine ce risque.

**Pourquoi le format `utilisateur@domaine` ou `DOMAINE\utilisateur` est nécessaire ici, alors qu'au quotidien sur un poste déjà joint un simple identifiant suffit ?**

Pour son utilisation quotidienne, un utilisateur se connecte à une machine déjà jointe au domaine. La machine sachant déjà à quel domaine elle appartient, le domaine d'authentification est implicite : elle sait où chercher pour trouver le compte correspondant à l'identifiant saisi. Lors d'une opération d'intégration, la machine n'a pas encore cette information : il faut donc lui préciser explicitement dans quel domaine et avec quel compte effectuer l'opération, d'où le format complet `utilisateur@domaine`.

**Vérification finale :**

Après la seconde intégration, une ouverture de session avec `t.bernard` a de nouveau été testée avec succès. Une vérification complémentaire a été effectuée côté DC01 :

```powershell
Get-ADComputer -Filter * | Select-Object Name, DistinguishedName
```

**Explication de la commande :**

- `Get-ADComputer` est l'équivalent de `Get-ADUser` mais pour les objets de type ordinateur dans Active Directory.
- `-Filter *` est obligatoire pour ce cmdlet : l'astérisque signifie l'absence de critère de filtrage, c'est-à-dire que tous les objets ordinateurs doivent être retournés.
- `Select-Object Name, DistinguishedName` sélectionne uniquement le nom de l'objet et son emplacement complet dans l'annuaire.

**Résultat :**

Un seul objet PC01 a été retrouvé dans Active Directory, situé dans `CN=PC01,CN=Computers,DC=dpro,DC=lab`, ce qui confirme que le retrait du domaine effectué entre les deux méthodes a correctement nettoyé l'objet ordinateur précédent côté annuaire, sans laisser de doublon. Pour comparaison, le contrôleur de domaine DC01 lui-même apparaît également comme objet ordinateur, mais situé dans l'unité organisationnelle protégée Domain Controllers.

**Analyse comparative des deux méthodes :**

Les deux méthodes apportent chacune leurs avantages. La méthode via interface graphique est plus visuelle et adaptée à un dépannage ponctuel. Elle demande aussi moins de compétences techniques et sera plus accessible à un profil junior. La méthode PowerShell demande davantage de connaissances, mais permet en contrepartie d'être plus rapide une fois la commande maîtrisée. Elle est aussi plus adaptée à des déploiements de masse sur plusieurs postes, car elle est scriptable et donc reproductible. Les deux méthodes ont produit ici un résultat identique côté Active Directory, ce qui confirme leur équivalence fonctionnelle.


## Résultats

À l'issue de ce lab, le domaine `dpro.lab` compte 6 unités organisationnelles (Direction, RH, Informatique, Postes, Commerce, Production), 50 nouveaux comptes utilisateurs répartis sur 4 départements, 4 groupes de sécurité associés, ainsi qu'un compte helpdesk disposant d'une délégation de droits sur 3 OU. Trois GPO sont actives : une politique de mot de passe et de verrouillage conforme aux recommandations ANSSI au niveau du domaine, une politique d'audit complet au niveau du domaine, et une restriction d'accès au panneau de configuration et aux interpréteurs de commandes sur les OU Commerce et Production. Le poste PC01 a été intégré au domaine selon deux méthodes (interface graphique et PowerShell), avec un résultat identique côté annuaire : un seul objet ordinateur PC01, sans doublon.


## Recommandations

La GPO_Restrictions_Utilisateurs bloque `powershell.exe` mais pas `powershell_ise.exe` (PowerShell ISE), qui est un exécutable distinct situé dans les mêmes répertoires. Un utilisateur des départements Commerce ou Production pourrait donc contourner la restriction en lançant PowerShell ISE. Une règle de chemin supplémentaire ciblant `powershell_ise.exe` devrait être ajoutée pour fermer cette voie de contournement. L'application de la GPO_Restrictions_Utilisateurs à la Direction pourrait également être réévaluée selon les outils de gestion réellement utilisés par ce département.

Les objets ordinateurs comme PC01 se trouvent dans le conteneur par défaut "Computers", qui ne permet pas l'application de GPO ; un déplacement vers une OU dédiée aux postes clients permettrait d'appliquer des règles spécifiques à ces machines. Enfin, le rapport des comptes inactifs produit au Bloc 6 devrait faire l'objet d'une revue périodique, avec une procédure de désactivation après une durée définie, afin de limiter le risque lié aux comptes orphelins.


## Compétences mobilisées

Ce lab a mobilisé l'administration Active Directory à travers la création d'unités organisationnelles, de comptes utilisateurs et de groupes de sécurité, ainsi que le scripting PowerShell pour l'automatisation de tâches d'administration en masse via boucles et tableaux d'objets. Il a également porté sur la gestion des stratégies de groupe pour la sécurité des mots de passe conforme aux recommandations ANSSI, l'audit des événements et la restriction d'usage pour certains profils utilisateurs, sur la délégation de droits selon le principe du moindre privilège, ainsi que sur l'intégration d'un poste de travail au domaine via deux méthodes complémentaires, interface graphique et ligne de commande.

---

*Write-up rédigé dans le cadre d'un parcours de reconversion en cybersécurité*
