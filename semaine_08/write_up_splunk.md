**Lab Splunk**

**23 Avril 2026**

**Objectif :** Analyse de logs Windows et construction de baseline SOC

 
 **Environnement :**

- PC Windows personnel
- SIEM : Splunk Entreprise (version gratuite)
- Accès au SIEM : http://localhost:8000
- Source de logs : Journal de sécurité Windows (source locale)
- Volume : 500 événements


**Contexte :**


*Situation professionnelle simulée :* 

Un analyste SOC N1 eçoit une alerte : activité inhabituelle suspectée sur un poste Windows en environnement PME. Sa première mission est de collecter les logs de sécurité, les intégrer dans le SIEM, puis établir une baseline comportementale avant de pouvoir identifier toute anomalie.

Ce lab simule cette séquence : de l'export brut des logs jusqu'à l'interprétation SOC d'un jeu de données réel.


*Pourquoi ce lab?*
Un SIEM (Security Information and Event Management) est l'outil central d'un SOC. Savoir l'alimenter, effectuer des requêtes et interpréter ses résultats est une compétence exigée dès le niveau 1. Ce lab permet de découvrir les trois compétences fondamentales :

- *Ingestion :* comment introduire des logs dans Splunk.
- *Requêtes SPL :* Comment interroger ces logs avec le Search Processing Language.
- *Analyse SOC :* Comment interpréter les résultats pour distinguer comportement normal et anomalie.


**Méthodologie :**


*Etape 1 : export des logs Windows (PowerShell)*

Commande : Get-WinEvent -LogName Security -MaxEvents 500 | Select-Object TimeCreated, Id, Message | Export-Csv C:\security_logs.csv -Encoding UTF8 -NoTypeInformation

Explication :

- *Get-WinEvent -LogName Security :* permet d'accéder au journal de sécurité Windows.
- *-MaxEvents 500 :* limite à 500 événements pour ne pas saturer l'import
- *Select-Object :* sélectionne uniquement les champs souhaités. Ici : horodatage, ID de l'événement et message.
- *Export-Csv :* génère un fichier CSV lisible par Splunk, suivi du chemin ou le fichier doit être exporté.
- *-Encoding UTF8 :* permet de forcer l'encodage en UTF-8 qui garantit que Splunk pourra lire le fichier sans erreur
- *-NoTypeInformation :* Par défaut, PowerShell aurait ajouté une première ligne #TYPE dans le CSV. Il s'agit d'une ligne de métadonnées PowerShell qui pourrait être reconnue comme une en-tête invalide par Splunk.

Résultat : fichier "security_logs.csv" - 500 événements, 3 champs exportés (TimeCreated, Id, Message).


*Etape 2 : ingestion dans Splunk*

Chemin : Paramètres -> Ajouter des données -> Envoyer des fichiers depuis mon ordinateur

Paramètre | Valeur
Fichier | security_logs.csv
Sourcetype |  CSV (détection automatique
Hôte | windows-host
Index | défaut


*Etape 3 : requêtage SPL*

Les requêtes sont exécutées dans l'ordre logique d'une investigation SOC : exploration -> filtrage -> comptage -> visualisation temporelle.


**Résultats :**


*Exploration initiale - vérification de l'ingestion :*

Requête : source="security_logs.csv" | head 20 
Affiche les 20 premiers événements. Ingestion confirmée.

Requête : source="security_logs.csv" | head 5 | table* 
Affiche les 5 premiers événements et l'ensemble des colonnes disponibles (26 détectées). Vérification de la strucutre du fichier exploré : les champs TimeCreated, Id et Message sont présents et exploitables.

Requête : source="security_logs.csv" | head 5 | table Id 
Affiche les 5 premiers événements mais uniquement la colonne Id. Confirmation que le champ Id contient bien les Event IDs Windows.


*Recherche d'échecs de connexion - Event ID 4625 :*

Requête : source="security_logs.csv" Id=4625
Résultat : 0 occurence

Aucun échec de connexion sur la période analysée. En contexte SOC, c'est un signal positif : pas de tentative de brute force détectée.


*Analyse des connexions réussies - Event ID 4624 :*

Requête : source="security_logs.csv" Id=4624
Résultat : 58 événements

Investigation sur le type de connexion réussie :
Requête : source="security_logs.csv" Id = 4624 | table TimeCreated, Id, Message
Résultat : 58 connexions avec horodatage complet. Vérification des horaires de connexion afin de vérifier dans un premier temps qu'elles n'apparaissent pas à des heures inhabituelles. Vérification du Logon Type : elles présentent toutes un type d'ouverture de session 5 (services Windows automatique) visible dans Message.

Requête : source="security_logs.csv" Id=4624 | stats count by Id
Résultat : 58 événements de connexion réussie. Information redondante, mais permet d'introduire la logique "stats counts by". Peut-être utile pour comparer des ID (4624 et 4625 par exemple : source="security_logs.csv" Id=4624 OR Id=4625 | stats count by Id)

Requête : source="security_logs.csv" Id=4624 | timechart count
Résultat : timechart count regroupe les événements par intervalle de temps automatique (selon la fenêtre d'analyse) et compte le nombre d'occurences dans chaque intervalle. Affichage de la répartition visualisée sous forme de graphique. Aucun pic anormal identifié, distribution régulières sur les heures ouvrées.


*Recherche de privilèges élevés - Event ID 4672 :*

Requête : source="security_logs.csv" Id=4672
Résultat : 58 événements.
Hypothèse : quand un service Windows se connecte il s'octroie un privilège pour accomplir sa tâche.

Requête : source="security_logs.csv" Id=4672 | timechart count
Résultat : Répartition temporelle identique à celle des événements 4624.

Corrélation : le nombre d'événements identiques (58) et la répartition temporelle superposable entre 4624 et 4672 indiquent que chaque connexion service Windows (4624 Logon Type 5) génère systématiquement une attribution de privilèges élevés (4672). Ce comportement est attendu et normal pour les services systèmes.


*Event IDs critiques - résultats complets :*

Event ID | Signification | Occurences | Statut
:---: | :--- | :---: | :---
4624 | Connexion réussie | 58 | Normal (Logon Type 5, services système)
4625 | Échec de connexion | 0 | Aucune tentative détectée
4648 | Connexion avec credentials explicites | 0 | Non détecté
4672 | Privilèges élevés attribués | 58 | Corrélé aux 4624 — comportement attendu
4688 | Processus créé | 0 | Non détecté
4698 | Tâche planifiée créée | 0 | Non détecté
4720 | Compte utilisateur créé | 0 | Non détecté
4776 | Authentification NTLM | 0 | Non détecté


**Analyse :**


*Interprétation du Logon Type 5 :*

Toutes les connexions 4624 présentent un Logon Type 5, correspondant à des services windows démarrés automatiquement (antivirus, planificateur de tâches, services OS). Ces connexions sont invisibles pour l"utilisateur et font partie du comportement normal d'un système  Windows en fonctionnement.

Acune connexion de type 2 (connexion interactive) ou 10 (connexion à distance (RDP)) n'a été détectée, ce qui exclut toute session utilisateur humaine suspecte sur la période.


*Corrélation 4624 / 4672 :*

Le ration 1:1 entre connexion réussie (4624) et attribution de privilèges (4672) est cohérent : chaque service système qui s'authentifie reçoit les droits nécessaires à son fonctionnement. Cette corrélation a été vérifiée par comparaison des répartitions temporelles (timechart), qui sont superposables.

En contexte d'attaque, ce ration pourrait être rompu. Par exemple, un pic de 4672 sans 4624 correspondant signalerait une élévation de privilèges anormale.


*Construction de la baseline :*

Métrique | Valeur de référence
Connexions 4624 / période | 58
Privilèges 4672 / période | 58 (ratio 1:1 avec 4624)
Logon Types détectés | Type 5 uniquement
Échecs 4625 | 0
Plages horaires | Heures ouvrées normales


*IoC recherchés :*

Idicateur ce compromission | Détecté
Tentatives de brute force (4625 en rafale) | Non
Connexion RDP suspecte (4624 Type 10, heure inhabituelle) | Non
Connexion avec credentials explicites (4648) | Non
Élévation de privilèges anormale (4672 sans 4624 corrélé) | Non
Création de processus inhabituel (4688) | Non
Tâche planifiée inhabituelle (4698) | Non
Création de compte inattendue (4720) | Non
Authentification NTLM suspecte (4776) | Non

Conclusion : aucun indicateur de compromission détecté sur la période analysée.


**Recommandations :**


*Elargir la fenêtre d'analyse*

La recommandation standard est d'observer 2 à 4 semaines de données avant de créer des alertes. Une période trop courte produit une baseline non représentative.


*Enrichir les sources*

Croiser des logs de sécurité Windows avec :

- Les logs système (System) pour les erreurs de services.
- Les logs réseau (pare-feu, proxy) pour corréler les connexions sortantes.


*Créer des alertes sur les IoC prioritaires*

Suite à cette baseline, configurer des alertes Splunk sur :

- Plus de X événements 4625 en moins de 5 minutes -> suspiscion de brute force.
- Tout événement 4624 avec Logon Type 10 en dehors des heures ouvrées -> connexion RDP suspecte.
- Tout événement 4720 en dehors d'une procédure RH validée -> création de compte non autorisée.
- Tout pic de 4672 sans 4624 corrélé -> élévation de privilèges anormale.


*Implémenter le parsing avanc des champs*

Le champ "Message" contient des informations structurées (Logon Type, nom de compte, IP source) non exploitables en l'état. Une prochaine étape consiste à utiliser la commande SPL *rex* pour extraire ces champs et les rendre requêtables. Ce qui permettrait par exemple de filtrer directement sur *LogonType=10*.

*Documenter et réviser la baseline mensuellement*

Le comportement d'un système évolue avec les mises à jour et les changements organisationnels. La baseline doit être partagée avec l'équipe SOC et révisée au minimum une fois par mois.

