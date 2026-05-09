# Injection SQL (UNION-Based SQLi)

**Plateforme :** PortSwigger Web Security Academy  
**Catégorie :** Injection SQL  
**Difficulté :** Apprentice / Practitioner
**Date :** 08 Mai 2026  
**Référence OWASP :** A03:2025 — Injection  


## 1. Contexte

L'injection SQL (SQLi) est une vulnérabilité qui permet à un attaquant de manipuler les requêtes SQL exécutées par une application web en injectant du code malveillant dans les paramètres d'entrée. Elle figure en position A03 de l'OWASP Top 10 2025.

Ces exercices ont été réalisés sur PortSwigger Web Security Academy dans un environnement contrôlé. L'objectif était de comprendre et d'appliquer la technique UNION-Based SQLi, qui permet d'extraire des données depuis des tables normalement inaccessibles, en s'appuyant sur la clause SQL `UNION`.


## 2. Méthodologie

### 2.1 Identification du point d'injection

Le point d'injection identifié est le paramètre `category` dans l'URL :

```
https://site.com/filter?category=Gifts
```

Ce paramètre est directement intégré dans une requête SQL côté serveur sans validation. La requête côté serveur ressemble à :

```sql
SELECT nom, description, prix FROM produits WHERE categorie = 'Gifts'
```

En injectant une apostrophe `'`, la requête devient syntaxiquement incorrecte et retourne une erreur HTTP — confirmant que l'entrée utilisateur est interprétée par le moteur SQL sans protection.


### 2.2 Détermination du nombre de colonnes

Avant toute extraction de données, il faut connaître le nombre exact de colonnes retournées par la requête originale. La clause `UNION` exige que les deux `SELECT` retournent exactement le même nombre de colonnes — sinon la base de données retourne une erreur de syntaxe.

**Technique utilisée :** injection de valeurs `NULL` successives.

```sql
' UNION SELECT NULL--
' UNION SELECT NULL, NULL--
' UNION SELECT NULL, NULL, NULL--
```

**Raisonnement :** `NULL` est compatible avec tous les types de données. On ajoute un `NULL` à chaque tentative. Tant que le nombre ne correspond pas, la base retourne une erreur. Quand la requête s'exécute sans erreur, le nombre de `NULL` correspond au nombre de colonnes réel.

**Résultat :** la requête originale retourne **3 colonnes**.

---

### 2.3 Identification des colonnes compatibles texte

Pour extraire des données textuelles (identifiants, mots de passe), il faut identifier quelle colonne accepte un type `string/varchar`. Injecter une valeur string dans une colonne de type `integer` provoque une erreur de type qui fait échouer toute la requête `UNION`.

**Technique utilisée :** remplacement des `NULL` par une valeur string `'a'`, un par un.

```sql
' UNION SELECT 'a', NULL, NULL--
' UNION SELECT NULL, 'a', NULL--
' UNION SELECT NULL, NULL, 'a'--
```

**Raisonnement :** on teste chaque position indépendamment. Si la requête s'exécute sans erreur, la colonne testée accepte du texte. Si erreur de type, la colonne est incompatible.

**Résultat :** la **deuxième colonne** accepte du texte.


### 2.4 Extraction de données depuis une table externe

Une fois la structure de la requête connue, l'objectif est d'extraire les données de la table `users`, qui contient les identifiants et mots de passe de l'application.

**Raisonnement :** `UNION` permet d'accoler les résultats d'une seconde requête contrôlée par l'attaquant à la requête légitime. La seconde requête cible une table différente de celle prévue par l'application. Pour connaître les noms de tables disponibles dans la base, on peut interroger `information_schema.tables` — une table système présente dans la plupart des SGBD (MySQL, PostgreSQL, MSSQL) qui liste toutes les tables existantes.

```sql
' UNION SELECT table_name, NULL, NULL FROM information_schema.tables--
```

Une fois la table `users` identifiée, on extrait son contenu :

```sql
' UNION SELECT NULL, username, password FROM users--
```

**Résultat :** les identifiants et mots de passe de tous les utilisateurs sont retournés dans la réponse de la page, y compris le compte `administrator`. Connexion au compte administrateur confirmée.


### 2.5 Extraction avec concaténation dans une seule colonne

Dans un scénario où une seule colonne accepte du texte, il est impossible d'extraire deux valeurs distinctes dans deux colonnes séparées. Il faut concaténer plusieurs valeurs dans cette unique colonne.

**Raisonnement :** sans séparateur, `adminpassword` est illisible et inexploitable. L'ajout d'un séparateur `:` produit `admin:password`, directement lisible. L'opérateur de concaténation dépend du SGBD — ici PostgreSQL avec `||`.

```sql
' UNION SELECT NULL, username||':'||password FROM users--
```

**Résultat :** les identifiants sont retournés sous la forme `administrator:motdepasse`. Connexion au compte administrateur confirmée.


## 3. Résultats

| Étape | Technique utilisée | Résultat obtenu |
|---|---|---|
| Détection du point d'injection | Injection `'` | Erreur SQL — vulnérabilité confirmée |
| Nombre de colonnes | `NULL` successifs | 3 colonnes identifiées |
| Type des colonnes | Valeur `'a'` par position | Colonne 2 compatible texte |
| Identification des tables | `information_schema.tables` | Table `users` identifiée |
| Extraction simple | `UNION SELECT` sur `users` | Identifiants et mots de passe récupérés |
| Extraction concaténée | Opérateur `\|\|` | Identifiants lisibles dans une seule colonne |


## 4. Analyse

### Pourquoi cette vulnérabilité existe

L'application intègre directement la valeur du paramètre `category` dans la requête SQL sans validation ni paramétrage :

```sql
SELECT nom, description, prix FROM produits WHERE categorie = '[valeur utilisateur]'
```

L'attaquant contrôle entièrement la fin de cette requête. En injectant `' UNION SELECT...`, il ajoute une seconde requête dont il contrôle la cible et le contenu. Aucune vérification n'est effectuée côté serveur sur la valeur reçue.

### Conditions d'application de UNION-Based SQLi

Cette technique fonctionne uniquement lorsque les résultats de la requête sont **affichés dans la réponse HTTP**. Si les résultats ne sont pas visibles, d'autres techniques sont nécessaires :
- **Boolean-Blind SQLi** : inférence par vrai/faux sur le comportement de la page
- **Time-Based SQLi** : inférence par délai de réponse (ex: `SLEEP()`)
- **Error-Based SQLi** : extraction via les messages d'erreur de la base

### Impact — Triade CIA

| Pilier | Impact |
|---|---|
| **Confidentialité** | Extraction de l'ensemble des identifiants, mots de passe et données sensibles de la base |
| **Intégrité** | Modification ou suppression de données possibles via des requêtes `INSERT`, `UPDATE`, `DELETE` injectées |
| **Disponibilité** | Suppression de tables ou saturation de la base potentiellement envisageables |


## 5. Recommandations

### 1. Requêtes paramétrées — défense principale

Ne jamais construire une requête SQL par concaténation de chaînes de caractères. Utiliser des requêtes préparées où les paramètres utilisateur sont transmis séparément du code SQL — le moteur de base de données les traite alors comme de la donnée, jamais comme du code exécutable.

### 2. ORM (Object-Relational Mapping)

Un ORM est une couche logicielle qui fait l'intermédiaire entre l'application et la base de données. Au lieu d'écrire des requêtes SQL manuellement, le développeur manipule des objets dans son langage de programmation — l'ORM génère les requêtes SQL de manière sécurisée en arrière-plan. Les requêtes paramétrées sont appliquées automatiquement, sans que le développeur ait à s'en préoccuper explicitement. Exemples courants : SQLAlchemy (Python), Hibernate (Java), Django ORM (Python).

### 3. Validation des entrées côté serveur

Valider et filtrer toutes les entrées utilisateur côté serveur. Privilégier une liste blanche des valeurs autorisées plutôt qu'une liste noire de caractères interdits — les listes noires sont contournables.

### 4. Principe du moindre privilège

Le compte base de données utilisé par l'application ne doit avoir accès qu'aux tables nécessaires à son fonctionnement. Il ne doit en aucun cas avoir accès à `information_schema` ou disposer de droits `DROP`, `INSERT`, `UPDATE` si l'application n'en a pas besoin.

### 5. WAF (Web Application Firewall)

Couche de défense supplémentaire capable de détecter et bloquer les patterns d'injection connus. Ne remplace pas les défenses précédentes — à considérer comme protection complémentaire.

---

*Write-up rédigé dans le cadre d'une formation cybersécurité — environnement légal et contrôlé (PortSwigger Web Security Academy).*
