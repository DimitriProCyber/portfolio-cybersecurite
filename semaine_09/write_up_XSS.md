# Cross-Site Scripting (XSS)

**Plateforme :** PortSwigger Web Security Academy  
**Catégorie :** Cross-Site Scripting (XSS)  
**Difficulté :** Apprentice / Practitioner
**Date :** 09 Mai 2026  
**Référence OWASP :** A03:2025 — Injection  


## 1. Contexte

Le Cross-Site Scripting (XSS) est une vulnérabilité qui permet à un attaquant d'injecter du code JavaScript malveillant dans une page web consultée par d'autres utilisateurs. Le script s'exécute dans le navigateur de la victime, dans le contexte de confiance du site légitime.

Il existe trois types de XSS :

- **Reflected XSS** : le payload est injecté dans l'URL. Le serveur le reflète dans la réponse HTML et le navigateur de la victime l'exécute. La victime doit cliquer sur un lien malveillant.
- **Stored XSS** : le payload est stocké en base de données et exécuté automatiquement par tous les utilisateurs qui consultent la page concernée. Plus dangereux car aucune interaction spécifique n'est requise.
- **DOM XSS** : le payload n'est jamais envoyé au serveur. Il est lu directement depuis l'URL par un script JavaScript légitime de la page, et inséré dans le DOM côté navigateur. Indétectable côté serveur.

Ces exercices ont été réalisés sur PortSwigger Web Security Academy dans un environnement contrôlé. L'objectif était de comprendre le mécanisme de chaque type de XSS selon le contexte d'injection.


## 2. Concepts clés — Source et Sink (DOM XSS)

En DOM XSS, deux concepts sont fondamentaux :

- **Source** : point d'entrée de la donnée contrôlée par l'attaquant. Exemple : `location.search` — la valeur du paramètre dans l'URL (`?search=...`).
- **Sink** : fonction JavaScript qui insère cette donnée dans le DOM. Si la donnée arrive dans un sink sans être nettoyée, elle peut être exécutée. Exemples : `document.write()`, `innerHTML`.

Le schéma d'une attaque DOM XSS : **Source** → script légitime → **Sink** → exécution dans le navigateur.


## 3. Méthodologie

### 3.1 Reflected XSS — Contexte HTML sans encodage

**Lab :** Reflected XSS into HTML context with nothing encoded

**Point d'injection :** barre de recherche — la valeur est reflétée directement dans le HTML de la réponse sans aucun traitement.

**Raisonnement :** aucun filtre n'étant appliqué, une balise `<script>` est directement exécutée par le navigateur.

**Payload utilisé :**
```
<script>alert(1)</script>
```

**Résultat :** la fonction `alert()` s'exécute dans le navigateur — injection confirmée.


### 3.2 Stored XSS — Contexte HTML sans encodage

**Lab :** Stored XSS into HTML context with nothing encoded

**Point d'injection :** champ commentaire — la valeur est stockée en base de données et reflétée dans la page à chaque consultation.

**Raisonnement :** le payload est stocké sans validation. Chaque utilisateur consultant la page déclenche l'exécution du script.

**Payload utilisé :**
```
<script>alert(1)</script>
```

**Résultat :** la fonction `alert()` s'exécute automatiquement à chaque chargement de la page — injection persistante confirmée.


### 3.3 DOM XSS — Sink `document.write` avec source `location.search`

**Lab :** DOM XSS in document.write sink using source location.search

**Source :** `location.search` — paramètre de recherche dans l'URL.  
**Sink :** `document.write()` — le script légitime de la page lit la valeur et l'écrit directement dans le DOM.

Le code légitime de la page :
```javascript
function trackSearch(query) {
    document.write('<img src="/resources/images/tracker.gif?searchTerms=' + query + '">');
}
var query = (new URLSearchParams(window.location.search)).get('search');
if (query) { trackSearch(query); }
```

**Raisonnement :** la valeur de recherche est insérée à l'intérieur de l'attribut `src` d'une balise `<img>`. Pour en sortir, on ferme l'attribut avec `"` puis la balise avec `>`. Une balise `<script>` injectée dynamiquement via `document.write` n'est pas exécutée par les navigateurs modernes — il faut utiliser un event handler sur une autre balise HTML. La balise `<svg>` avec l'attribut `onload` déclenche l'exécution dès le chargement de l'élément.

**Payload utilisé :**
```
"><svg onload=alert(1)>
```

**Décomposition du payload :**
- `"` — ferme l'attribut `src`
- `>` — ferme la balise `<img>`
- `<svg onload=alert(1)>` — balise SVG dont l'event handler `onload` exécute `alert(1)` au chargement

**Résultat :** `alert()` s'exécute — injection DOM confirmée sans aucun passage par le serveur.


### 3.4 DOM XSS — Sink `innerHTML` avec source `location.search`

**Lab :** DOM XSS in innerHTML sink using source location.search

**Source :** `location.search`  
**Sink :** `innerHTML` — insère du HTML dans le DOM mais **refuse d'exécuter les balises `<script>`**. C'est une limitation de sécurité des navigateurs modernes : une balise `<script>` insérée via `innerHTML` est ignorée.

**Raisonnement :** `<script>` étant bloqué, il faut un vecteur d'exécution alternatif. Un event handler sur une balise HTML valide contourne cette limitation. La balise `<img>` avec `onerror` déclenche l'exécution lorsque le navigateur tente de charger une image depuis une source invalide (`src=x`) et échoue.

**Payload utilisé :**
```
<img src=x onerror=alert(1)>
```

**Décomposition du payload :**
- `src=x` — source d'image inexistante, provoque une erreur de chargement
- `onerror=alert(1)` — event handler déclenché par l'échec de chargement

**Résultat :** `alert()` s'exécute via l'erreur de chargement de l'image — injection DOM via `innerHTML` confirmée.


### 3.5 Reflected XSS — Contexte attribut avec angle brackets encodés

**Lab :** Reflected XSS into attribute with angle brackets HTML-encoded

**Point d'injection :** barre de recherche — la valeur est insérée dans un attribut HTML.

**Filtrage appliqué :** les caractères `<` et `>` sont encodés en `&lt;` et `&gt;`. Une injection classique `"><script>alert(1)</script>` est neutralisée — le `>` encodé ne ferme plus la balise, le payload est affiché comme du texte.

**Raisonnement :** impossible de sortir du contexte attribut via `< >`. En revanche, les guillemets ne sont pas encodés. On peut fermer la valeur de l'attribut courant avec `"` et injecter un nouvel attribut event handler directement dans la balise — sans avoir besoin de créer une nouvelle balise.

**Payload utilisé :**
```
" onmouseover="alert(1)
```

**Décomposition du payload :**
- `"` — ferme la valeur de l'attribut courant
- `onmouseover="alert(1)` — injecte un nouvel attribut event handler dans la balise existante

**Résultat :** `alert()` s'exécute au survol de l'élément — injection en contexte attribut confirmée.


### 3.6 Reflected XSS — Contexte JavaScript avec échappement des guillemets simples et backslash

**Lab :** Reflected XSS into a JavaScript string with single quote and backslash escaped

**Point d'injection :** barre de recherche — la valeur est insérée à l'intérieur d'une chaîne JavaScript dans un bloc `<script>` existant.

**Filtrage appliqué :** le site échappe `'` en `\'` et `\` en `\\` pour empêcher de fermer la chaîne JavaScript.

**Raisonnement :** les tentatives de fermeture de chaîne via `'` ou `\'` sont neutralisées par le double échappement. Cependant, le navigateur effectue deux passes distinctes sur le document : il **parse le HTML en premier**, avant d'interpréter le JavaScript. La balise `</script>` est donc reconnue et traitée par le parser HTML même si elle se trouve au milieu d'une chaîne JavaScript syntaxiquement invalide. Le bloc script courant est fermé, le JavaScript cassé est ignoré, et un nouveau bloc `<script>` injecté est exécuté normalement.

**Payload utilisé :**
```
</script><script>alert(1)</script>
```

**Décomposition du payload :**
- `</script>` — ferme le bloc script existant au niveau du parser HTML
- `<script>alert(1)</script>` — nouveau bloc script exécuté normalement

**Résultat :** `alert()` s'exécute — injection en contexte JavaScript confirmée en exploitant la priorité du parser HTML.


## 4. Résultats

| Lab | Type XSS | Contexte | Technique | Résultat |
|---|---|---|---|---|
| HTML sans encodage (Reflected) | Reflected | HTML direct | `<script>alert(1)</script>` | Résolu |
| HTML sans encodage (Stored) | Stored | HTML direct | `<script>alert(1)</script>` | Résolu |
| document.write / location.search | DOM | Attribut src | `"><svg onload=alert(1)>` | Résolu |
| innerHTML / location.search | DOM | innerHTML | `<img src=x onerror=alert(1)>` | Résolu |
| Attribut / angle brackets encodés | Reflected | Attribut HTML | `" onmouseover="alert(1)` | Résolu |
| JS string / quote+backslash escapés | Reflected | Chaîne JavaScript | `</script><script>alert(1)</script>` | Résolu |


## 5. Analyse

### Le contexte d'injection détermine le payload

Le principal enseignement de ces labs est que le payload doit être adapté au **contexte dans lequel la donnée est insérée**. Il n'existe pas de payload universel — chaque contexte impose ses contraintes :

| Contexte | Contrainte | Solution |
|---|---|---|
| HTML direct | Aucune | `<script>` direct |
| Attribut HTML | `< >` encodés | Event handler dans l'attribut |
| Sink `innerHTML` | `<script>` ignoré | Event handler sur autre balise |
| Sink `document.write` | `<script>` ignoré dynamiquement | Event handler sur autre balise |
| Chaîne JavaScript | Guillemets échappés | Fermeture du bloc via parser HTML |

### Pourquoi les event handlers contournent les filtres

Les filtres XSS ciblent souvent les balises `<script>` et les caractères `< >`. Les event handlers (`onload`, `onerror`, `onmouseover`) sont des attributs HTML standards — ils ne nécessitent pas de nouvelles balises et échappent aux filtres ciblant uniquement `<script>`.

### Impact — Triade CIA

| Pilier | Impact |
|---|---|
| **Confidentialité** | Vol de cookies de session (`document.cookie`), interception de données saisies dans les formulaires |
| **Intégrité** | Modification du contenu de la page affiché à la victime, redirection vers un site malveillant |
| **Disponibilité** | Dégradation de l'interface, boucles infinies rendant la page inutilisable |


## 6. Recommandations

### 1. Encodage des sorties — défense principale

Encoder systématiquement toutes les données affichées dans la page selon le contexte de sortie :
- **Contexte HTML** : encoder `< > & " '` en entités HTML
- **Contexte attribut** : encoder les guillemets
- **Contexte JavaScript** : encoder les guillemets simples et doubles
- **Contexte URL** : encoder les caractères spéciaux URL

L'encodage doit être appliqué **au moment de l'affichage**, pas à la saisie.

### 2. Content Security Policy (CSP)

Mécanisme de sécurité côté navigateur qui restreint les sources de scripts autorisées à s'exécuter sur la page. Une CSP correctement configurée empêche l'exécution de scripts injectés même si l'injection a lieu. À définir via l'en-tête HTTP `Content-Security-Policy`.

### 3. Attribut HTTPOnly sur les cookies de session

L'attribut `HttpOnly` sur un cookie empêche JavaScript d'y accéder via `document.cookie`. Un attaquant ayant réussi une injection XSS ne peut pas voler le cookie de session — ce qui limite l'impact d'une attaque réussie.

### 4. Validation des entrées côté serveur

Valider et filtrer toutes les entrées utilisateur côté serveur. Privilégier une liste blanche des valeurs et formats autorisés. Ne pas se reposer uniquement sur la validation côté client, contournable par l'attaquant.

### 5. WAF (Web Application Firewall)

Couche de défense supplémentaire capable de détecter et bloquer les patterns XSS connus. Ne remplace pas les défenses précédentes — à considérer comme protection complémentaire.

---

*Write-up rédigé dans le cadre d'une formation cybersécurité — environnement légal et contrôlé (PortSwigger Web Security Academy).*
