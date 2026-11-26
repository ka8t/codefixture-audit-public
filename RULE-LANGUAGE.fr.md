# Écrire des règles : le langage `.sca`

*English version: [RULE-LANGUAGE.md](RULE-LANGUAGE.md)*

Une règle dit au moteur ce qu'il doit chercher dans le code : un texte, ou une donnée qui voyage depuis son entrée dans le programme jusqu'à un appel où elle fait du tort. Ce guide s'adresse à qui en écrit une : un client qui ajoute des règles pour son propre code (une API interne, une convention maison, un framework que les règles livrées ne connaissent pas), et l'éditeur qui écrit le catalogue. Il décrit où se range une règle, le langage dans lequel elle s'écrit, comment la tester et comment elle apparaît dans le rapport.

Il est écrit d'après l'analyseur et les exécuteurs du moteur, et vérifié par les tests du moteur : chaque exemple ci-dessous compile et trouve ce qu'il annonce, et chaque mot-clé que l'analyseur accepte est décrit ici.

## Où se rangent vos règles

Vos règles sont de simples fichiers texte dans `~/.codefixture-audit/custom-rules/` (`%USERPROFILE%\.codefixture-audit\custom-rules\` sous Windows), une règle par fichier :

```text
~/.codefixture-audit/custom-rules/
├── python/
│   └── security/
│       └── ma_regle.sca
└── cases/
    ├── registry.json
    ├── vulnerable/python/ma_regle.py
    └── clean/python/ma_regle_clean.py
```

- Le premier dossier est le langage de la règle : `python`, `javascript` (les fichiers TypeScript utilisent les règles `javascript`), `java`, `csharp`, `php`, `html`, `yaml`, `dockerfile`. Une analyse ne lit que les règles des langages qu'elle analyse.
- Le second dossier est sa catégorie, la même que sa ligne `category`.
- Le nom du fichier est l'identifiant de la règle : `ma_regle.sca` contient `rule ma_regle`.
- `cases/` contient les cas de test de la règle (voir [Tester une règle](#tester-une-règle)). Une analyse ne lit que les fichiers `.sca`, jamais les cas.

Chaque analyse charge ces règles en plus des règles livrées ; `--custom-rules-dir <DOSSIER>`, ou la variable d'environnement `CODEFIXTURE_AUDIT_CUSTOM_RULES` pour toutes les analyses d'une machine (un serveur de CI dont le compte n'est pas le vôtre, par exemple), lit un autre dossier à la place. Un dossier donné ainsi doit exister, sinon l'analyse s'arrête et le nomme. Chaque analyse dit lesquelles de vos règles elle a lues, et depuis quel dossier, même avec `--quiet` : `Vos règles : 3/3 fichier(s) de règles retenu(s) pour les langages du projet, depuis le dossier …`, ou `Vos règles : aucune, le dossier … n'existe pas`. Aucune compilation, mise à jour ou réinstallation du moteur ne touche ce dossier. Une de vos règles qui porte le langage et l'identifiant d'une règle livrée remplace celle-ci dans chaque analyse, et l'analyse le dit : c'est ainsi qu'on ajuste une règle livrée à son code. Une règle qui ne compile pas est nommée dans un avertissement, avec l'erreur, et laissée de côté ; les autres s'exécutent.

## Écrire une règle avec l'assistant

```bash
codefixture-audit custom-rules create --lang fr
```

L'assistant demande le langage, l'identifiant, la catégorie et la gravité, puis ce qu'il faut détecter : un texte, ou un suivi de données (ses sources, ses sinks, ses nettoyants et ses passages). Il demande ensuite pourquoi le code est dangereux, comment le corriger, ce que la correction apporte, et un exemple de code vulnérable avec sa version corrigée. Il affiche la règle, la compile, nomme les règles qui cherchent déjà le même texte, et l'écrit après votre confirmation, avec ses cas de test. Si vous donnez l'identifiant d'une de vos règles, il propose de la modifier ; si vous donnez celui d'une règle livrée, il demande avant que la vôtre la remplace. Il a besoin d'un terminal.

L'assistant écrit une partie du langage : des textes simples (`text`, `text-not`), les quatre lignes du suivi de données et les blocs de texte. Tout le reste, ci-dessous, s'écrit à la main dans le même fichier : ouvrez-le dans un éditeur, modifiez-le, et relancez ses cas de test.

## Un fichier de règle

```text
rule <id>
  <header lines>
  <detection>
  <text blocks>
  <metadata block>
  <fix_before / fix_after blocks>
end
```

- `<id>` : lettres ASCII minuscules, chiffres et `_` (`[a-z0-9_]+`).
- Indentation de deux espaces. Chaque bloc s'ouvre par son mot-clé seul sur
  une ligne et se ferme par `end` sur sa propre ligne ; la règle se ferme par
  un dernier `end` en colonne 0.
- Une valeur par ligne, séparée de son mot-clé par des espaces :
  `severity  HIGH`.
- Les lignes vides sont permises partout. `#` ouvre un commentaire quand il
  commence une ligne ou suit une espace, hors guillemets : écrivez `[^#]`,
  jamais ` #`, dans un motif.

## En-tête

| Mot-clé | Valeurs | Obligatoire |
|---|---|---|
| `language` | `python`, `javascript`, `java`, `csharp`, `php`, `html`, `yaml`, `dockerfile` | oui |
| `category` | `security`, `arch`, `ui`, `ux`, `maintenance`, `cicd`, `database`, `dependencies` | non, mais le dossier de la règle porte son nom et le rapport regroupe par catégorie |
| `severity` | `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO` | oui |
| `confidence` | entier de 0 à 100 : la certitude d'un constat | non |
| `mode` | `regex`, `taint`, `regex+taint`, `ast`, `file_contains`, `python_hook` | non : déduit des blocs présents |
| `hook` | nom d'un hook Python (mode `python_hook`) | ancien, inutilisé |

Les fichiers TypeScript utilisent les règles `javascript`.

## Détection

Une règle détecte de l'une de trois façons : un motif (`match`), un suivi de
données (`source` / `sink`), ou une condition sur le fichier entier
(`requires` avec `has` / `not_has`).

### Règles à motif : `match`

```text
  match
    pattern  <regular expression>
    scope    line | file | context-<N>
    with     <regular expression>
    pattern-not  <regular expression>
  end
```

| Mot-clé | Sens |
|---|---|
| `pattern` | Expression régulière (syntaxe `fancy-regex` de Rust : l'anticipation `(?=…)`, `(?!…)` et la rétrospection sont permises ; `(?i)` pour ignorer la casse). Obligatoire, ou `text`. |
| `text` | Texte littéral au lieu d'une expression régulière ; `*` vaut n'importe quels caractères. |
| `scope` | Où `pattern` est cherché. `line` (le cas courant) : chaque ligne seule, un constat par ligne qui correspond. `file` : chaque ligne, mais `with` et `pattern-not` regardent le fichier entier. `context-N` : des fenêtres de N lignes commençant à chaque ligne, `.` correspond aussi à un saut de ligne, si bien qu'un motif peut couvrir plusieurs lignes. |
| `with` / `with-text` | Doit aussi correspondre, dans la même ligne (`line`), la même fenêtre (`context-N`) ou le fichier (`file`), pour que le constat soit gardé. |
| `pattern-not` / `text-not` | Exclusion : aucun constat quand il correspond dans la ligne, dans la fenêtre plus les N lignes qui la précèdent (`context-N`), ou dans le fichier (`file`). La façon habituelle de reconnaître une variante sûre (`timeout=`, `filter=`, un appel qui nettoie). Plusieurs lignes dans un bloc sont toutes gardées : une seule qui correspond suffit à exclure. Tout autre mot-clé donné deux fois dans un bloc est une erreur de syntaxe. |
| `pattern-inside`, `pattern-not-inside` | Acceptés par l'analyseur mais **non appliqués par le moteur**, comme dans l'Audit : une règle qui les utilise trouve comme s'ils étaient absents. Utilisez `with` pour la même ligne ou la même fenêtre, ou `requires` avec `has` pour le fichier entier. |

- Plusieurs blocs `match` dans une règle : chacun trouve de son côté ; une
  ligne n'est signalée qu'une fois. Le `pattern-not` de **chaque** bloc
  s'applique aux candidats de tous les blocs, comme dans l'Audit
  (`regex.py`) : un `pattern-not` écrit pour un bloc fait aussi taire les
  autres. Pour exclure une forme sûre dans un seul bloc, mettez la condition
  dans le `pattern` de ce bloc (une anticipation `(?!…)`).
- Les commentaires du langage analysé sont retirés avant la vérification de
  `with` et `pattern-not` ; `pattern` voit la ligne telle qu'elle est écrite.
  Ce retrait ne connaît pas les chaînes, comme dans l'Audit : `//` dans
  `"http://x"` coupe le reste de la ligne pour `with` et `pattern-not`.
- `match regex` est identique à `match`. `match ast` (une requête
  tree-sitter sous `pattern`) et `match file_contains` (`has`, `not_has`,
  `scope`) existent, mais aucune règle livrée ne les utilise.

### Règles de suivi de données : `source`, `sink`, `sanitizer`, `passthrough`

Le moteur suit les valeurs à travers le programme (affectations, appels,
retours, d'une fonction et d'un fichier à l'autre) et signale un sink atteint
par une valeur venue d'une source, sauf si un nettoyant a été appliqué en
chemin. Pris en charge pour `python`, `java`, `javascript`, `php` et
`csharp`. Ces lignes se placent directement dans la règle, hors de tout
bloc.

```text
  source  <regular expression>  kind=<kind>
  sink    <regular expression>  [arg_index=<n> [arg_name=<name>] | arg_index=all]  [kinds=<kind>,<kind>]
  sanitizer  <regular expression>
  passthrough  <regular expression>  [arg_index=<n> | arg_index=none]
```

| Mot-clé | Sens |
|---|---|
| `source` | Là où entre la donnée non fiable (`request\.args`, `req\.body`). `kind=` parmi `http` (par défaut), `cli`, `env`, `stdin`, `file`, `network`, `database` (une colonne relue dans une base de données). Au moins une. Une source qui finit par un indice, `Request\[` ou `\$_GET\[`, désigne une collection : le suivi de données la prend lue en entier (`print_r($_GET)`) ou lue à un indice (`Request["id"]`), pas comme le récepteur d'un membre (`Request.HttpContext.User.Identity.Name`) ; écrivez un membre qui porte des données comme sa propre source (`req\.body`). Une source qui finit par un point, `req\.query\.`, désigne les membres et l'objet lui-même, lu en entier (`return req.query`). Une fonction qui renvoie une source la transmet à ses appelants, quel que soit son `kind`. |
| `sink` | L'appel dangereux que la donnée ne doit pas atteindre (`\.execute\s*\(`). Au moins un. Un constructeur s'écrit avec son mot-clé, `new\s+Cookie\s*\(` : le moteur nomme `new Cookie(...)` d'après sa classe. Une classe PHP avec espace de noms prend une barre oblique inverse échappée, `Twig\\Environment\s*\(`, comme PHP l'écrit. Une méthode s'écrit avec son point, `\.setAttribute\s*\(` : sans lui, le motif ne désigne qu'une fonction seule. Un sink peut aussi lire ses arguments, `\.setAttribute\s*\(\s*["'](?:role|admin)["']` : le suivi de données nomme l'appel par le texte qui précède sa `(`, et l'expression entière doit quand même correspondre à la ligne. Une écriture à un indice s'écrit avec son crochet, `Response\.Headers\[\s*"Set-Cookie"\s*\]` : le suivi de données nomme `Response.Headers["Set-Cookie"] = value` par le texte qui précède son `[`, et la clé doit quand même correspondre à la ligne. Une rétrospection peut exclure un récepteur : `(?<![Ss]chema)\.execute\s*\(` écarte le `schema.execute(query)` de GraphQL, qui n'exécute aucun SQL. N'écartez pas un appel parce qu'il a un argument de paramètres : `cursor.execute("... " + name, params)` reste une injection. |
| `arg_index=<n>` | Option d'une ligne `sink` : l'argument (0 pour le premier) qui porte le danger, par exemple le texte SQL de `db.query(sql, params)`. Seul cet argument est vérifié, y compris dans un appel écrit sur plusieurs lignes, si bien qu'une valeur passée dans un autre argument (un paramètre de requête) n'est pas signalée. Sans elle, le suivi de données ne vérifie que le premier argument, et la vérification de la ligne cherche dans tout l'appel. |
| `arg_name=<name>` | Option d'une ligne `sink`, à côté de `arg_index=<n>` : le même argument passé par son nom, comme Python le permet. `\bResponse\s*\(  arg_index=2  arg_name=headers` vérifie les en-têtes de `Response(body, 200, h)` et de `Response(body, headers=h)`, jamais le corps. Sans elle, un argument nommé n'est jamais vérifié. Un nom qui n'est pas un identifiant, ou `arg_name` sans `arg_index` numérique, est une erreur. |
| `arg_index=all` | Option d'une ligne `sink` : chaque argument porte le danger. Écrivez-la quand l'argument dangereux n'est pas toujours le premier, typiquement un constructeur : la valeur de `new Cookie(name, value)`, le corps de `new Function("x", body)`. Les valeurs d'un initialiseur d'objet C# viennent après les arguments du constructeur : `new CookieOptions { Domain = d }` passe `d`, lu avec `arg_index=all` ; un tel sink finit par `\b`, pas par `\s*\(`, puisque l'initialiseur se passe de parenthèses. Un `new() { .. }` typé par sa cible prend le nom du type que le code lui déclare (une variable locale, un champ, une propriété, un paramètre d'une méthode de la même classe, un type de retour) : écrivez le mot-clé facultatif, `(?:new\s+)?CookieOptions\b`, puisque ce type n'est pas sur la ligne de `new()`. Toute autre option, ou une valeur qui n'est ni un nombre entier ni `all`, est une erreur. |
| `kinds=<kind>,<kind>` | Option d'une ligne `sink` : seules les données de ces types de source l'atteignent. `\.println\s*\(  kinds=http,env` empêche un sink large, qui écrit aussi des fichiers, de prendre une source `file`, qu'un sink d'écriture de page sans l'option prend toujours. Type inconnu : erreur. |
| `sanitizer` | Un appel dont le résultat est propre (`\bint\s*\(`, `escapeHtml`). |
| `passthrough` | Un appel qui transmet la contamination de son argument à son résultat (`\.strip\s*\(`). `arg_index=<n>` : cet argument et le récepteur seulement ; `arg_index=none` : le récepteur seulement, `\.xpath\s*\(  arg_index=none` (le résultat d'une requête XPath est du texte de son document, pas de la requête). |

Les quatre prennent une expression régulière comparée au code de
l'expression.

Une regex qui ne nomme aucun appel (une instruction, `^\s*return\s+f["']`, ou un texte joint à un appel par `.*`) n'est vérifiée que sur la ligne de l'instruction.

### Conditions sur le fichier : `requires` avec `has` / `not_has`

```text
  requires
    has      <regular expression>
    not_has  <regular expression>
  end
```

| Mot-clé | Sens |
|---|---|
| `has` | Doit correspondre quelque part dans le fichier (toutes les lignes `has`). |
| `not_has` | Ne doit correspondre nulle part dans le fichier. |
| `min_lines` | Le fichier a au moins ce nombre de lignes. |
| `path_contains` | Le chemin du fichier, depuis la racine du projet, contient ce texte (sans tenir compte de la casse). Plusieurs lignes : une seule suffit. |
| `not_path_contains` | Le chemin du fichier ne contient aucun de ces textes (sans tenir compte de la casse, un par ligne). Avec `path_contains`, il répartit une sorte de fichier entre des règles selon le chemin, comme le font les trois règles YAML de secrets pour les fichiers de pipeline, les fichiers locaux et les autres fichiers de configuration. |
| `not_path_has_file` | Aucun fichier de ce nom dans le dossier du fichier ni jusqu'à 5 dossiers au-dessus (un fichier de gouvernance comme `SECURITY.md`). |
| `scope` | `file` (par défaut). |

Seul, un bloc `requires` avec ces clés est la détection : un constat en
ligne 1 de chaque fichier qui remplit toutes les conditions. À côté d'un bloc
`match`, il filtre les fichiers sur lesquels `match` s'exécute. À côté des
lignes `source` / `sink`, seuls `has` et `not_has` sont permis : le suivi de
données ne signale rien dans un fichier qu'ils écartent, comme
`taint_graphql_injection` (JavaScript) ne lit que les fichiers qui utilisent
GraphQL, où `client.query(` n'est pas un client PostgreSQL.

Trois fichiers de configuration sont analysés en plus du code : `pom.xml`
(pour les règles `java`), `web.config` (`csharp`) et `package.json`
(`javascript`). Seule une règle avec `path_contains` les lit : une règle
écrite pour l'un d'eux le nomme, `path_contains  pom.xml`. Leurs
commentaires sont des commentaires XML (`pom.xml`, `web.config`) ou aucun
(`package.json`), quel que soit le langage de la règle.

## Blocs de texte

```text
  message
    en: <one line>
    fr: <one line>
    es: <one line>
    de: <one line>
  end
```

| Bloc | Contenu |
|---|---|
| `risk` | Pourquoi le code est dangereux, avec la CWE entre parenthèses. Affiché comme message du constat quand il n'y a pas de bloc `message`. |
| `solution` | Comment le corriger, concrètement. |
| `benefit` | Ce que la correction apporte. |
| `message` | Message court facultatif d'un constat, affiché à la place de `risk`. |

Chaque ligne de langue s'écrit `<code>: <texte>` sur une ligne. Le rapport
affiche le texte de sa propre langue, sinon l'anglais, sinon le premier
écrit : écrivez au moins `en` dans `risk` et `solution`.

`fix_before` et `fix_after` contiennent du code tel quel, gardé comme il est
écrit (indentation relative au bloc) : un exemple vulnérable et sa version
corrigée. Une ligne qui ne contient que `end` ferme le bloc : elle ne peut
donc pas figurer dans le code.

## Métadonnées

Le bloc `metadata` contient les références de la règle.

```text
  metadata
    cwe    CWE-89
    owasp  A03:2021
  end
```

| Clé | Valeur |
|---|---|
| `cwe` | Une ou plusieurs `CWE-<n>`, séparées par des virgules ou des espaces. Le rapport affiche chacune avec son nom et ses schémas d'attaque, tirés des listes CWE et CAPEC de MITRE intégrées au moteur ; un identifiant absent de la liste est affiché seul, et une CWE retirée par MITRE est signalée comme telle. |
| `owasp` | Entrée du Top 10 OWASP, `A03:2021`. |
| `cve` | Un ou plusieurs identifiants CVE. |
| `iso27001`, `asvs`, `wcag` | Identifiants de contrôles. |
| `generated_by`, `generated_at`, `auditai_version`, `manifest_hash`, `org_id`, `signature` | Réservés aux règles générées ; jamais écrits à la main. |

## Tester une règle

Une règle se teste sur des cas de test : de petits fichiers de code qu'elle doit signaler (vulnérables) et des fichiers qu'elle ne doit pas signaler (propres), chacun passé dans le moteur avec cette seule règle. Ils se rangent dans `cases/` de votre dossier de règles, listés dans `cases/registry.json`. L'assistant en écrit deux pour chaque règle qu'il crée : son exemple de code quand vous en avez donné un, sinon un commentaire à remplacer par du code.

```json
{
  "format": 1,
  "cases": {
    "ma_regle_python": {
      "language": "python",
      "rule": "ma_regle",
      "expect": "detected",
      "file": "vulnerable/python/ma_regle.py",
      "target": "src/app.py",
      "lines": [2]
    },
    "ma_regle_python_clean": {
      "language": "python",
      "rule": "ma_regle",
      "expect": "clean",
      "file": "clean/python/ma_regle_clean.py",
      "target": "src/app.py"
    }
  }
}
```

| Champ | Sens |
|---|---|
| clé | Le nom du cas : lettres minuscules, chiffres et `_`, unique. |
| `language`, `rule` | La règle testée, `<language>/<category>/<rule>.sca` de votre dossier. |
| `expect` | `detected` : la règle doit signaler le fichier ; `clean` : elle ne doit pas le signaler. |
| `file` | Le fichier du cas, relatif à `cases/`. Chaque fichier de `cases/vulnerable/` et `cases/clean/` doit appartenir à un cas. |
| `target` | L'emplacement du fichier dans le projet de test : un chemin que l'analyse lit comme le langage de la règle (`src/app.py`, `Dockerfile`, `src/.github/workflows/ci.yml`). |
| `lines` | Facultatif, `detected` seulement : le constat doit être sur l'une de ces lignes. |
| `extra` | Facultatif : d'autres fichiers du projet de test, `[{"file": "…", "target": "…"}]`, pour un suivi de données qui traverse plusieurs fichiers. |

```bash
codefixture-audit custom-rules test --lang fr                   # tous les cas
codefixture-audit custom-rules test python/ma_regle --lang fr   # les cas d'une règle
```

Chaque cas en échec est nommé avec sa raison, puis viennent les comptes. Le code de sortie vaut 0 quand tous les cas passent, 1 quand l'un échoue, 2 quand le registre manque ou n'est pas cohérent ; `--json` affiche le résultat en JSON. Une règle sans cas qu'elle doit signaler, ou sans cas qu'elle ne doit pas signaler, est nommée après les comptes.

Pour mettre une règle au point sur du vrai code, lancez-la sur un projet : chaque ligne qu'elle signale s'affiche (avec l'origine de la donnée, pour un suivi de données), sans rapport. Les règles livrées de son langage s'exécutent à côté : une ligne que l'une d'elles signale aussi s'affiche avec le nom de cette règle, puisque le rapport y garde le constat livré. Elles sont lues dans `rules.cfpack`, à côté de l'exécutable, comme pour `scan` ; `--rules <dossier ou pack>` en lit d'autres, et `--custom-rules-dir <dossier>` lit vos règles dans un autre dossier que `~/.codefixture-audit/custom-rules`. Les chemins du `audit.config.json` du projet s'appliquent. `custom-rules test` lance chaque cas avec sa seule règle : il ne nomme donc pas ces lignes.

```bash
codefixture-audit custom-rules try python/ma_regle /chemin/vers/le/projet --lang fr
```

## Dans le rapport

Chaque analyse exécute vos règles avec les règles livrées. Le rapport étiquette leurs constats comme les vôtres, et sa section « Règles personnalisées » liste chacune de vos règles chargées, avec son nombre de constats. Quand votre règle et une règle livrée de la même catégorie signalent la même ligne, le rapport garde le constat de la règle livrée, qui porte les textes et la remédiation du catalogue, et y laisse le vôtre de côté. L'analyse le dit, une fois par paire de règles (`Votre règle python/ma_regle fait doublon avec la règle livrée python/base64_eval sur 2 ligne(s)`), et la carte de votre règle dans la section « Règles personnalisées » nomme la règle livrée ; l'assistant prévient quand une règle livrée cherche déjà le texte que vous saisissez. Deux de vos règles sur une même ligne sont gardées toutes les deux.

## Exemples

Un motif sur une ligne, écarté quand un argument sûr est présent dans la
fenêtre :

```sca
rule missing_timeout
  language  python
  category  security
  severity  MEDIUM
  match
    pattern  (?:requests\.(?:get|post|put|delete|patch)\s*\(|urlopen\s*\(|http\.client)
    pattern-not  timeout
    scope    context-4
  end
  metadata
    cwe    CWE-400
  end
  risk
    en: HTTP requests without timeout can hang indefinitely, causing resource exhaustion (CWE-400).
    fr: Les requêtes HTTP sans timeout peuvent bloquer indéfiniment et épuiser les ressources (CWE-400).
    es: Las solicitudes HTTP sin timeout pueden bloquearse indefinidamente y agotar recursos (CWE-400).
    de: HTTP-Anfragen ohne Timeout können unbegrenzt hängen und Ressourcen erschöpfen (CWE-400).
  end
  solution
    en: Pass a timeout to every HTTP request: requests.get(url, timeout=30).
    fr: Passer un timeout à chaque requête HTTP : requests.get(url, timeout=30).
    es: Pasar un timeout a cada solicitud HTTP: requests.get(url, timeout=30).
    de: Jeder HTTP-Anfrage ein Timeout mitgeben: requests.get(url, timeout=30).
  end
  benefit
    en: A slow server can no longer block the application.
    fr: Un serveur lent ne peut plus bloquer l'application.
    es: Un servidor lento ya no puede bloquear la aplicación.
    de: Ein langsamer Server kann die Anwendung nicht mehr blockieren.
  end
  fix_before
    response = requests.get(url)
  end
  fix_after
    response = requests.get(url, timeout=10)
  end
end
```

Un motif qui demande aussi un second élément sur la même ligne :

```sca
rule subprocess_shell_true
  language  python
  category  security
  severity  HIGH
  confidence 85
  match
    pattern  \bsubprocess\.(?:run|call|Popen|check_output|check_call)\s*\(
    with     shell\s*=\s*True
    scope    line
  end
  metadata
    cwe    CWE-78
    owasp  A03:2021
  end
  risk
    en: A command run through the shell with shell=True is open to command injection when any part of it comes from input (CWE-78).
    fr: Une commande lancée par le shell avec shell=True est exposée à l'injection de commandes dès qu'une partie vient d'une entrée (CWE-78).
    es: Un comando ejecutado por el shell con shell=True queda expuesto a inyección de comandos si una parte viene de una entrada (CWE-78).
    de: Ein mit shell=True über die Shell ausgeführter Befehl ist für Command Injection anfällig, sobald ein Teil aus einer Eingabe stammt (CWE-78).
  end
  solution
    en: Pass the command as a list without shell=True: subprocess.run(["ls", path]).
    fr: Passer la commande en liste sans shell=True : subprocess.run(["ls", path]).
    es: Pasar el comando como lista sin shell=True: subprocess.run(["ls", path]).
    de: Den Befehl als Liste ohne shell=True übergeben: subprocess.run(["ls", path]).
  end
  benefit
    en: Arguments are never interpreted by a shell.
    fr: Les arguments ne sont jamais interprétés par un shell.
    es: Los argumentos nunca son interpretados por un shell.
    de: Argumente werden nie von einer Shell interpretiert.
  end
  fix_before
    subprocess.run("ls " + path, shell=True)
  end
  fix_after
    subprocess.run(["ls", path])
  end
end
```

Un suivi de données d'une requête HTTP jusqu'à l'appel d'un modèle de
langage :

```sca
rule prompt_injection_llm
  language  javascript
  category  security
  severity  HIGH
  confidence 80
  source  req\.(body|query|params)\.  kind=http
  source  req\.body\[  kind=http
  sink    openai\.chat\.completions\.create\s*\(
  sink    \.messages\.create\s*\(
  sanitizer  sanitize
  sanitizer  escapePrompt
  metadata
    cwe    CWE-1426
  end
  risk
    en: User input sent unsanitized to a language model lets an attacker override its instructions or leak data (CWE-1426).
    fr: Une entrée utilisateur envoyée telle quelle à un modèle de langage permet de détourner ses instructions ou de fuiter des données (CWE-1426).
    es: Una entrada del usuario enviada sin sanear a un modelo de lenguaje permite desviar sus instrucciones o filtrar datos (CWE-1426).
    de: Ungefiltert an ein Sprachmodell gesendete Benutzereingaben erlauben es, seine Anweisungen zu umgehen oder Daten preiszugeben (CWE-1426).
  end
  solution
    en: Sanitize user input before it reaches the model, and keep it apart from the system instructions.
    fr: Assainir l'entrée avant qu'elle n'atteigne le modèle et la séparer des instructions système.
    es: Sanear la entrada antes de que llegue al modelo y separarla de las instrucciones del sistema.
    de: Eingaben bereinigen, bevor sie das Modell erreichen, und von den Systemanweisungen trennen.
  end
  benefit
    en: The model keeps following its own instructions.
    fr: Le modèle continue de suivre ses propres instructions.
    es: El modelo sigue sus propias instrucciones.
    de: Das Modell folgt weiterhin seinen eigenen Anweisungen.
  end
  fix_before
    openai.chat.completions.create({ messages: [{ role: "user", content: req.body.q }] });
  end
  fix_after
    openai.chat.completions.create({ messages: [{ role: "user", content: sanitize(req.body.q) }] });
  end
end
```

Une condition sur le fichier entier :

```sca
rule missing_doctype
  language  html
  category  ux
  severity  LOW
  requires
    has      <html
    not_has  (?i)<!DOCTYPE
  end
  metadata
    wcag    4.1.1
  end
  risk
    en: Without a doctype the browser renders in quirks mode, with inconsistent layout.
    fr: Sans doctype, le navigateur affiche en mode quirks, avec une mise en page incohérente.
    es: Sin doctype, el navegador muestra en modo quirks, con un diseño inconsistente.
    de: Ohne Doctype rendert der Browser im Quirks-Modus mit uneinheitlichem Layout.
  end
  solution
    en: Add <!DOCTYPE html> as the first line of the document.
    fr: Ajouter <!DOCTYPE html> en première ligne du document.
    es: Añadir <!DOCTYPE html> como primera línea del documento.
    de: <!DOCTYPE html> als erste Zeile des Dokuments einfügen.
  end
  benefit
    en: The page renders the same in every browser.
    fr: La page s'affiche de la même façon dans tous les navigateurs.
    es: La página se muestra igual en todos los navegadores.
    de: Die Seite wird in allen Browsern gleich dargestellt.
  end
  fix_before
    <html>
  end
  fix_after
    <!DOCTYPE html>
    <html lang="en">
  end
end
```
