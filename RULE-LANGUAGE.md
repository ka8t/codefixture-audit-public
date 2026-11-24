# Writing rules: the `.sca` language

*Version française : [RULE-LANGUAGE.fr.md](RULE-LANGUAGE.fr.md)*

A rule tells the engine what to look for in code: a text, or data that travels from where it enters the program to a call where it does harm. This guide is for anyone who writes one: a client adding rules for their own code (an in-house API, a house convention, a framework the delivered rules do not know), and the editor writing the catalog. It describes where a rule lives, the language it is written in, how to test it and how it shows in the report.

It is written from the engine's parser and executors, and checked against them by the engine's tests: every example below compiles and finds what it says, and every keyword the parser accepts is described here.

## Where your rules live

Your rules are plain text files in `~/.codefixture-audit/custom-rules/` (`%USERPROFILE%\.codefixture-audit\custom-rules\` on Windows), one rule per file:

```text
~/.codefixture-audit/custom-rules/
├── python/
│   └── security/
│       └── my_rule.sca
└── cases/
    ├── registry.json
    ├── vulnerable/python/my_rule.py
    └── clean/python/my_rule_clean.py
```

- The first folder is the rule's language: `python`, `javascript` (TypeScript files use the `javascript` rules), `java`, `csharp`, `php`, `html`, `yaml`, `dockerfile`. A scan only reads the rules of the languages it analyses.
- The second folder is its category, the same as its `category` line.
- The file name is the rule's id: `my_rule.sca` holds `rule my_rule`.
- `cases/` holds the rule's test cases (see [Testing a rule](#testing-a-rule)). A scan reads `.sca` files only, never the cases.

Every scan loads these rules besides the delivered ones; `--custom-rules-dir <FOLDER>` reads another folder instead. No build, update or reinstall of the engine touches this folder. A rule of yours with the language and the id of a delivered rule replaces that rule in every scan, and the scan says so: that is how you adjust a delivered rule to your code. A rule that does not compile is named in a warning, with the error, and left out; the others run.

## Writing a rule with the wizard

```bash
codefixture-audit custom-rules create --lang en
```

The wizard asks the language, the id, the category and the severity, then what to detect: a text, or a data flow (its sources, sinks, sanitizers and passthroughs). It then asks why the code is dangerous, how to fix it, what the fix brings, and an example of vulnerable code with its fixed version. It shows the rule, compiles it, names the rules that already search the same text, and writes it after your confirmation, with its test cases. Given the id of one of your rules, it offers to edit it; given the id of a delivered rule, it asks before yours replaces it. It needs a terminal.

The wizard writes a part of the language: plain texts (`text`, `text-not`), the four data-flow lines and the text blocks. Everything else below is written by hand, in the same file: open it in an editor, change it, and run its test cases again.

## A rule file

```text
rule <id>
  <header lines>
  <detection>
  <text blocks>
  <metadata block>
  <fix_before / fix_after blocks>
end
```

- `<id>`: lowercase ASCII letters, digits and `_` (`[a-z0-9_]+`).
- Two-space indentation. Every block opens with its keyword alone on a
  line and closes with `end` on its own line; the rule closes with a last
  `end` at column 0.
- One value per line, separated from its keyword by spaces:
  `severity  HIGH`.
- Blank lines are allowed anywhere. `#` starts a comment when it begins a
  line or follows a space, outside quotes: write `[^#]`, never ` #`, inside a
  pattern.

## Header

| Keyword | Values | Required |
|---|---|---|
| `language` | `python`, `javascript`, `java`, `csharp`, `php`, `html`, `yaml`, `dockerfile` | yes |
| `category` | `security`, `arch`, `ui`, `ux`, `maintenance`, `cicd`, `database`, `dependencies` | no, but the rule's folder is named after it and the report groups by it |
| `severity` | `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO` | yes |
| `confidence` | integer 0–100: how sure a finding is | no |
| `mode` | `regex`, `taint`, `regex+taint`, `ast`, `file_contains`, `python_hook` | no: inferred from the blocks present |
| `hook` | name of a Python hook (mode `python_hook`) | legacy, unused |

TypeScript files use the `javascript` rules.

## Detection

A rule detects in one of three ways: a pattern (`match`), a data flow
(`source` / `sink`), or a condition on the whole file (`requires` with
`has` / `not_has`).

### Pattern rules: `match`

```text
  match
    pattern  <regular expression>
    scope    line | file | context-<N>
    with     <regular expression>
    pattern-not  <regular expression>
  end
```

| Keyword | Meaning |
|---|---|
| `pattern` | Regular expression (Rust `fancy-regex` syntax: look-ahead `(?=…)`, `(?!…)` and look-behind are allowed; `(?i)` for case-insensitive). Required, or `text`. |
| `text` | Literal text instead of a regular expression; `*` stands for any characters. |
| `scope` | Where `pattern` is searched. `line` (default in practice): each line alone, one finding per matching line. `file`: each line, but `with` and `pattern-not` look at the whole file. `context-N`: windows of N lines starting at each line, `.` also matches a line break, so a pattern can span lines. |
| `with` / `with-text` | Must also match, in the same line (`line`), the same window (`context-N`) or the file (`file`), for the finding to be kept. |
| `pattern-not` / `text-not` | Exclusion: no finding when it matches in the line, the window plus the N lines before it (`context-N`), or the file (`file`). The usual way to recognize a safe variant (`timeout=`, `filter=`, a sanitizing call). Several lines in one block are all kept: one matching is enough to exclude. Any other keyword given twice in one block is a syntax error. |
| `pattern-inside`, `pattern-not-inside` | Accepted by the parser but **not applied by the engine**, as in the Audit: a rule that uses them finds as if they were absent. Use `with` for the same line or window, or `requires` with `has` for the whole file. |

- Several `match` blocks in one rule: each one finds on its own; a line is
  reported once. The `pattern-not` of **every** block applies to the
  candidates of every block, as in the Audit (`regex.py`): a `pattern-not`
  written for one block also silences the others. To exclude a safe form in
  one block only, put the condition in that block's `pattern` (a look-ahead
  `(?!…)`).
- Comments of the scanned language are removed before `with` and
  `pattern-not` are checked; `pattern` sees the line as written. The removal
  does not know strings, as in the Audit: `//` inside `"http://x"` cuts the
  rest of the line for `with` and `pattern-not`.
- `match regex` is the same as `match`. `match ast` (a tree-sitter query
  under `pattern`) and `match file_contains` (`has`, `not_has`, `scope`)
  exist but no delivered rule uses them.

### Data-flow rules: `source`, `sink`, `sanitizer`, `passthrough`

The engine follows values through the program (assignments, calls, returns,
across functions and files) and reports a sink reached by a value coming
from a source, unless a sanitizer was applied on the way. Supported for
`python`, `java`, `javascript`, `php` and `csharp`. These lines sit
directly in the rule, outside any block.

```text
  source  <regular expression>  kind=<kind>
  sink    <regular expression>  [arg_index=<n> [arg_name=<name>] | arg_index=all]  [kinds=<kind>,<kind>]
  sanitizer  <regular expression>
  passthrough  <regular expression>  [arg_index=<n> | arg_index=none]
```

| Keyword | Meaning |
|---|---|
| `source` | Where untrusted data enters (`request\.args`, `req\.body`). `kind=` one of `http` (default), `cli`, `env`, `stdin`, `file`, `network`, `database` (a column read back from a database). At least one. A source ending with an index, `Request\[` or `\$_GET\[`, names a collection: the data flow takes it read whole (`print_r($_GET)`) or read into (`Request["id"]`), not as the receiver of a member (`Request.HttpContext.User.Identity.Name`); write a member that carries data as its own source (`req\.body`). A source ending with a dot, `req\.query\.`, names the members and the object itself, read whole (`return req.query`). A function that returns a source hands it to its callers, whatever its `kind`. |
| `sink` | The dangerous call the data must not reach (`\.execute\s*\(`). At least one. A constructor is written with its keyword, `new\s+Cookie\s*\(`: the engine names `new Cookie(...)` after its class. A PHP namespaced class takes one escaped backslash, `Twig\\Environment\s*\(`, as PHP writes it. A method is written with its dot, `\.setAttribute\s*\(`: without it, the pattern names a bare function only. A sink can also read its arguments, `\.setAttribute\s*\(\s*["'](?:role|admin)["']`: the data flow names the call by the text before its `(`, and the whole expression must still match the line. A write into an index is written with its bracket, `Response\.Headers\[\s*"Set-Cookie"\s*\]`: the data flow names `Response.Headers["Set-Cookie"] = value` by the text before its `[`, and the key must still match the line. A look-behind can exclude a receiver: `(?<![Ss]chema)\.execute\s*\(` skips GraphQL's `schema.execute(query)`, which runs no SQL. Do not skip a call because it has a parameters argument: `cursor.execute("... " + name, params)` is still an injection. |
| `arg_index=<n>` | Option of a `sink` line: the argument (0 for the first) that carries the danger, for example the SQL text of `db.query(sql, params)`. Only that argument is checked, including in a call written over several lines, so a value passed in another argument (a query parameter) is not reported. Without it, the data flow checks the first argument only, and the line check searches the whole call. |
| `arg_name=<name>` | Option of a `sink` line, beside `arg_index=<n>`: the same argument passed by keyword, as Python allows. `\bResponse\s*\(  arg_index=2  arg_name=headers` checks the headers of `Response(body, 200, h)` and of `Response(body, headers=h)`, never the body. Without it, a keyword argument is never checked. A name that is not an identifier, or `arg_name` without a numbered `arg_index`, is an error. |
| `arg_index=all` | Option of a `sink` line: every argument carries the danger. Write it when the dangerous argument is not always the first, typically a constructor: the value of `new Cookie(name, value)`, the body of `new Function("x", body)`. The values of a C# object initializer come after the constructor's own arguments: `new CookieOptions { Domain = d }` passes `d`, read with `arg_index=all`; such a sink ends with `\b`, not `\s*\(`, since the initializer needs no parentheses. A target-typed `new() { .. }` is named after the type the code declares for it (a local, a field, a property, a parameter of a method of the same class, a return type): write the keyword optional, `(?:new\s+)?CookieOptions\b`, since that type is not on the line of `new()`. Any other option, or a value that is neither a whole number nor `all`, is an error. |
| `kinds=<kind>,<kind>` | Option of a `sink` line: only data of these source kinds reaches it. `\.println\s*\(  kinds=http,env` keeps a broad sink that also writes files from taking a `file` source, which a page sink without the option still takes. Unknown kind: error. |
| `sanitizer` | A call whose result is clean (`\bint\s*\(`, `escapeHtml`). |
| `passthrough` | A call that carries taint from its argument to its result (`\.strip\s*\(`). `arg_index=<n>`: that argument and the receiver only; `arg_index=none`: the receiver only, `\.xpath\s*\(  arg_index=none` (an XPath result is text of its document, not of the query). |

All four take a regular expression matched against the code of the
expression.

A regex that names no call (a statement, `^\s*return\s+f["']`, or text joined to a call by `.*`) is tested on the statement's line only.

### File conditions: `requires` with `has` / `not_has`

```text
  requires
    has      <regular expression>
    not_has  <regular expression>
  end
```

| Keyword | Meaning |
|---|---|
| `has` | Must match somewhere in the file (all `has` lines). |
| `not_has` | Must match nowhere in the file. |
| `min_lines` | The file has at least this many lines. |
| `path_contains` | The file path, from the project root, contains this text (case-insensitive). Several lines: one of them is enough. |
| `not_path_contains` | The file path contains none of these texts (case-insensitive, one per line). With `path_contains`, it shares one kind of file between rules by path, as the three YAML secret rules do for pipeline, local and other configuration files. |
| `not_path_has_file` | No file of this name in the file's folder or up to 5 folders above (a governance file such as `SECURITY.md`). |
| `scope` | `file` (default). |

Alone, a `requires` block with these keys is the detection: one finding at
line 1 of each file that meets all conditions. Beside a `match` block, it
filters the files the `match` runs on. Beside `source` / `sink` lines, only
`has` and `not_has` are allowed: the data flow reports nothing in a file
they reject, as `taint_graphql_injection` (JavaScript) only reads the files
that use GraphQL, where `client.query(` is not a PostgreSQL client.

Three configuration files are scanned besides the code: `pom.xml` (for the
`java` rules), `web.config` (`csharp`) and `package.json` (`javascript`).
Only a rule with `path_contains` reads them, so a rule written for one of
them names it: `path_contains  pom.xml`. Their comments are XML comments
(`pom.xml`, `web.config`) or none (`package.json`), whatever the rule
language.

## Text blocks

```text
  message
    en: <one line>
    fr: <one line>
    es: <one line>
    de: <one line>
  end
```

| Block | Content |
|---|---|
| `risk` | Why the code is dangerous, with the CWE in parentheses. Shown as the finding's message when there is no `message` block. |
| `solution` | How to fix it, concretely. |
| `benefit` | What the fix brings. |
| `message` | Optional short message of a finding, shown instead of `risk`. |

Each language line is `<code>: <text>` on one line. The report shows the
text of its own language, else the English one, else the first one written:
write at least `en` in `risk` and `solution`.

`fix_before` and `fix_after` hold plain code, kept as written (indentation
relative to the block): a vulnerable example and its fixed version. A line
holding only `end` closes the block, so it cannot appear in the code.

## Metadata

The `metadata` block holds the references of the rule.

```text
  metadata
    cwe    CWE-89
    owasp  A03:2021
  end
```

| Key | Value |
|---|---|
| `cwe` | One or more `CWE-<n>`, separated by commas or spaces. |
| `owasp` | OWASP Top 10 entry, `A03:2021`. |
| `cve` | One or more CVE ids. |
| `iso27001`, `asvs`, `wcag` | Control ids. |
| `generated_by`, `generated_at`, `auditai_version`, `manifest_hash`, `org_id`, `signature` | Reserved for generated rules; never written by hand. |

## Testing a rule

A rule is tested on test cases: small files of code it must flag (vulnerable) and files it must not (clean), each run through the engine with this rule alone. They sit in `cases/` of your rules folder, listed in `cases/registry.json`. The wizard writes two for each rule it creates: its code example when you gave one, otherwise a comment to replace with code.

```json
{
  "format": 1,
  "cases": {
    "my_rule_python": {
      "language": "python",
      "rule": "my_rule",
      "expect": "detected",
      "file": "vulnerable/python/my_rule.py",
      "target": "src/app.py",
      "lines": [2]
    },
    "my_rule_python_clean": {
      "language": "python",
      "rule": "my_rule",
      "expect": "clean",
      "file": "clean/python/my_rule_clean.py",
      "target": "src/app.py"
    }
  }
}
```

| Field | Meaning |
|---|---|
| key | The case's name: lowercase letters, digits and `_`, unique. |
| `language`, `rule` | The rule tested, `<language>/<category>/<rule>.sca` of your folder. |
| `expect` | `detected`: the rule must flag the file; `clean`: it must not. |
| `file` | The case file, relative to `cases/`. Every file of `cases/vulnerable/` and `cases/clean/` must belong to a case. |
| `target` | Where the file is put in the test project: a path the scan reads as the rule's language (`src/app.py`, `Dockerfile`, `src/.github/workflows/ci.yml`). |
| `lines` | Optional, `detected` only: the finding must be on one of these lines. |
| `extra` | Optional: other files of the test project, `[{"file": "…", "target": "…"}]`, for a data flow that crosses files. |

```bash
codefixture-audit custom-rules test                  # every case
codefixture-audit custom-rules test python/my_rule   # the cases of one rule
```

Each failed case is named with its reason, then the counts. The exit code is 0 when every case passes, 1 when one fails, 2 when the registry is missing or does not hold together; `--json` prints the result as JSON. A rule without a case it must flag, or one it must not, is named after the counts.

To tune a rule on real code, run it on a project: every line it flags is printed (and the source of the data, for a data flow), without a report. The delivered rules of its language run beside it: a line one of them also flags is printed with that rule's name, since the report keeps the delivered finding there. They are read from `rules.cfpack` next to the executable, as for `scan`; `--rules <folder or pack>` reads others, and `--custom-rules-dir <folder>` reads your rules from another folder than `~/.codefixture-audit/custom-rules`. The project's `audit.config.json` paths apply. `custom-rules test` runs each case with its rule alone, so it does not name such lines.

```bash
codefixture-audit custom-rules try python/my_rule /path/to/project
```

## In the report

Every scan runs your rules with the delivered ones. The report labels their findings as yours, and its "Custom Rules" section lists each of your rules loaded, with its number of findings. When your rule and a delivered rule of the same category flag the same line, the report keeps the delivered rule's finding, which carries the catalog's texts and remediation, and leaves yours out there. The scan says so, once per pair of rules (`Your rule python/my_rule duplicates the delivered rule python/base64_eval on 2 line(s)`), and the card of your rule in the "Custom Rules" section names the delivered rule; the wizard warns when a delivered rule already searches the text you enter. Two rules of yours on one line are both kept.

## Examples

A pattern on one line, excluded when a safe argument is present in the
window:

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

A pattern that also needs a second element on the same line:

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

A data flow from an HTTP request to a language model call:

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

A condition on the whole file:

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
