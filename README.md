# CodeQL Model Editor Demo — Python

> **Training demo:** This repo shows how to use the CodeQL Model Editor to teach CodeQL about frameworks it doesn't recognize. Walk through the sections below in order during your demo.

---

## The problem we're solving

CodeQL finds vulnerabilities by tracing data from **sources** (where user input enters) through **summaries** (functions that pass data along) to **sinks** (where dangerous operations happen):

```
SOURCE ──────────► SUMMARY ──────────► SINK
(user input)       (transforms data    (dangerous operation:
                    but preserves       SQL query, shell cmd,
                    taint)              file read, etc.)
```

CodeQL ships with models for hundreds of popular frameworks — Flask, Django, SQLAlchemy, etc. **But when your code uses a framework CodeQL has never seen, it can't trace anything.** No model = no findings.

This demo uses a **fictional framework called "QuickAPI"** (in the `quickapi/` folder) to simulate that exact scenario. The app has 9 obvious security bugs, but CodeQL finds **zero** of them out of the box.

---

## What's in this repo

```
model-editor-demo/
│
├── quickapi/                              ← The fictional "unsupported" framework
│   ├── request.py                         SOURCES  — methods that return user input
│   ├── database.py                        SINKS    — methods that run SQL queries
│   ├── templating.py                      SINKS    — methods that render HTML (no escaping)
│   ├── security.py                        MIXED    — auth (sources) + system ops (sinks)
│   └── utils.py                           SUMMARIES — transform data, preserve taint
│
├── app/
│   ├── main.py                            App entry point & route wiring
│   └── views.py                           ★ 9 intentional vulnerabilities ★
│
└── README.md                              ← You are here
```

---

## Key concepts to explain

Before opening VS Code, make sure the audience understands these three ideas:

| Concept | Plain English | Example from this demo |
|---------|--------------|----------------------|
| **Source** | "This method returns data an attacker controls" | `request.get_query_param("name")` — the user typed that value into the URL |
| **Sink** | "This method does something dangerous with its argument" | `db.execute_query(sql)` — runs whatever SQL string you give it |
| **Summary** | "This function's output is derived from its input — taint passes through" | `Sanitizer.strip_tags(x)` — removes HTML tags but returns a modified version of `x` |

**For frameworks CodeQL already knows** (Flask, Django, etc.) these are built in. For QuickAPI, **none exist** — that's the gap we'll fill.

---

## Demo walkthrough

### Pre-work: Build the CodeQL database

```bash
cd /path/to/quick-api
codeql database create codeql-db --language=python --source-root=.
```

---

### Part 1: Show the vulnerability (2 min)

> **Goal:** The audience should be able to see the bug with their own eyes.

Open `app/views.py` and show the `search_users` function:

```python
def search_users(request: Request, db: DatabaseConnection) -> JSONResponse:
    name = request.get_query_param("name")                          # ← user input
    query = f"SELECT * FROM users WHERE username LIKE '%{name}%'"   # ← string concat
    results = db.execute_query(query)                                # ← runs SQL
    return JSONResponse({"users": results})
```

**Ask the audience:** *"Can you see the SQL injection here?"* — everyone will.

---

### Part 2: Show that CodeQL finds nothing (3 min)

> **Goal:** Establish that CodeQL misses this despite it being obvious.

**In VS Code:**
1. Open the CodeQL database (CodeQL sidebar → **From a folder** → select `codeql-db`)
2. Run the `python-security-and-quality` query suite

**Or from the CLI:**
```bash
codeql database analyze codeql-db \
  --format=sarif-latest \
  --output=baseline-results.sarif \
  -- python-security-and-quality
```

3. **Result: 0 security findings**

**Explain why:**
- CodeQL doesn't know `request.get_query_param()` returns user-controlled data → **no source**
- CodeQL doesn't know `db.execute_query()` runs SQL → **no sink**
- With neither end of the taint path defined, there's nothing to trace

> *"CodeQL's analysis is correct — it ran SQL injection queries, command injection queries, XSS queries, all of them. It just doesn't have the vocabulary to understand this particular framework."*

---

### Part 3: Model a source + sink (10 min)

> **Goal:** Show the Model Editor and make the first finding appear.

#### Open the Model Editor

1. In the CodeQL sidebar, make sure the database is selected
2. Open the **CodeQL Method Modeling** panel
3. Click **"Start modeling"** (or run command `CodeQL: Open Model Editor (Beta)`)
4. Wait for the telemetry queries to finish — the editor lists all external APIs

#### Model the source: `Request.get_query_param()`

Find `quickapi` in the list and expand it. Locate `get_query_param` and set:

| Field | Value |
|-------|-------|
| **Model Type** | `Source` |
| **Output** | `ReturnValue` |
| **Kind** | `remote` |

> *"We're telling CodeQL: when this method is called, its return value contains data from a remote attacker."*

#### Model the sink: `DatabaseConnection.execute_query()`

Locate `execute_query` and set:

| Field | Value |
|-------|-------|
| **Model Type** | `Sink` |
| **Input** | `Argument[0]` |
| **Kind** | `sql-injection` |

> *"We're telling CodeQL: the first argument to this method is used in a SQL query — if it's tainted, that's SQL injection."*

#### Save and re-run

1. Click **Save all** in the model editor — models are saved to `.github/codeql/extensions/`

**In VS Code:**
2. Set `"codeQL.runningQueries.useExtensionPacks": "all"` in your VS Code settings
3. Re-run the `python-security-and-quality` query suite

**Or from the CLI:**

The Model Editor saves models to `.github/codeql/extensions/<database-name>-<language>/`.
For our database named `codeql-db`, the auto-generated pack is `pack/codeql-db-python`.

```bash
codeql database analyze codeql-db \
  --format=sarif-latest \
  --output=after-modeling-results.sarif \
  --additional-packs=.github/codeql/extensions/ \
  --model-packs=pack/codeql-db-python \
  -- python-security-and-quality
```

**Result: SQL injection in `search_users` is now detected!**

> *"We added two models — one source and one sink — and CodeQL can now trace the taint from `get_query_param()` through the f-string into `execute_query()`. That's the core idea."*

---

### Part 4: Model a summary (5 min)

> **Goal:** Show that some vulnerabilities need summaries to bridge a gap in the taint chain.

Open `app/views.py` and show the `update_profile` function:

```python
def update_profile(request: Request, db: DatabaseConnection) -> JSONResponse:
    body = request.get_json_body()
    new_bio = body.get("bio", "")

    cleaned_bio = Sanitizer.strip_tags(new_bio)     # ← developer thinks this helps

    user_id = request.get_query_param("user_id")
    sql = f"UPDATE users SET bio = '{cleaned_bio}' WHERE id = {user_id}"
    db.execute_update(sql)                           # ← still SQL injection!
```

**Explain:** *"The developer called `strip_tags()` thinking it would sanitize the input. It removes HTML tags, but does nothing about SQL metacharacters like `'` or `;`. The SQL injection is still there. But even with our source and sink models, CodeQL won't find it — because taint stops at `strip_tags()`. CodeQL doesn't know the output is derived from the input."*

#### Model the summary: `Sanitizer.strip_tags()`

| Field | Value |
|-------|-------|
| **Model Type** | `Flow summary` |
| **Input** | `Argument[0]` |
| **Output** | `ReturnValue` |
| **Kind** | `taint` |

> *"We're telling CodeQL: whatever goes into `strip_tags` affects what comes out — taint flows through."*

Also model `execute_update` as a sink (same as `execute_query` — Kind: `sql-injection`), then save and re-run (same CLI command as Part 3).

**Result: The SQL injection in `update_profile` is now detected!**

---

### Part 5: Model the rest (optional hands-on, 10 min)

If time allows, let the audience model the remaining APIs themselves. Here's the complete list:

#### All sources (Model Type: Source, Output: ReturnValue, Kind: remote)

| Method | Notes |
|--------|-------|
| `Request.get_query_param()` | ✅ Done in Part 3 |
| `Request.get_all_query_params()` | |
| `Request.get_header()` | |
| `Request.get_json_body()` | |
| `Request.get_raw_body()` | |
| `Request.get_form_field()` | |
| `Request.get_cookie()` | |
| `Request.get_uploaded_filename()` | |
| `TokenValidator.decode_token()` | Returns user-controlled claims from a JWT |
| `TokenValidator.get_user_id()` | |

#### All sinks (Model Type: Sink)

| Method | Input | Kind |
|--------|-------|------|
| `DatabaseConnection.execute_query()` | `Argument[0]` | `sql-injection` |
| `DatabaseConnection.execute_update()` | `Argument[0]` | `sql-injection` |
| `DatabaseConnection.execute_raw()` | `Argument[0]` | `sql-injection` |
| `SystemHelper.run_command()` | `Argument[0]` | `command-injection` |
| `SystemHelper.ping_host()` | `Argument[0]` | `command-injection` |
| `SystemHelper.read_file()` | `Argument[0]` | `path-injection` |
| `SystemHelper.write_log()` | `Argument[1]` ⚠️ | `log-injection` |
| `TemplateEngine.render_string()` | `Argument[0]` | `html-injection` |
| `Response.redirect()` | `Argument[0]` | `url-redirection` |

> ⚠️ Note: `write_log(logfile, message)` — the sink is the **second** argument (the message), not the first.

#### All summaries (Model Type: Flow summary, Kind: taint)

| Method | Input | Output |
|--------|-------|--------|
| `Sanitizer.strip_tags()` | `Argument[0]` | `ReturnValue` |
| `Sanitizer.truncate()` | `Argument[0]` | `ReturnValue` |
| `Sanitizer.to_lowercase()` | `Argument[0]` | `ReturnValue` |
| `DataTransformer.to_json()` | `Argument[0]` | `ReturnValue` |
| `DataTransformer.from_json()` | `Argument[0]` | `ReturnValue` |
| `DataTransformer.format_string()` | `Argument[0]` | `ReturnValue` |
| `DataTransformer.join_strings()` | `Argument[0]` | `ReturnValue` |

#### Answer key

The complete model file is at:
```
.github/codeql/extensions/model-editor-demo-python/models/quickapi-complete-reference.model.yml
```

---

## All 9 vulnerabilities

After modeling everything, CodeQL should detect all of these:

| # | Vulnerability | Taint path | What needs to be modeled |
|---|--------------|-----------|------------------------|
| 1 | **SQL Injection** | `get_query_param()` → f-string → `execute_query()` | source + sink |
| 2 | **SQL Injection (builder)** | `get_query_param()` → `where_raw()` → `build()` → `execute_query()` | source + sink + summary |
| 3 | **Reflected XSS** | `get_query_param()` → `render_string()` | source + sink |
| 4 | **Command Injection** | `get_query_param()` → `ping_host()` | source + sink |
| 5 | **Path Traversal** | `get_query_param()` → `read_file()` | source + sink |
| 6 | **SQL Injection (sanitizer bypass)** | `get_json_body()` → `strip_tags()` → `execute_update()` | source + sink + summary |
| 7 | **SQL Injection (JWT claims)** | `get_header()` → `decode_token()` → `execute_query()` | source + source + sink |
| 8 | **Command Injection (transformer)** | `get_query_param()` → `format_string()` → `run_command()` | source + sink + summary |
| 9 | **Log Injection** | `get_query_param()` → `write_log()` | source + sink |

---

## Key takeaways for your audience

1. **CodeQL's detection is only as good as its models.** If it misses something, it might not be a bug — it might be a missing model.
2. **The Model Editor lets you fill that gap without writing any QL.** You get a GUI that auto-discovers APIs and lets you classify them as sources, sinks, or summaries.
3. **Models are just YAML files.** They're stored in `.github/codeql/extensions/` and can be committed to your repo so the whole team benefits.
4. **Summaries matter.** Even with perfect sources and sinks, taint can "die" at an intermediate function call if CodeQL doesn't know the output is derived from the input.

---

## YAML model format reference

The Model Editor generates YAML in this format. You can also write it by hand:

```yaml
extensions:
  # Source: marks return values as user-controlled
  - addsTo:
      pack: codeql/python-all
      extensible: sourceModel
    data:
      - ["quickapi.request.Request", "Member[get_query_param].ReturnValue", "remote"]

  # Sink: marks arguments as security-sensitive
  - addsTo:
      pack: codeql/python-all
      extensible: sinkModel
    data:
      - ["quickapi.database.DatabaseConnection", "Member[execute_query].Argument[0]", "sql-injection"]

  # Summary: marks taint flow through a function
  - addsTo:
      pack: codeql/python-all
      extensible: summaryModel
    data:
      - ["quickapi.security.Sanitizer!", "Member[strip_tags]", "Argument[0]", "ReturnValue", "taint"]
```

> **Note:** The `!` suffix on `Sanitizer!` means "the class itself" (for static methods) rather than "instances of the class."

---

## Further reading

- [Using the CodeQL Model Editor](https://docs.github.com/en/code-security/how-tos/scan-code-for-vulnerabilities/scan-from-vs-code/using-the-codeql-model-editor)
- [Customizing Library Models for Python](https://codeql.github.com/docs/codeql-language-guides/customizing-library-models-for-python/)
- [Creating and working with CodeQL packs](https://docs.github.com/en/code-security/codeql-cli/using-the-advanced-functionality-of-the-codeql-cli/creating-and-working-with-codeql-packs)
