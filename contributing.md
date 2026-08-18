# Contributing to the CQL Hub

Thanks for helping grow the collection! There are two ways to add a query. Both end up as a normal pull request in this repository that we review before it goes live on [byteray.com/cql-hub](https://www.byteray.com/cql-hub).

## Option 1: Submit via the website (recommended)

1. Open **[byteray.com/cql-hub-contribute](https://www.byteray.com/cql-hub-contribute)**.
2. Fill in the form: query name, description, the CQL itself, an explanation, tags, MITRE ATT&CK IDs, required log sources and Falcon modules, and your name / GitHub handle.
3. Submit.

What happens next: the submission is automatically turned into a `queries/<name>.yml` file in the correct format, validated, and opened as a pull request in this repository (labelled `community-submission`). If you gave a GitHub handle, the commit is attributed to you. We review the PR, may ask for changes there, and merge it, at which point the query appears on the site.

Your email address is used only to get in touch about the submission and is **not** published in the repository or the PR.

## Option 2: Submit via pull request

If you prefer working in git directly:

1. **Check for duplicates.** Browse `queries/` to see whether the same or a very similar query already exists. If it does, improve that one instead of adding a copy.
2. **Fork** this repository and create a branch.
3. **Add your query** as `queries/<Descriptive_Name>.yml`. Copy an existing file as a starting point, or use the structure below.
4. **Open a pull request.** Briefly describe what the query does, which MITRE techniques it relates to, and any caveats or limitations. The `Validate Queries` check runs automatically on your PR.

## Query file format

Every query is a single YAML file in `queries/`. Fields:

| Field | Required | Notes |
|---|---|---|
| `name` | yes | Human-readable title shown on the site |
| `cql` | yes | The query itself, as a `\|` block scalar (multi-line) |
| `description` | yes | One or two sentences on **what it detects**, shown as the summary on the site |
| `explanation` | recommended | The detail: what the query looks for, the telemetry/log sources it needs, expected false positives and how to tune it. Markdown is rendered on the site |
| `author` | recommended | Your name or team, this is how you get credit |
| `mitre_ids` | optional | List of technique IDs, e.g. `T1059.001` (must start with `T`) |
| `tags` | optional | List; allowed values: `Hunting`, `Monitoring`, `Detection` |
| `log_sources` | optional | List; allowed values: `Endpoint`, `Network`, `Identity`, `Cloud`, `Mail`, `Other` |
| `cs_required_modules` | optional | List; allowed values: `Insight`, `Identity`, `Spotlight`, `CSPM / ASPM / DSPM`, `Data Protection`, `IT Automation` |

Minimal example:

```yaml
name: New API Keys within the Falcon Platform

mitre_ids:
  - T1098.001

description: Detects the creation of new API clients in the Falcon platform.

author: Jane Doe

log_sources:
  - Other

tags:
  - Monitoring

cql: |
  #event.dataset = falcon.cloud
  | OperationName = CreateAPIClient
  | table([timestamp, Attributes.name, Attributes.APIClientID, UserId])

explanation: |
  **What it looks for:** `CreateAPIClient` audit events in `falcon.cloud`,
  i.e. every newly created API client together with its scopes and the user
  who created it.

  **Telemetry needed:** Falcon platform audit logs (`#event.dataset = falcon.cloud`)
  ingested into Next-Gen SIEM.

  **False positives / tuning:** Legitimate integrations and admins create API
  clients too. Exclude known service accounts on `UserId`, or alert only on
  clients with broad scopes.
```

The lists above are enforced by `.github/workflows/validate.yml`; a PR with an unknown tag, log source or module value will fail the check.

## Guidelines

- **Test it.** Run the query in your own Next-Gen SIEM before submitting. Broken logic or excessive false positives are the most common reasons we send a PR back.
- **Explain it.** `description` = what it detects, in a sentence or two. `explanation` = what the query looks for, which telemetry it needs, expected false positives and how to tune it. That split is what makes a query usable by someone who didn't write it.
- **Keep it readable.** Multi-line CQL with one pipe per line and inline comments where something isn't obvious.
- **Attribute yourself.** Fill in `author` (and your GitHub handle on the website form) so you're credited.
- **Improve, don't duplicate.** If a similar query exists, open a PR against that file instead.

## Questions

Open an issue in this repository or reach out via [byteray.com](https://www.byteray.com).
