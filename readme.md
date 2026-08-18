# CQL Hub | CrowdStrike Next-Gen SIEM & LogScale Queries

This repository is the source for the [**CQL Hub**](https://www.byteray.com/cql-hub): a **free, community-driven collection** of **CrowdStrike Falcon Next-Gen SIEM / LogScale queries** maintained by [ByteRay](https://www.byteray.com).

Every query in `queries/` is published on the CQL Hub website, where you can browse, search and filter them, and open them directly in Falcon.

---

## About

- **Community-first**: Contributions from security practitioners worldwide, reviewed before they go live.
- **Free & open**: All queries are open source (MIT) and free to use, share and adapt.
- **Structured & Searchable**: Each query is a YAML file with metadata (MITRE ATT&CK IDs, tags, log sources, required Falcon modules), which is what makes filtering on the [CQL Hub](https://www.byteray.com/cql-hub) possible.

## How to use

1. Browse and search the queries on the [**CQL Hub**](https://www.byteray.com/cql-hub).
2. Copy the CQL into Next-Gen SIEM, or pick your Falcon region and use **Run Query in Falcon**.

## Repository layout

| Path | Contents |
|---|---|
| `queries/` | One `.yml` per query, see [contributing.md](contributing.md) for the format |
| `lookup-files/` | CSV lookup files referenced by some queries (cloud provider IP ranges, known-bad package lists, etc.) |
| `.github/` | Query validation and the automation that turns website submissions into pull requests |

## Contributing

We welcome new queries and improvements to existing ones.

- **Easiest:** Submit via the [**Contribute form**](https://www.byteray.com/cql-hub-contribute). Your submission is automatically converted into a correctly formatted query file, validated and opened as a pull request here for review, no git required.
- **Or** fork this repository and open a pull request with a new `queries/<name>.yml`.

Details, the YAML format and the allowed field values are in the [Contributing Guide](contributing.md). Once a PR is merged, the query appears on the CQL Hub.

## License

Released under the **MIT License**. All queries are free to use, share and adapt — attribution is appreciated.
