## How to Contribute

We welcome new queries and improvements to existing ones!

### Option 1: Submit directly via CQL Hub (Recommended)

1. **Create your query** using the online **[Contribute](https://cql-hub.com)** button on the top right.
2. **Submit it directly** — we'll review it and push it to the repository.

That's it! No need to fork, clone, or open a PR.

### Option 2: Submit via Pull Request

1. **Explore existing queries**
   - Browse the repo to check if your query (or a similar one) already exists.
   - If it does, consider enhancing it instead of duplicating.

2. **Create your query in the right format**
   - Use the **[Contribute](https://cql-hub.com)** button to create a `.yml` file in the correct format.
   - This ensures consistency across all queries in the repository.

3. **Add your query to the repo**
   - Fork this repository.
   - Add your new `.yml` file under the appropriate directory.
   - Make sure the file name is descriptive and aligned with the use case.

4. **Submit a Pull Request**
   - Open a PR with your changes.
   - Provide a short description of the query, including:
     - The purpose of the query (e.g., detection of suspicious PowerShell activity).
     - Related MITRE ATT&CK techniques, if applicable.
     - Any limitations or known caveats.

---

## Guidelines for Queries

- **Clarity**: Keep queries well-documented and include comments where necessary.
- **Consistency**: Use the YAML structure from the **CQL Hub builder**.
- **Quality**: Queries should be tested before submission to avoid false positives or broken logic.
- **Attribution**: Add yourself as the author in the YAML metadata so contributors get credit.
