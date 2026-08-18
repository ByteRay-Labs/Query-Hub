"""Validate one query YAML with the same rules as .github/workflows/validate.yml."""
import sys
import yaml

VALID_LOG_SOURCES = ['Endpoint', 'Network', 'Identity', 'Cloud', 'Mail', 'Other']
VALID_TAGS = ['Hunting', 'Monitoring', 'Detection']
VALID_MODULES = ['Insight', 'Identity', 'Spotlight', 'CSPM / ASPM / DSPM', 'Data Protection', 'IT Automation']

path = sys.argv[1]
data = yaml.safe_load(open(path, encoding="utf-8"))
errors = []

for f in ('name', 'cql'):
    if not isinstance(data.get(f), str) or not data[f].strip():
        errors.append(f"'{f}' is required and must be a non-empty string")

for f in ('description', 'author', 'explanation'):
    if f in data and data[f] is not None and not isinstance(data[f], str):
        errors.append(f"'{f}' must be a string")

def check_list(field, allowed=None):
    if field not in data or data[field] is None:
        return
    v = data[field]
    if not isinstance(v, list) or not v:
        errors.append(f"'{field}' must be a non-empty list")
        return
    for item in v:
        if not isinstance(item, str):
            errors.append(f"'{field}' contains a non-string item")
        elif allowed and item not in allowed:
            errors.append(f"'{field}' has invalid value '{item}' (allowed: {allowed})")

check_list('log_sources', VALID_LOG_SOURCES)
check_list('tags', VALID_TAGS)
check_list('cs_required_modules', VALID_MODULES)
check_list('mitre_ids')
for m in data.get('mitre_ids') or []:
    if isinstance(m, str) and not m.startswith('T'):
        errors.append(f"invalid MITRE ID '{m}' (must start with T)")

if errors:
    print(f"❌ {path}")
    for e in errors:
        print("   -", e)
    sys.exit(1)
print(f"✅ {path} is valid")
