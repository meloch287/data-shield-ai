# Cookbook

Practical recipes. Every snippet uses only the standard library plus
`data-shield-ai` and is runnable as-is.

## Mask a prompt before calling any LLM

```python
from datashield import redact

def safe_prompt(user_text: str) -> str:
    return redact(user_text).masked_text

# send safe_prompt(...) to the model instead of the raw text
```

## Reversible round-trip (un-mask the model's answer)

```python
from datashield import redact, restore

r = redact("Email john@acme.com about card 4111 1111 1111 1111", reversible=True)
masked = r.masked_text                      # send this to the model
answer = call_model(masked)                 # model replies using the placeholders
final = restore(answer, r.vault)            # put the real values back
```

## OpenAI / LiteLLM proxy pattern

Wrap the client so every outgoing message is masked:

```python
from datashield import redact

def masking_chat(client, messages, **kw):
    masked = [{**m, "content": redact(m["content"]).masked_text} for m in messages]
    return client.chat.completions.create(messages=masked, **kw)
```

For a fully reversible proxy, keep a per-request vault and `restore()` the reply.

## LangChain

```python
from datashield import redact

def redact_input(inputs: dict) -> dict:
    return {k: (redact(v).masked_text if isinstance(v, str) else v)
            for k, v in inputs.items()}

# chain = RunnableLambda(redact_input) | prompt | llm
```

## MCP server (any agent)

Register the MCP server so an agent can call `redact`/`scan` as tools:

```json
{
  "mcpServers": {
    "data-shield-ai": { "command": "datashield-mcp" }
  }
}
```

## Mask data in application logs

```python
import logging
from datashield.integrations.logging_filter import RedactingFilter

logging.getLogger().addFilter(RedactingFilter())
logging.info("user %s paid with %s", "a@b.com", "4111 1111 1111 1111")
# -> user [EMAIL_1] paid with [CREDIT_CARD_1]
```

## Block secrets in CI / pre-commit

`.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/meloch287/data-shield-ai
    rev: v1.11.0
    hooks: [{ id: data-shield-ai }]
```

Or in any CI step: `datashield check $(git ls-files) --min-severity high`.

## Redact structured data without breaking it

```python
from datashield import redact_json

print(redact_json('{"user":{"name":"John Smith","password":"x","age":30}}'))
# {
#   "user": {
#     "name": "[PERSON_1]",      # detected as a person (full name)
#     "password": "[REDACTED]",  # masked by sensitive key, regardless of value
#     "age": 30                  # non-string scalars are preserved
#   }
# }
```

Values are redacted two ways: by **detector** (the name) and by **sensitive
key** (`password`, `token`, `ssn`, …). A bare first name with no context
(`"Ivan"` alone) is intentionally *not* detected — enable `names_aggressive`
or rely on the key-based path for fields like `"first_name"`.

## Compliance presets

```bash
datashield redact --preset pci-dss   < tx.log     # cards + secrets only
datashield redact --preset hipaa     < notes.txt  # health + identity + contact
datashield redact --min-severity critical < x.txt # only the most sensitive
```

## Add your own detector (no fork needed)

Inline via config (`.datashield.json`):

```json
{ "custom_patterns": [
    {"name": "employee_id", "type": "EMPLOYEE_ID", "pattern": "EMP-\\d{6}", "confidence": 0.9}
] }
```

Or ship a package that registers an entry point in group
`datashield.detectors` (a zero-arg callable returning a list of detectors).

## Huge files and batches

```bash
datashield redact --stream --in big.log --out big.masked   # constant memory
datashield batch logs/*.txt --out-dir masked/ --workers 8   # parallel
```
