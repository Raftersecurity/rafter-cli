# Rafter Badges

Static badges you can add to your project README to show that your repo is scanned by Rafter.

## Available Badges

### "Scanned by Rafter"

![Scanned by Rafter](https://img.shields.io/badge/scanned_by-Rafter-2ea44f?logo=data:image/svg+xml;base64,&logoColor=white)

### "Rafter Policy: Enforced"

![Rafter policy: enforced](https://img.shields.io/badge/rafter_policy-enforced-2ea44f)

### "Rafter Policy: Moderate"

![Rafter policy: moderate](https://img.shields.io/badge/rafter_policy-moderate-blue)

### "Secrets: Clean"

![Secrets: clean](https://img.shields.io/badge/secrets-clean-2ea44f)

## Usage

Pick a badge and copy the snippet for your preferred format.

### Scanned by Rafter

**Markdown:**

```markdown
[![Scanned by Rafter](https://img.shields.io/badge/scanned_by-Rafter-2ea44f)](https://github.com/raftercli/rafter)
```

**HTML:**

```html
<a href="https://github.com/raftercli/rafter">
  <img src="https://img.shields.io/badge/scanned_by-Rafter-2ea44f" alt="Scanned by Rafter">
</a>
```

**reStructuredText:**

```rst
.. image:: https://img.shields.io/badge/scanned_by-Rafter-2ea44f
   :target: https://github.com/raftercli/rafter
   :alt: Scanned by Rafter
```

### Rafter Policy: Enforced

**Markdown:**

```markdown
[![Rafter policy: enforced](https://img.shields.io/badge/rafter_policy-enforced-2ea44f)](https://github.com/raftercli/rafter)
```

**HTML:**

```html
<a href="https://github.com/raftercli/rafter">
  <img src="https://img.shields.io/badge/rafter_policy-enforced-2ea44f" alt="Rafter policy: enforced">
</a>
```

**reStructuredText:**

```rst
.. image:: https://img.shields.io/badge/rafter_policy-enforced-2ea44f
   :target: https://github.com/raftercli/rafter
   :alt: Rafter policy: enforced
```

### Rafter Policy: Moderate

**Markdown:**

```markdown
[![Rafter policy: moderate](https://img.shields.io/badge/rafter_policy-moderate-blue)](https://github.com/raftercli/rafter)
```

**HTML:**

```html
<a href="https://github.com/raftercli/rafter">
  <img src="https://img.shields.io/badge/rafter_policy-moderate-blue" alt="Rafter policy: moderate">
</a>
```

**reStructuredText:**

```rst
.. image:: https://img.shields.io/badge/rafter_policy-moderate-blue
   :target: https://github.com/raftercli/rafter
   :alt: Rafter policy: moderate
```

### Secrets: Clean

**Markdown:**

```markdown
[![Secrets: clean](https://img.shields.io/badge/secrets-clean-2ea44f)](https://github.com/raftercli/rafter)
```

**HTML:**

```html
<a href="https://github.com/raftercli/rafter">
  <img src="https://img.shields.io/badge/secrets-clean-2ea44f" alt="Secrets: clean">
</a>
```

**reStructuredText:**

```rst
.. image:: https://img.shields.io/badge/secrets-clean-2ea44f
   :target: https://github.com/raftercli/rafter
   :alt: Secrets: clean
```

## Color Reference

| Badge | Hex | Use |
|-------|-----|-----|
| Green (`2ea44f`) | Rafter brand green | Scanned, enforced, clean |
| Blue (`blue`) | Shields.io default blue | Moderate policy, informational |

## Notes

These are static badges powered by [Shields.io](https://shields.io). They do not query a live API -- they simply indicate that your project uses Rafter for security scanning.

For CI status badges that reflect actual scan results, use your CI provider's native badge (e.g., GitHub Actions workflow status badge) on the workflow that runs `rafter scan local`.
