## Summary

Brief description of what this PR does and why.

## Type of change

- [ ] Bug fix
- [ ] New profile
- [ ] New protocol
- [ ] New CLI flag or feature
- [ ] Documentation update
- [ ] CI / tooling change

## Checklist

- [ ] `cargo fmt` — code is formatted (`cargo fmt --check` passes)
- [ ] `cargo clippy -- -D warnings` — no clippy warnings
- [ ] `cargo test` — all tests pass
- [ ] New behaviour is covered by a test (or explain why not below)
- [ ] Documentation updated if CLI flags, config format, or profile behaviour changed
- [ ] Default targets point to loopback or RFC 1918 addresses only (no external infrastructure)

## Testing done

Describe how you tested this change. Include the command(s) you ran and what you observed.

```bash
# Example
echos --profile MyNewProfile --count 3 --dry-run
```

## Related issues

Closes # (if applicable)
