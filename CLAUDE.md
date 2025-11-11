# Mumbojumbo Project Guidelines

## CRITICAL: Project Architecture Constraints

### Single-File Implementation
**mumbojumbo.py MUST remain a single file.** Do not split functionality into multiple modules or files. This is a core design principle for simplicity, portability, and ease of deployment.

### Library Dependencies
**Be VERY restrictive on adding new libraries.** Only use Python standard library unless absolutely necessary. Every new dependency:
- Increases attack surface
- Complicates deployment
- Reduces portability
- Must be strongly justified

### Code Philosophy
- **Do NOT overgeneralize** - Keep implementations specific and practical
- **Compact and effective** - Every line should have clear purpose
- **Fool-proof** - Design for reliability and error prevention
- **Robust** - Handle edge cases and failures gracefully
- **Full test coverage** - All functionality must be tested

## Domain-Key Variable

The project uses a **domain-key** concept for maximum simplicity in client configuration:

### Format
```
<server-pubkey-alphanumeric>.<configured-domain>
```

### Purpose
This single string contains everything a client needs:
- **Server public key** (encoded as alphanumeric subdomain)
- **Domain destination** (the actual domain to connect to)

### Example
```
a1b2c3d4e5f6g7h8.example.com
```

Where:
- `a1b2c3d4e5f6g7h8` = base32/base64url encoded server public key
- `example.com` = configured domain from server config

### Benefits
- **One copy-paste configuration** - Client only needs this single string
- **Embedded authentication** - Public key is part of the address
- **No separate key distribution** - Key and domain are unified
- **Simple UX** - Users can't misconfigure domain vs key mismatch

## Development Workflow

### Before Making Changes
1. Run `pwd` to confirm working directory
2. Read relevant tests to understand current behavior
3. Consider impact on single-file constraint

### After Making Changes
1. Run full test suite: `python -m pytest`
2. Verify test coverage remains 100%
3. Check no new dependencies added
4. Ensure code remains compact and readable

## Code Style
- Use Python standard library idioms
- Keep functions focused and testable
- Prefer explicit over implicit
- Comment only what's non-obvious
- Use type hints where they add clarity

## Testing Requirements
- **100% test coverage** mandatory
- Test happy paths AND edge cases
- Test error conditions and recovery
- Use pytest for all tests
- Mock external dependencies (network, filesystem)

## Security Considerations
- Validate all inputs
- Use constant-time comparisons for crypto
- Clear sensitive data when done
- Assume hostile network environment
- Log security-relevant events

## When in Doubt
- Keep it simple
- Keep it in one file
- Keep dependencies minimal
- Keep tests comprehensive
- Keep the domain-key concept central to UX
