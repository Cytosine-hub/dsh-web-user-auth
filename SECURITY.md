# Security

## Scope and trust model

This plugin provides application-level authentication and per-user session/workspace filtering. It is not an operating-system sandbox.

- Ordinary users can manage other plugins for the entire Harness instance. Installing a plugin loads server-side code. Only grant access to trusted users.
- Bash, tools and plugins running under the same system account can potentially access that account's files, including credentials. Use separate system accounts or containers to isolate untrusted tenants.
- Header authentication requires a trusted proxy that overwrites identity and shared-secret headers. Prevent clients from reaching the upstream directly.
- Safe deactivation transfers the browser to native Harness administrator access, which covers the entire instance. It requires explicit administrator confirmation and a verified native cookie.
- Token authentication accepts only an administrator-configured same-origin user-info endpoint. Raw tokens remain in browser storage and server memory, never in signed cookies or configuration. All same-origin scripts must be trusted. Upstream revocation detection is bounded by the configured polling interval plus request timeout; offline browsers receive cookie deletion on their next request.
- Keep the Harness data directory, backups, initial passwords, launch links and signing secrets private. Never commit runtime data or include it in releases.
- Use a compatible Harness version; the currently verified host is documented in the README. Recheck authentication and isolation when upgrading the host.

## Reporting a vulnerability

Use this repository's **Security → Report a vulnerability** flow for private reports. Include affected versions, a minimal reproduction using test accounts, and the expected security boundary. Do not publish production tokens, passwords, signing keys or personal session contents in issues or pull requests.

If private reporting is temporarily unavailable, open an issue requesting a private reporting channel without including exploit details or secrets.
