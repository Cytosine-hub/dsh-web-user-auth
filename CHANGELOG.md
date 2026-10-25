# Changelog

## 0.9.0

- Map Token user-info roles to configured administrator roles with explicit, case-sensitive matching.
- Keep Token administrators on their own identity, sessions and workspaces, with independent local administrator recovery.
- Revoke sessions on administrator role changes; preserve Token expiry and cookie clearing.

## 0.8.0

- Add same-origin Token authentication from localStorage or sessionStorage, including JSON storage field extraction.
- Add user-info endpoint configuration, identity mapping, strict status/JSON/expiration rules, and periodic server validation.
- Bound Harness cookies to reported token expiration; revoke sessions and clear cookies when token validation fails.
- Watch browser token replacement/removal, preserving independent local administrator login.

## 0.7.2

First public release.

- Local, HTTP API and trusted-header user authentication with an independent local administrator.
- Native account management, user workspace roots, historical workspace ownership and per-user session access.
- Administrator and local-user password changes, password revocation, and server-side administrator recovery tools.
- Verified native-login handoff before disabling or uninstalling the authentication plugin.
- Native plugin management for trusted ordinary users, with authentication and core-plugin controls protected.
- Reject reserved internal administrator identities from external authentication and ordinary principals.
- Portable deployment documentation, MIT license, private vulnerability reporting instructions, and automated tests.
