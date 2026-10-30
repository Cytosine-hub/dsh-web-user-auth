# Changelog

## 0.9.1

- Ship an explicit, version/hash-checked Gateway repair tool for native approvals and user questions, including older approval-only repairs. No automatic Host mutation on plugin startup.
- Recheck session/control ownership both on interaction delivery and answers; keep administrator isolation, cancellation, stop and reconnect behavior.


- Add browser downloads to native delivery cards through their public slot; resolve only owned durable delivery coordinates and enforce user workspace boundaries, including administrator isolation and native byte limits.
- Admit only authenticated GET requests to the native desktop metadata route, so headless Hosts report unavailable instead of a metadata read error; desktop actions remain restricted.

- Resolve file RPC paths from the session workspace and validate byte-read base files and resolved targets, blocking cross-user symlink and base-file reads while retaining owned parent paths.
- Restrict the native reminder catalog to owned sessions and bind optional-service guards to their reload lifecycle; deny catalog access before its guard is ready and reject expired administrator identities at service guards.

- Allow authenticated users to read the opaque Office preview generation used by the native preview cache. Keep document rendering restricted to owned sessions and workspace paths.

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
