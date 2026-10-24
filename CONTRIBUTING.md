# Contributing

Use Node.js 22 or 24 and Python 3. Tests use built-in modules and temporary directories, so they do not require access to a running Harness deployment or production credentials.

```sh
npm test
npm pack --ignore-scripts
```

The generated archive is the installable plugin bundle. Host integration still requires a compatible DeepSeek Harness installation; the peer dependency is supplied by the host.

For changes to authentication, test administrator and ordinary-user behavior separately, including rejected requests, cookie revocation, restart behavior, and preservation of user data. Never run integration tests against real users or include their data in fixtures.

Keep documentation independent of any particular deployment. Use example domains, replaceable paths and the `DSH_HOME` convention. Report security issues privately as described in SECURITY.md.
