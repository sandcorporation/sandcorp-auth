"""Resource-server side of Sandcorp auth. Modules: `tokens` (access-token validation, JWKS
cache), `resource` (RFC 9728 metadata, WWW-Authenticate), `login` (operator login),
`testing` (fakes for the sites' suites) and `django` (bearer auth for Django and
django-ninja; needs the `[django]` extra). See README.md."""

__version__ = "0.2.0"
