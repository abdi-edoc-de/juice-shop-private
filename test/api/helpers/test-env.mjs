process.env.NODE_ENV = 'test'
// Allows the SSRF protection of outgoing requests (see lib/ssrfGuard.ts) to reach local mock servers
process.env.SSRF_ALLOWED_PRIVATE_HOSTS = 'localhost,127.0.0.1'
