- **CLM001** (high): Claim asserted in documentation without code evidence
- **CLM002** (high): Documentation claim contradicted by code evidence
- **CLM003** (medium): Claim only partly implemented with missing controls
- **CLM004** (high): Fake implementation: non-test function ignores parameters 
and returns literals
- **DEP001** (critical): Dependency not found on official registry 
(hallucinated package)
- **DEP002** (high): Dependency typosquatting of popular package
- **DEP003** (medium): Brand-new single-release dependency with no source 
repository
- **DEP004** (medium): Imported package not declared in project manifest
- **DEP005** (low): Declared dependency is never imported in codebase
- **DEP006** (low): Unpinned, latest, or wildcard dependency version without 
lockfile
- **DEP007** (medium): Cross-ecosystem package name confusion
- **GAP001** (medium): Unresolved TODO, FIXME, HACK, or XXX
- **GAP002** (medium): Unimplemented stub function or method
- **GAP003** (medium): Skipped, empty, or unasserted test
- **GAP004** (low): Untested production module
- **GAP005** (medium): Unregistered handler or unreferenced export
- **GAP006** (low): Undocumented environment variable
- **GAP007** (low): Broken relative documentation link
- **GAP008** (low): Missing repository baseline hygiene
- **GAP009** (low): Suppression without mandatory reason
- **SEC001** (critical): Hardcoded secret or authentication credential
- **SEC002** (high): Dynamic code or command execution with non-literal input
- **SEC003** (high): SQL statement constructed via string concatenation or 
interpolation
- **SEC004** (high): Unsafe deserialization of untrusted data
- **SEC005** (high): TLS certificate verification disabled
- **SEC006** (medium): Weak cryptographic primitive or insecure random 
generator
- **SEC007** (medium): Overly permissive CORS policy or production debug mode
- **SEC008** (medium): Route handler with no nearby authorization guard
- **SEC009** (high): Outbound request using user-controlled URL without 
allowlist (SSRF)
- **SEC010** (medium): State-changing route without CSRF or tenant ownership 
validation
- **SEC011** (low): Public web application without rate limiting or security 
headers
- **SEC012** (medium): Dockerfile root user, unpinned base image, or 
pipe-to-shell
- **SEC013** (high): GitHub Actions pull_request_target with PR checkout or 
unpinned actions
- **SEC014** (medium): Prompt-injection instruction or hidden directional 
unicode in agent-read file
- **SEC015** (medium): Over-permissive agent or MCP configuration
- **SLP001** (medium): Swallowed exception or empty catch block
- **SLP002** (high): Mock or placeholder data in production path
- **SLP003** (low): Tautological comment restating code name
- **SLP004** (low): Unreferenced dead code or commented-out code block
- **SLP005** (low): Near-duplicate functions
- **SLP006** (low): Redundant passthrough wrapper
- **SLP007** (low): Debug leftover in production code
- **SLP008** (low): Type escape hatch without reason
- **SLP009** (low): Oversized or cyclomatically complex function
- **SLP010** (low): Conflicting identifier naming stems
