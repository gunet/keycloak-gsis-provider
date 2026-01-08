# Security Policy

## Overview

The **GSIS for Keycloak Provider** is a security-sensitive component that integrates
the Greek General Secretariat of Information Systems (GSIS / TAXISNet) OAuth 2.0 service
into **Keycloak**.

This project is designed to operate in **high-assurance environments**, including
public-sector and institutional deployments within the European Union.

Security is treated as a **first-class concern** throughout the design and
implementation of this provider.

---

## Supported Versions

Only the **latest released version** of the provider is actively supported with
security updates.

Users are **strongly encouraged** to upgrade promptly when new releases are published,
especially when security fixes are involved.

---

## Vulnerability Reporting

### 🚨 Reporting a Security Issue

If you discover a **security vulnerability**, **do not open a public issue**.

Instead, report it **privately** using one of the following channels:

- GitHub **Security Advisories** (preferred)
- Direct contact with the maintainers via [**GUnet's Email**](mailto:info@gunet.gr)

Please include:

- A clear description of the issue
- Affected versions
- Steps to reproduce (if possible)
- Potential impact assessment

---

## Coordinated Disclosure

This project follows a **responsible / coordinated disclosure** process in line with
European best practices.

Upon receiving a valid report:

1. The issue will be triaged and validated
2. A fix will be developed privately
3. A security release will be published
4. A public advisory will be issued if appropriate

Reporters will be **credited** unless anonymity is requested.

---

## Dependency Security

- The provider relies primarily on **Keycloak-provided APIs**
- All Keycloak dependencies are marked as `provided`
- External libraries are kept minimal and reviewed
- Known vulnerable dependencies are updated as part of regular maintenance

Users should:

- Monitor CVEs for the underlying **Keycloak version**
- Apply Keycloak security patches promptly

---

## Configuration Security Recommendations

Operators are strongly advised to:

- Use **HTTPS** exclusively for all GSIS endpoints
- Protect `clientSecret` using Keycloak’s credential vault or equivalent
- Restrict GSIS provider usage to trusted authentication flows
- Enable reconciliation for environments requiring strong identity assurance
- Review logs for failed validations and suspicious authentication attempts

---

## Scope Limitations

This project:

- ❌ Does not replace Keycloak hardening
- ❌ Does not secure the GSIS OAuth service itself
- ❌ Does not manage network-level protections

Security of the overall system depends on:

- Keycloak configuration
- Infrastructure security
- Identity governance policies
- Proper operational monitoring

---

## Security Updates & Advisories

Security fixes will be:

- Released as **regular versions** or **out-of-band patches**
- Documented in the **GitHub Releases** page
- Clearly marked when they address security issues

---

## Acknowledgements

This project benefits from:

- The Keycloak security architecture
- Open-source community best practices
- Public-sector security expertise within the Greek research and education network

---

## Contact

For security matters related to this project, please use **private reporting channels**
as described above.

Public discussions of vulnerabilities **before a fix is available** are strongly discouraged.
