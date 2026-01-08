# GSIS for Keycloak: Production-ready Identity Provider & Advanced Reconciliation

**GSIS for Keycloak** is an extension providing delegated authentication through
the **Greek General Secretariat of Information Systems (GSIS / TAXISNet)** using OAuth 2.0 specification, which also implements an *optional* reconciliation process with an existing users repository.

It is fully compatible with **Keycloak 26.4+ (Quarkus)** and integrates natively with Keycloak's Identity
Brokering and Authentication Flow Mechanisms.

This extension is designed for Greek organizations that rely on GSIS OAuth 2.0 as an authentication method.

## What This Provider Delivers

### 🔐 GSIS OAuth 2.0 Identity Provider

An implementation of the official **GSIS TAXISNet OAuth 2.0 service**.

Key features:

- Secure user authentication via GSIS
- Automatic profile retrieval (TIN, full name, birth year, etc.)
- Smooth integration with Keycloak’s brokered identity model
- No custom scripting or manual configuration required

Just plug it in and authenticate your users through GSIS in minutes.

### 🛡️ Optional Reconciliation Authenticator

An authentication flow that ensures **only known users** (in Keycloak or LDAP) can authenticate through GSIS.

This authenticator provides:

1. Matching a GSIS *attribute* (e.g., `taxid`) against existing user records
2. Validating surname correctness with *normalization* and *word matching*
3. Blocking access when a user is not recognized or data does not match

This is essential for organizations that:

- Must restrict GSIS to approved user lists
- Use LDAP or existing centralized registries
- Need strong identity confirmation before granting access

### ⚡ Support for Keycloak's Feauture Transient Users

The provider is compatible with [**Keycloak’s Transient User**](https://github.com/keycloak/keycloak/blob/main/docs/transient-users.md) architecture without persisting their personal data locally and ensuring compliance with [Data Protection Impact Assessment (DPIA)](https://www.edps.europa.eu/data-protection-impact-assessment-dpia_en).

## Requirements & Credentials

To use GSIS OAuth 2.0, organizations must request access from the
**Interoperability Center (Κέντρο Διαλειτουργικότητας - ΚΕ.Δ)**.

GSIS will provide:

- `clientId`
- `clientSecret`

## Installation

### 1. Download

Grab the latest release from the GitHub [Releases page](https://github.com/gunet/keycloak-gsis-provider/releases).

### 2. Install

Copy the JAR to:

```bash
$KEYCLOAK_HOME/providers/
```

### 3. Build & Start Keycloak

```bash
kc.sh build
kc.sh start
```

After restart, Keycloak will display:

- **GsisTaxis** under `Identity Providers → Add provider`
- **GSIS Reconciliation Authenticator** under `Authentication → Flows → Add execution`

## Configuration Guide

### 🔑 Configure the Identity Provider

Navigate to `Identity Providers → Add provider → GsisTaxis`
and set:

- Client ID
- Client Secret
- Authorization, Token, User Info and Logout URLs of GSIS OAuth 2.0 Identity Provider
- (Optional) Alias and display name

You may configure attribute mappers using GSIS data fields:

| GSIS Field | Type    |
| ---------- | ------- |
| userid     | String  |
| taxid      | Integer |
| lastname   | String  |
| firstname  | String  |
| fathername | String  |
| mothername | String  |
| birthyear  | Integer |

You can use the following mappers to handle GSIS attributes:

- **Attribute Importer**: persists attributes directly on the user model
- **IDP Attribute to Session Note**: exposes attributes temporarily via session notes
- **Attributes to include**: comma-separated list of IDP attributes to store in session notes (e.g., `email, uid`)

The **IDP Attribute to Session Note** mapper stores each mapped attribute as a session note using the key format `idp_<ATTRIBUTE_NAME>`. These session notes can then be accessed by Client Services during authentication.

For example, mapping attribute **Attributes to include** with value `firstname, lastname` will produce the following session note:

```json
"idp_firstname": "Αλεξάνδρα",
"idp_lastname": "Δοκιμαστικός"
```

Leaving **Attributes to include** empty stores all external IDP attributes as session notes.

### 🛡️ Configure the Reconciliation Authenticator (Optional)

Use this configuration when GSIS login must be restricted to a pre-existing set of users.
This authenticator should be configured inside the **First login flow override** setting, found in the Identity Provider's Advanced settings.

#### Steps

1. In the Admin Console, navigate to `Authentication → Flows → Create flow`
2. Set a `Name` for the new basic flow (e.g., `Reconciliation Flow`)
3. Click `Add execution` and Add **Detect Existing LDAP User via External IDP**
4. Set the requirement to **REQUIRED**
5. Configure the desired Settings based on the explanations below
6. Navigate to `Identity providers → [Your Provider Name] → Advanced settings`
7. In the First login flow override option, select the flow you just created (e.g., Reconciliation Flow)

This is suitable for LDAP-backed organizations or deployments using transient users.

### 🧠 Reconciliation Settings Explained

#### Identification fields

- **External IDP Attribute**: GSIS attribute used for matching (e.g., `taxid`)
- **LDAP Search Attribute**: LDAP attribute used to search (e.g., `tin`, `uniqueCode`)
- **LDAP Search Pattern**: Template for searching structured identifiers with a PLACEHOLDER. If empty, the provider will search the exact value. For example, `urn:mace:example:org:{TIN_NUMBER}:GR` will result on replacing `{TIN_NUMBER}` with the value of `External IDP Attribute`. Final search will be `urn:mace:example:org:VALUE:GR`

#### Surname validation (optional but recommended)

Validation is only active when *both* `Validation: External IDP Attribute` and `Validation: LDAP Attribute` fields contain values. When validation is enabled, warning logs will be generated during the validation process.

- **Validation: External IDP Attribute**: GSIS attribute to compare (e.g., `lastname`)
- **Validation: LDAP Attribute**: LDAP attribute (e.g., `sn` or `last-name`)
- **Validation Threshold**: Allowed variation, how many differences it can accept. For example, with threshold `1`, external idp attribute `Παπαδόππουλος` and LDAP Attribute `Παπαδοπουλος` will be accepted.
- **Block Invalid Users**: When enabled, users failing validation will also fail authentication.
- **Allow NULL LDAP Attribute**: When enabled, users with NULL LDAP attribute will not fail authentication (requires `Block Invalid Users` to be enabled).

> [!NOTE]
> A mismatch beyond the configured threshold results in authentication failure.

## Build from Source

Clone this repository and run:

```bash
git clone https://github.com/gunet/keycloak-gsis-provider/
cd keycloak-gsis-provider
mvn clean package
```

The built JAR will appear under:

```bash
target/keycloak-gsis-provider-{version}.jar
```

## Related Work

Similar [implementation](https://github.com/cti-nts/keycloak-gsis-providers) for older Keycloak versions by [Greek School Network and Networking Technologies Directorate](https://github.com/cti-nts)

## License and Contributions

- License: Apache License, Version 2.0 (see the [LICENSE](LICENSE) file)
- [Contribution guidelines](CONTRIBUTING.md)
