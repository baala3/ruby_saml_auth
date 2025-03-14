### SAML SSO with OKTA using Ruby

A minimal Ruby implementation of SAML Single Sign-On (SSO) with Okta as the Identity Provider (IdP).

## Prerequisites

- Ruby 3.0+
- Bundler
- An Okta developer account
- A configured SAML application in Okta

### Local Setup

1. Clone the repository
2. set `IDP_SSO_TARGET_URL` (of any IDp okta/azure_ad)
3. Add `IDP certificate` to `cert/okta_cert.pem`
4. Start the server using puma-dev (i.e, run `make run`)
