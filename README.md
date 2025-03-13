### SAML SSO with OKTA using Ruby

A minimal Ruby implementation of SAML Single Sign-On (SSO) with Okta as the Identity Provider (IdP).

## Prerequisites

- Ruby 3.0+
- Bundler
- An Okta developer account
- A configured SAML application in Okta

### Local Setup

1. Clone the repository
2. load env

```
   HOST=http://localhost:9292
   OKTA_DOMAIN=your-domain.okta.com
   OKTA_APP_PATH=app/your-app-path/sso/saml
```

3. Start the server (ie, run `puma`)
