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
   SP_ACS_URL=your-sp-acs-endpoint # shoud handle POST
   IDP_SSO_TARGET_URL=your-idp-sso-endpoint
   SP_ENTITY_ID=entity-id-of-issuer
```

3. Add IDp certificate to cart/okta_cert.pem

4. Start the server (ie, run `puma`)
