### SAML SSO with OKTA using Ruby

A minimal Ruby implementation of SAML Single Sign-On (SSO) with Okta as the Identity Provider (IdP).

## Prerequisites

- Ruby 3.0+
- Bundler
- An Okta developer account
- A configured SAML application in Okta

### Local Setup

1. Clone the repository.

```
git clone https://github.com/your-repo/saml-sso-ruby.git
cd saml-sso-ruby
```

2. Install Dependencies with `bundle install`.
3. Set Environment Variables:

```
## SP
SP_HOST=<sp-host>
SP_ACS_URL=<sp-acs-endpoint>
SP_ENTITY_ID=<sp-enitiy-id> # project-name/any string that identifies app

## IDP
IDP_SSO_TARGET_URL=<IDP-sso-url>
IDP_ENTITY_ID=<IDP-entity-id>
```

4. Create IDP from okta developer dashboard

   - Download the Okta certificate from your Okta SAML application settings.
   - Save it as cert/okta_cert.pem.

5. Generate Private Key and Certificate:

   - Run the following command to generate a private key and certificate.
   - Upload the generated certificate.crt to your Okta SAML application settings for assertion encryption.

```
openssl req -x509 -nodes -sha256 -days 3650 -newkey rsa:2048 -keyout cert/private.key -out cert/certificate.crt
```

6. Start the server using puma-dev (i.e, run `make run`)
