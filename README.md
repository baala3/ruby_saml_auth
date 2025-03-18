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

2. Install Dependencies with `make setup`.
3. Load & configure Environment Variables `touch .env && cat .env.example > .env`
4. Create IDP on okta developer dashboard

   - Download the Okta certificate from your Okta SAML application settings.
   - Save it as cert/okta_cert.pem.

5. If you want SAML assertion to be encrypted then follow this step:
   - Run the below command to generate a private key and certificate.
   - Upload the generated certificate.crt to your Okta SAML application settings for assertion encryption.
   - and set `IS_ASSERTION_ENCRYPTED` to `true`

```
openssl req -x509 -nodes -sha256 -days 3650 -newkey rsa:2048 -keyout cert/private.key -out cert/certificate.crt
```

6. Start the server using puma-dev (i.e, run `make run`)
