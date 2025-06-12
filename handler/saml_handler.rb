# frozen_string_literal: true

require 'base64'
require 'openssl'
require 'nokogiri'
require 'time'
require 'zlib'
require 'securerandom'
require 'xmlenc'
require_relative '../helpers/saml_helper'
require 'cgi'

class SamlHandler
  extend SamlHelper
  def self.handle_auth_request(env)
    # Read and process the template
    saml_request_id = "id-#{SecureRandom.uuid}"
    session = env['rack.session']
    session[:saml_request_id] = saml_request_id

    template = File.read('xml/saml_sso_request_template.xml')
    saml_request = template
                   .gsub('{{SP_ACS_URL}}', ENV.fetch('SP_ACS_URL', nil))
                   .gsub('{{SP_ENTITY_ID}}', ENV.fetch('SP_ENTITY_ID', nil))
                   .gsub('{{IDP_SSO_TARGET_URL}}', ENV.fetch('IDP_SSO_TARGET_URL', nil))
                   .gsub('{{UNIQUE_ID}}', saml_request_id)
                   .gsub('{{ISSUE_INSTANT}}', Time.now.utc.strftime('%Y-%m-%dT%H:%M:%S.%3NZ'))
    # Deflate and encode
    deflated_request = Zlib::Deflate.deflate(saml_request, Zlib::BEST_COMPRESSION)[2..-5]
    base64_request = Base64.strict_encode64(deflated_request)
    encoded_request = URI.encode_www_form_component(base64_request)

    redirect_url = "#{ENV.fetch('IDP_SSO_TARGET_URL', nil)}?SAMLRequest=#{encoded_request}"
    [302, { 'Location' => redirect_url }, []]
  end

  def self.handle_acs(env)
    form_data = URI.decode_www_form(env['rack.input'].read).to_h
    return [400, { 'Content-Type' => 'text/html' }, ['SAMLResponse not found']] unless log_saml_response(form_data)

    # Get the base64 decoded SAML response
    saml_response = Base64.decode64(form_data['SAMLResponse'])

    # Handle encrypted assertion if configured
    if ENV['IS_ASSERTION_ENCRYPTED'] == 'true'
      success, decrypted_xml = decrypt_assertion(
        saml_response,
        './cert/private.key'
      )

      return [400, { 'Content-Type' => 'text/html' }, ["Decryption failed: #{decrypted_xml}"]] unless success

      saml_response = decrypted_xml
    end

    # Validate the SAML response
    validate_saml_response(saml_response, File.read('./cert/certificate.crt'))

    extract_and_store_user_attributes(saml_response, env)

    [302, { 'Location' => '/home?status=success&message=Successfully+logged+in' }, []]
  end

  def self.handle_logout_request(env)
    session = env['rack.session']
    # Read and process template
    template = File.read('xml/saml_slo_request_template.xml')

    saml_request = template
                   .gsub('{{IDP_LOGOUT_URL}}', ENV.fetch('IDP_LOGOUT_URL', nil))
                   .gsub('{{UNIQUE_ID}}', "id-#{SecureRandom.uuid}")
                   .gsub('{{ISSUE_INSTANT}}', Time.now.utc.strftime('%Y-%m-%dT%H:%M:%S.%3NZ'))
                   .gsub('{{NOT_ON_OR_AFTER}}', (Time.now.utc + 10).strftime('%Y-%m-%dT%H:%M:%S.%3NZ'))
                   .gsub('{{SP_ENTITY_ID}}', ENV.fetch('SP_ENTITY_ID', nil))
                   .gsub('{{ASSERTION_NAME_ID}}', session[:name_id])
                   .gsub('{{REQUEST_UNIQUE_ID}}', session[:saml_request_id])

    encoded_saml_request = encoded_saml_request(saml_request)

    sig_alg = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256'
    signature = sign_saml_request(encoded_saml_request, sig_alg)

    redirect_url = "#{ENV.fetch('IDP_LOGOUT_URL',
                                nil)}?SAMLRequest=#{encoded_saml_request}&SigAlg=#{CGI.escape(sig_alg)}&Signature=#{signature}"

    [302, { 'Location' => redirect_url }, []]
  end
end
