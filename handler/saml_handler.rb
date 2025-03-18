# frozen_string_literal: true

require 'base64'
require 'openssl'
require 'nokogiri'
require 'time'
require 'zlib'
require 'securerandom'
require 'ruby-saml'
require 'xmlenc'
require_relative '../helpers/saml_helper'

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

    [302, { 'Location' => '/home' }, []]
  end

  def self.handle_logout_callback(_)
    [200, { 'Content-Type' => 'text/html' }, ['logout callback']]
  end
end
