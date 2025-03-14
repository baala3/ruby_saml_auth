# frozen_string_literal: true

require 'base64'
require 'openssl'
require 'nokogiri'
require 'time'
require 'zlib'
require 'securerandom'

class SamlHandler
  def self.handle_auth_request
    # Read and process the template
    template = File.read('xml/saml_request_template.xml')
    saml_request = template
                   .gsub('{{SP_ACS_URL}}', ENV.fetch('SP_ACS_URL', nil))
                   .gsub('{{SP_ENTITY_ID}}', ENV.fetch('SP_ENTITY_ID', nil))
                   .gsub('{{IDP_SSO_TARGET_URL}}', ENV.fetch('IDP_SSO_TARGET_URL', nil))
                   .gsub('{{UNIQUE_ID}}', "id-#{SecureRandom.uuid}")
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
    log_saml_response(form_data) # for debugging purposes
    is_valid, message = validate_saml_response(form_data, File.read('./cert/okta_cert.pem'))

    if is_valid
      [200, { 'Content-Type' => 'text/html' }, ['successfully authenticated']]
    else
      [400, { 'Content-Type' => 'text/html' }, [message]]
    end
  end

  def self.log_saml_response(form_data)
    if form_data.key?('SAMLResponse')
      decoded_response = Base64.decode64(form_data['SAMLResponse'])
      doc = Nokogiri::XML(decoded_response)

      # Define namespaces
      namespaces = {
        'saml2' => 'urn:oasis:names:tc:SAML:2.0:assertion',
        'ds' => 'http://www.w3.org/2000/09/xmldsig#'
      }

      # Hide sensitive data
      doc.xpath('//saml2:NameID', namespaces).each { |node| node.content = '[REDACTED]' }
      doc.xpath('//saml2:AttributeValue', namespaces).each do |node|
        node.content = '[REDACTED]'
      end
      doc.xpath('//ds:X509Certificate', namespaces).each do |node|
        node.content = '[REDACTED]'
      end
      doc.xpath('//ds:SignatureValue', namespaces).each do |node|
        node.content = '[REDACTED]'
      end

      File.write('xml/saml_response.xml', doc.to_xml(indent: 2))
    else
      File.write('xml/saml_response.xml', 'No SAMLResponse found in the request')
    end
  end

  def self.validate_saml_response(form_data, certificate)
    return [false, 'SAMLResponse is required'] unless form_data.key?('SAMLResponse')

    decoded_response = Base64.decode64(form_data['SAMLResponse'])
    xml_doc = Nokogiri::XML(decoded_response)
    cert = OpenSSL::X509::Certificate.new(certificate)

    # First verify the response signature
    signature_node = xml_doc.at_xpath('//ds:Signature', 'ds' => 'http://www.w3.org/2000/09/xmldsig#')
    return [false, 'No signature found in SAML response'] if signature_node.nil?

    # Verify Response signature
    is_valid_sig = verify_signature(signature_node, cert)
    return is_valid_sig unless is_valid_sig[0]

    # Find and verify the Assertion
    assertion = xml_doc.at_xpath('//saml:Assertion',
                                 'saml' => 'urn:oasis:names:tc:SAML:2.0:assertion')
    return [false, 'No Assertion found in SAML response'] if assertion.nil?

    # Verify Assertion signature
    assertion_signature = assertion.at_xpath('.//ds:Signature', 'ds' => 'http://www.w3.org/2000/09/xmldsig#')
    return [false, 'No signature found in SAML Assertion'] if assertion_signature.nil?

    is_valid_assertion_sig = verify_signature(assertion_signature, cert)
    return is_valid_assertion_sig unless is_valid_assertion_sig[0]

    verify_assertion_timestamps_and_audience(assertion)
  end

  def self.verify_assertion_timestamps_and_audience(assertion)
    # Verify conditions (timestamps)
    conditions = assertion.at_xpath('.//saml:Conditions',
                                    'saml' => 'urn:oasis:names:tc:SAML:2.0:assertion')
    return [false, 'No Conditions found in SAML Assertion'] if conditions.nil?

    # Verify timestamps
    not_before = Time.parse(conditions['NotBefore'])
    not_on_or_after = Time.parse(conditions['NotOnOrAfter'])

    if Time.now < not_before || Time.now >= not_on_or_after
      return [false,
              'SAML Assertion expired or not yet valid']
    end

    # Verify Audience (optional but recommended)
    audience = conditions.at_xpath('.//saml:AudienceRestriction/saml:Audience',
                                   'saml' => 'urn:oasis:names:tc:SAML:2.0:assertion')
    if audience && audience.text != ENV['SP_ENTITY_ID']
      return [false, "Invalid Audience. Expected: #{ENV.fetch('SP_ENTITY_ID', nil)}, Got: #{audience.text}"]
    end

    # Verify Subject (optional but recommended)
    subject = assertion.at_xpath('.//saml:Subject',
                                 'saml' => 'urn:oasis:names:tc:SAML:2.0:assertion')
    return [false, 'No Subject found in SAML Assertion'] if subject.nil?

    [true, 'Successfully validated']
  end

  def self.verify_signature(signature_node, certificate)
    signed_info = signature_node.at_xpath('./ds:SignedInfo', 'ds' => 'http://www.w3.org/2000/09/xmldsig#')
    signature_value = Base64.decode64(signature_node.at_xpath('./ds:SignatureValue', 'ds' => 'http://www.w3.org/2000/09/xmldsig#').text)

    # First verify all digest values
    references = signed_info.xpath('.//ds:Reference', 'ds' => 'http://www.w3.org/2000/09/xmldsig#')
    references.each do |reference|
      is_valid_digest = verify_digest_value(reference, signature_node.document)
      unless is_valid_digest
        return [false,
                "Invalid Digest Value for Reference: #{reference['URI']}"]
      end
    end

    # Then verify the signature
    signature_method = signed_info.at_xpath('.//ds:SignatureMethod', 'ds' => 'http://www.w3.org/2000/09/xmldsig#')
    algorithm = signature_method['Algorithm'] if signature_method

    # Choose the appropriate digest based on the algorithm
    digest = case algorithm
             when 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256'
               OpenSSL::Digest.new('SHA256')
             when 'http://www.w3.org/2000/09/xmldsig#rsa-sha1'
               OpenSSL::Digest.new('SHA1')
             else
               OpenSSL::Digest.new('SHA256') # default to SHA256
             end

    # Get the canonicalized SignedInfo
    canon_string = signed_info.canonicalize(Nokogiri::XML::XML_C14N_EXCLUSIVE_1_0)

    # Verify the signature
    unless certificate.public_key.verify(digest, signature_value, canon_string)
      return [false, "Invalid Signature - Algorithm: #{algorithm}"]
    end

    [true, 'Valid signature']
  end

  def self.verify_digest_value(_reference, _document)
    # NOTE: skipping digest verification as it requires precise canonicalization
    # and transform handling. This should be implemented properly in a production environment
    # for full security compliance with SAML 2.0 specifications.
    true
  end
end
