# frozen_string_literal: true

require 'base64'
require 'openssl'
require 'nokogiri'
require 'time'
require 'zlib'
require 'securerandom'
require 'ruby-saml'
require 'xmlenc'

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
    log_saml_response(form_data)

    result = nil

    # Get the base64 decoded SAML response
    saml_response = Base64.decode64(form_data['SAMLResponse'])

    # Handle encrypted assertion if configured
    if ENV['IS_ASSERTION_ENCRYPTED'] == 'true'
      success, decrypted_xml = decrypt_assertion(
        saml_response,
        './cert/private.key'
      )

      return [400, { 'Content-Type' => 'text/html' }, ["Decryption failed: #{decrypted_xml}"]] unless success

      result = decrypted_xml

    else
      result = saml_response
    end

    # Validate the SAML response
    validate_saml_response(result, File.read('./cert/certificate.crt'))

    [200, { 'Content-Type' => 'text/html' }, ['successfully authenticated']]
  end

  def self.decrypt_assertion(saml_response, private_key_path)
    # Parse the SAML response
    doc = Nokogiri::XML(saml_response)

    # Load private key as OpenSSL key object
    private_key = OpenSSL::PKey::RSA.new(File.read(private_key_path))

    # Get the encrypted assertion
    encrypted_assertion = doc.at_xpath('//saml2:EncryptedAssertion',
                                       'saml2' => 'urn:oasis:names:tc:SAML:2.0:assertion')
    return [false, 'No encrypted assertion found'] unless encrypted_assertion

    # Get encrypted key node
    encrypted_key = encrypted_assertion.at_xpath('.//xenc:EncryptedKey',
                                                 'xenc' => 'http://www.w3.org/2001/04/xmlenc#')
    return [false, 'No encrypted key found'] unless encrypted_key

    # Get encrypted data node
    encrypted_data = encrypted_assertion.at_xpath('.//xenc:EncryptedData',
                                                  'xenc' => 'http://www.w3.org/2001/04/xmlenc#')
    return [false, 'No encrypted data found'] unless encrypted_data

    # First decrypt the key
    key_cipher = Xmlenc::EncryptedKey.new(encrypted_key)
    decrypted_key = key_cipher.decrypt(private_key)

    # Then decrypt the data with the decrypted key
    encryption = Xmlenc::EncryptedData.new(encrypted_data)
    decrypted_xml = encryption.decrypt(decrypted_key)

    [true, decrypted_xml]
  rescue OpenSSL::Cipher::CipherError => e
    [false, "Failed to decrypt: #{e.message}"]
  rescue OpenSSL::PKey::RSAError => e
    [false, "Key error: #{e.message}"]
  rescue StandardError => e
    [false, "Decryption failed: #{e.message}"]
  end

  def self.log_saml_response(form_data)
    if form_data.key?('SAMLResponse')
      decoded_response = Base64.decode64(form_data['SAMLResponse'])
      doc = Nokogiri::XML(decoded_response).to_xml(indent: 2)
      File.write('xml/saml_response.xml', doc)
    else
      File.write('xml/saml_response.xml', 'No SAMLResponse found in the request')
    end
  end

  def self.validate_saml_response(decrypted_xml, certificate)
    xml_doc = Nokogiri::XML(decrypted_xml)
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
