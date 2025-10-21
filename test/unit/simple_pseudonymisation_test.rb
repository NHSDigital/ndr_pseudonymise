require 'test_helper'

require 'ndr_pseudonymise/simple_pseudonymisation'
require 'ndr_pseudonymise/pseudonymisation_specification'
require 'json'
require 'rsa_aes_cbc'

class SimplePseudonymisationTest < ActiveSupport::TestCase
  test 'SimplePseudonymisation typical usage' do
    # The application has 3 secrets: salt_id, salt_demog and salt_clinical, each a 64-character hex string
    # Sample usage (in ruby pseudocode):
    salt_id = SecureRandom.hex(32)
    salt_demog = SecureRandom.hex(32)
    salt_clinical = SecureRandom.hex(32)

    # Set up clinical data and demographics
    clinical_data = SecureRandom.random_bytes(65537)
    all_demographics = {'nhsnumber' => '1234567881', 'postcode' => 'CB22 3AD', 'birthdate' => '1975-10-22', 'surname' => 'SMITH', 'forenames' => 'JOHN ROBERT'}

    # Generate pseudonymised identifiers and encryption keys
    (pseudo_id1, pseudo_id2, key_bundle, rowid, demog_key, clinical_key) = NdrPseudonymise::SimplePseudonymisation.generate_keys(salt_id, salt_demog, salt_clinical, all_demographics['nhsnumber'], all_demographics['postcode'], all_demographics['birthdate'])

    # Emit first 4 values as index demographics
    emit_index_demographics(pseudo_id1, pseudo_id2, key_bundle, rowid)

    # Encrypt all demographics with demog_key
    emit_encrypted_demographics(rowid, NdrPseudonymise::SimplePseudonymisation.encrypt_data64(demog_key, all_demographics.to_json))

    # Encrypt all clinical data with clinical_key
    emit_encrypted_clinical_data(rowid, NdrPseudonymise::SimplePseudonymisation.encrypt_data(clinical_key, clinical_data))

    # Test decryption
    clinical_data_to_compare = if clinical_data.respond_to?(:force_encoding)
                                 clinical_data.force_encoding('ASCII-8BIT')
                               else
                                 clinical_data
                               end
    keys = key_bundle.split(/ /)
    demog_key1 = decrypt_data64('nhsnumber_' + all_demographics['nhsnumber'] + salt_demog, keys[0])
    clinical_key1 = decrypt_data64('nhsnumber_' + all_demographics['nhsnumber'] + salt_clinical, keys[1])
    demog_key2 = decrypt_data64('birthdate_postcode_' + all_demographics['birthdate'] + '_' + all_demographics['postcode'].delete(' ') + salt_demog, keys[2])
    clinical_key2 = decrypt_data64('birthdate_postcode_' + all_demographics['birthdate'] + '_' + all_demographics['postcode'].delete(' ') + salt_clinical, keys[3])
    assert_equal(demog_key, demog_key1)
    assert_equal(clinical_key, clinical_key1)
    assert_equal(demog_key, demog_key2)
    assert_equal(clinical_key, clinical_key2)
    assert_equal(all_demographics.to_json, decrypt_data64(demog_key, NdrPseudonymise::SimplePseudonymisation.encrypt_data64(demog_key, all_demographics.to_json)))
    assert_equal(clinical_data_to_compare, decrypt_data(clinical_key, NdrPseudonymise::SimplePseudonymisation.encrypt_data(clinical_key, clinical_data)))
  end

  def emit_index_demographics(pseudo_id1, pseudo_id2, key_bundle, rowid)
    assert_match(/\A[0-9a-f]{64}\Z/, pseudo_id1) # SHA-256 (256 bits) in hex
    assert_match(/\A[0-9a-f]{64}\Z/, pseudo_id2) # SHA-256 (256 bits) in hex

    assert_match(/\A[0-9a-f]{64}\Z/, rowid) # SHA-256 (256 bits) in hex
  end

  def emit_encrypted_demographics(rowid, data)
    assert_match(/\A[0-9a-f]{64}\Z/, rowid) # SHA-256 (256 bits) in hex
    assert_match(/^[-A-Za-z0-9+\/=]*$/, data.delete("\r\n"))
  end

  def emit_encrypted_clinical_data(rowid, data)
    assert_match(/\A[0-9a-f]{64}\Z/, rowid) # SHA-256 (256 bits) in hex
  end

  def decrypt_data(key, data)
    NdrPseudonymise::SimplePseudonymisation.decrypt_data(key, data)
  end

  def decrypt_data64(key, data)
    NdrPseudonymise::SimplePseudonymisation.decrypt_data64(key, data)
  end

  test 'Encryption consistency across platforms' do
    key = '3b26a597662840c6997317b9a88eb8393037cc1471f26600ce4103036ded3ea3'
    data = 'This is a test message that should be encrypted consistently!'
    encrypted_data = "\rL4d\x86\xD8\xA6\x87\xDC\x8B>\xB4\xDF\x81z\xEE#K7\"\x96\b\xFE\x10Bk\xBAPV=Te\x9CH}\xF2|\"\x8BK\xF2\xDFX\x14\x9B\xB7\x9E\xC1\xBCq\n\xB5u'1s\x05`\x88\xFD_\x16[D"
    encrypted_data64 = 'DUw0ZIbYpofciz6034F67iNLNyKWCP4QQmu6UFY9VGWcSH3yfCKLS/LfWBSbt57BvHEKtXUnMXMFYIj9XxZbRA=='

    assert_equal(encrypted_data64,
                 NdrPseudonymise::SimplePseudonymisation.encrypt_data64(key, data))
    encrypted_data_to_compare = if encrypted_data.respond_to?(:force_encoding)
                                  encrypted_data.dup.force_encoding('ASCII-8BIT')
                                else
                                  encrypted_data
                                end
    assert_equal(encrypted_data_to_compare,
                 NdrPseudonymise::SimplePseudonymisation.encrypt_data(key, data))
  end
end
