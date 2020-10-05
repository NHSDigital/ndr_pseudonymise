require 'digest/sha1'
require 'securerandom'
require 'base64'

module NdrPseudonymise
  # Simple pseudonymisation library, for efficient pseudonymisation of
  # identifiable data, suitable for fuzzy matching
  #
  # Sample usage:
  # Set up clinical data and demographics
  # clinical_data = ... load pdf file ...
  # all_demographics = {'nhsnumber' => '1234567881', 'postcode' => 'CB22 3AD',
  # 'birthdate' => '1975-10-22', 'surname' => 'SMITH', 'forenames' => 'JOHN ROBERT'}
  #
  # # Generate pseudonymised identifiers and encryption keys
  # (pseudo_id1, pseudo_id2, key_bundle, rowid, demog_key, clinical_key) =
  #  NdrPseudonymise::SimplePseudonymisation.generate_keys(salt_id, salt_demog, salt_clinical,
  #   all_demographics['nhsnumber'], all_demographics['postcode'], all_demographics['birthdate'])
  #
  # # Emit first 4 values as index demographics
  # emit_index_demographics(pseudo_id1, pseudo_id2, key_bundle, rowid)
  #
  # # Encrypt all demographics with demog_key
  # emit_encrypted_demographics(rowid, NdrPseudonymise::SimplePseudonymisation.encrypt_data64(demog_key, all_demographics.to_json))
  #
  # # Encrypt all clinical data with clinical_key
  # emit_encrypted_clinical_data(rowid, NdrPseudonymise::SimplePseudonymisation.encrypt_data(clinical_key, clinical_data))
  #
  class SimplePseudonymisation
    # Generate pseudonymised identifiers and pseudonymisation keys
    # Returns an array of 6 strings:
    # [pseudo_id1, pseudo_id2, key_bundle, rowid, demog_key, clinical_key]
    def self.generate_keys(salt_id, salt_demog, salt_clinical, nhsnumber, current_postcode, birthdate)
      unless nhsnumber.is_a?(String) && nhsnumber =~ /\A([0-9]{10})?\Z/
        raise 'Invalid NHS number'
      end
      unless current_postcode.is_a?(String) && current_postcode =~ /\A[A-Z0-9 ]*\Z/
        raise 'Invalid postcode'
      end
      unless birthdate.is_a?(String) && birthdate =~ /\A([0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]|)\Z/
        raise 'Invalid birthdate'
      end
      real_id1 = 'nhsnumber_' + nhsnumber
      # Delete spaces from postcode
      real_id2 = 'birthdate_postcode_' + birthdate + '_' + current_postcode.split(' ').join('')

      pseudo_id1 = data_hash(real_id1, salt_id)
      pseudo_id2 = data_hash(real_id2, salt_id)
      demog_key = random_key
      clinical_key = random_key
      keys = []
      if nhsnumber.length > 0
        keys += [encrypt_data64(real_id1 + salt_demog, demog_key),
                 encrypt_data64(real_id1 + salt_clinical, clinical_key)]
      end
      if current_postcode.length > 0 && birthdate.length > 0
        keys += [encrypt_data64(real_id2 + salt_demog, demog_key),
                 encrypt_data64(real_id2 + salt_clinical, clinical_key)]
      end
      # TODO: Consider whether it's worth storing something, if keys would otherwise be empty.
      key_bundle = keys.join(' ')
      rowid = random_key
      [pseudo_id1, pseudo_id2, key_bundle, rowid, demog_key, clinical_key]
    end

    # Generate pseudonymised identifiers and pseudonymisation keys
    # for data with only an NHS number (missing patient postcode or DOB), where
    # only the demographics need to be pseudonymised (e.g. prescription data).
    # Returns an array of 3 strings:
    # [pseudo_id1, key_bundle, demog_key]
    def self.generate_keys_nhsnumber_demog_only(salt_id, salt_demog, nhsnumber)
      unless nhsnumber.is_a?(String) && nhsnumber =~ /\A([0-9]{10})?\Z/
        raise 'Invalid NHS number'
      end
      real_id1 = 'nhsnumber_' + nhsnumber

      pseudo_id1 = data_hash(real_id1, salt_id)
      demog_key = random_key
      key_bundle = if nhsnumber.length > 0
                     encrypt_data64(real_id1 + salt_demog, demog_key)
                   else
                     ''
                   end
      [pseudo_id1, key_bundle, demog_key]
    end

    def self.data_hash(value, salt)
      Digest::SHA2.hexdigest(value.to_s + salt.to_s)
    end

    def self.random_key
      SecureRandom.hex(32) # 32 bytes = 256 bits
    end

    # returns a base-64 encoded string
    def self.encrypt_data64(key, data)
      Base64.strict_encode64(encrypt_data(key, data))
    end

    # returns a binary string
    def self.encrypt_data(key, data)
      unless key =~ /[0-9a-f]{32}/
        raise(ArgumentError, 'Expected key to contain at least 256 bits of hex characters (0-9, a-f)')
      end
      aes = OpenSSL::Cipher.new('AES-256-CBC')
      aes.encrypt
      aes.key = Digest::SHA256.digest(key)
      aes.update(data) + aes.final
    end

    def self.decrypt_data64(key, data)
      decrypt_data(key, Base64.strict_decode64(data))
    end

    def self.decrypt_data(key, data)
      unless key =~ /[0-9a-f]{32}/
        raise(ArgumentError, 'Expected key to contain at least 256 bits of hex characters (0-9, a-f)')
      end
      aes = OpenSSL::Cipher.new('AES-256-CBC')
      aes.decrypt
      aes.key = Digest::SHA256.digest(key.chomp)
      (aes.update(data) + aes.final)
    end
  end
end
