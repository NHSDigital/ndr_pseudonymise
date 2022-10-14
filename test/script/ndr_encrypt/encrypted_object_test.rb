require 'test_helper'

require 'tempfile'
require 'ndr_encrypt'
require 'securerandom'

module NdrEncrypt
  # Test NdrEncrypt::EncryptedObject
  class EncryptedObjectTest < ActiveSupport::TestCase
    SAMPLE_DATA_11_BYTES = '01234569a'.freeze
    SAMPLE_DATA_512_BYTES = ('Test' * (512 / 4)).freeze
    SAMPLE_DATA_OVER_2MB = (('0123456789abcdef' * (1024 / 16) * 1024 * 2) + 'a').freeze
    # TODO: Test and support different key sizes
    # KEY_SIZES = [4096, 2048, 1024].freeze
    KEY_SIZES = [4096].freeze

    def setup
      @data_examples = [SAMPLE_DATA_11_BYTES, SAMPLE_DATA_512_BYTES, SAMPLE_DATA_OVER_2MB]
    end

    test 'encrypt and decrypt with different key sizes' do
      KEY_SIZES.each do |key_size|
        @private_key_filename = Tempfile.new("private_#{key_size}")
        @public_key_filename = Tempfile.new("public_#{key_size}")
        @passphrase = SecureRandom.hex(32)
        private_key = OpenSSL::PKey::RSA.new key_size
        File.open(@private_key_filename, 'w') do |f|
          f << private_key.export(OpenSSL::Cipher.new('aes-256-cbc'), @passphrase)
        end
        File.open(@public_key_filename, 'w') { |f| f << private_key.public_key.export }

        @data_examples.each do |data|
          encrypted = NdrEncrypt::EncryptedObject.encrypt(data, pub_key: @public_key_filename)
          assert encrypted.size >= data.size, 'Encrypted data cannot be smaler than original data'
          decrypted = NdrEncrypt::EncryptedObject.decrypt(encrypted,
                                                          private_key: @private_key_filename,
                                                          passin: "pass:#{@passphrase}")
          assert_equal data, decrypted, 'Expected decrypted data to match original'
        end
      end
    end
    # TODO: Test EncryptedObject with recovering existing data generated with various key sizes
  end
end
