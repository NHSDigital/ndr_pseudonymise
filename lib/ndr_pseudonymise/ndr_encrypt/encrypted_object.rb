require 'digest'
require 'io/console'
require 'openssl'
require 'zlib'

module NdrPseudonymise
  module NdrEncrypt
    # Defines utility methods for encrypting / decrypting objects
    module EncryptedObject
      # rubocop:disable Style/SlicingWithRange
      def self.blob(data)
        "blob #{data.size}\0#{data}"
      end

      def self.unpack_blob(blob)
        prefix, data = blob.split("\x00", 2)
        raise(ArgumentError, 'Invalid blob format') unless /\Ablob [0-9]+\z/ =~ prefix

        size = prefix[5..-1].to_i
        raise(ArgumentError, 'Incorrect blob size') unless size == data.size

        data
      end

      def self.digest(blob)
        Digest::SHA256.hexdigest(blob)
      end

      # Create zlib-compressed version of the content
      def self.compress(blob)
        Zlib::Deflate.deflate(blob)
      end

      # Unpack zlib-compressed content
      def self.decompress(contents)
        Zlib::Inflate.inflate(contents)
      end

      def self.encrypted_id(git_blobid, key_name: nil)
        # We need to support ruby 2.0 so cannot use required keyword arguments syntax
        raise(ArgumentError, 'missing keyword: :key_name') unless key_name

        temp_id = "ndr_encrypt #{git_blobid} #{key_name}"
        digest(blob(temp_id))
      end

      # Encrypt sensitive secret data, given a public key file as a String
      # Returns the encrypted output data
      # Result can either be decrypted using the decrypt method on this class.
      # TODO: write equivalent command-line method using only openssl and shell scripts
      def self.encrypt(secret_data, pub_key: nil)
        # We need to support ruby 2.0 so cannot use required keyword arguments syntax
        raise(ArgumentError, 'missing keyword: :pub_key') unless pub_key
        return nil unless secret_data

        public_key_data = File.read(pub_key)
        cipher = OpenSSL::Cipher.new('aes-256-cbc')
        cipher.encrypt
        cipher.key = random_key = cipher.random_key
        cipher.iv = random_iv = cipher.random_iv
        rawdata = cipher.update(secret_data)
        rawdata << cipher.final
        public_key = OpenSSL::PKey::RSA.new(public_key_data)
        public_key.public_encrypt(random_key) + random_iv + rawdata
      end

      # Decrypt sensitive secret data, given a private key and its password
      # Returns the decrypted output data
      # TODO: write equivalent command-line method using only openssl and shell scripts
      # TODO: Refactor with code from era UnifiedSources::ApiRetrieval::Extractor
      def self.decrypt(rawdata, private_key: nil, passin: nil)
        # We need to support ruby 2.0 so cannot use required keyword arguments syntax
        raise(ArgumentError, 'missing keyword: :private_key') unless private_key
        return nil unless rawdata

        password = get_passphrase(private_key: private_key, passin: passin)
        private_key_data = File.read(private_key)
        cipher = OpenSSL::Cipher.new('aes-256-cbc')
        cipher.decrypt
        private_key = OpenSSL::PKey::RSA.new(private_key_data, password)
        # TODO: Derive block length,
        # possibly using OpenSSL::PKey::RSA.new(private_key.public_key).public_encrypt('').size
        # cipher.key = private_key.private_decrypt(rawdata[0..255])
        cipher.key = private_key.private_decrypt(rawdata[0..511])
        # cipher.iv = rawdata[256..271]
        # decrypted_data = cipher.update(rawdata[272..-1])
        cipher.iv = rawdata[512..527]
        decrypted_data = cipher.update(rawdata[528..-1])
        decrypted_data << cipher.final
      end

      def self.get_passphrase(private_key: nil, passin: nil)
        # We need to support ruby 2.0 so cannot use required keyword arguments syntax
        raise(ArgumentError, 'missing keyword: :private_key') unless private_key

        @passphrase_cache ||= {}
        return @passphrase_cache[private_key] if @passphrase_cache.key?(private_key)

        raise(ArgumentError, 'Missing private key file') unless File.exist?(private_key)

        # Implement a subset of the openssl -passin options in
        # https://www.openssl.org/docs/man3.0/man1/openssl-passphrase-options.html
        result = case passin
                 when nil, ''
                   msg = "Enter passphrase for #{private_key}: "
                   if IO.console.respond_to?(:getpass)
                     IO.console.getpass msg
                   else
                     $stdout.print msg
                     password = $stdin.noecho(&:gets).chomp
                     puts
                     password
                   end
                 when /\Apass:/
                   passin[5..-1]
                 when /\Aenv:/
                   ENV[passin[4..-1]]
                 when 'stdin'
                   $stdin.readline.chomp
                 else
                   raise(ArgumentError, 'Unsupported passin option')
                 end
        @passphrase_cache[private_key] = result
      end
      # rubocop:enable Style/SlicingWithRange
    end
  end
end
