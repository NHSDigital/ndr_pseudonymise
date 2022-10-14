require 'test_helper'

require 'base64'
require 'ndr_encrypt'
require 'securerandom'

module NdrEncrypt
  # Test NdrEncrypt::Repository
  class RepositoryTest < ActiveSupport::TestCase
    # Sample image file in base64 format
    # base64 --decode > test/dir/ok.gif <<BASE64
    SAMPLE_IMAGE_BASE64 = <<~BASE64.freeze
      R0lGODlhDAAIAPABAAAAAP///yH5BAAAAAAAIf8LSW1hZ2VNYWdpY2sOZ2Ft
      bWE9MC40NTQ1NDUALAAAAAAMAAgAAAITjI8HC9GuTJvozRchVQz6BIZgAQA7
    BASE64
    SAMPLE_IMAGE_SHA256SUM = 'c4960f3721e4987b9b6a5dbd13b82d260c22b0d2678beb8a5f0967cf84bf9889'.
                             freeze
    SAMPLE_IMAGE_GIT_BLOBID = 'f29bddf64c444f663d106568f4a81a22151ed3f97b0ec0c2a5ab25a0e8a02515'.
                              freeze
    KEY_NAME = 'ourkey1'.freeze
    ENCRYPTED_ID = '5e7bfaadc549186d65846df2fbe8da97e34ffe27dc6e7b8a192cbdbe28780819'.freeze
    def setup
      # Set up a filespace with images
      @repo_dir = Dir.mktmpdir
      @image_path = 'test/dir/ok.gif' # Relative path, inside @repo_dir
      @image_filename = File.join(@repo_dir, @image_path) # Absolute path
      FileUtils.mkdir_p(File.dirname(@image_filename))
      File.open(@image_filename, 'wb') { |f| f << Base64.decode64(SAMPLE_IMAGE_BASE64) }

      # Create encrypted public / private key pair
      @key_dir = Dir.mktmpdir
      @key_name = KEY_NAME
      @private_key_filename = File.join(@key_dir, 'ourkey1.pem')
      @public_key_filename = File.join(@key_dir, 'ourkey1.pub')
      @passphrase = SecureRandom.hex(32)
      private_key = OpenSSL::PKey::RSA.new 4096
      File.open(@private_key_filename, 'w') do |f|
        f << private_key.export(OpenSSL::Cipher.new('aes-256-cbc'), @passphrase)
      end
      File.open(@public_key_filename, 'w') { |f| f << private_key.public_key.export }
    end

    def teardown
      FileUtils.remove_entry @key_dir
      FileUtils.remove_entry @repo_dir
    end

    test 'init, add and get' do
      # Set up an empty working copy
      repo = NdrEncrypt::Repository.new(repo_dir: @repo_dir)
      encrypted_dir = File.join(@repo_dir, NdrEncrypt::Repository::ENCRYPTED_DIR)
      refute Dir.exist?(encrypted_dir), 'encrypted directory should not yet exist'
      repo.init
      assert Dir.exist?(encrypted_dir), 'encrypted directory should exist after init'

      # Add a known file
      assert_equal SAMPLE_IMAGE_SHA256SUM, Digest::SHA256.hexdigest(File.binread(@image_filename)),
                   'Expect known image file'
      Dir.chdir(@repo_dir) do
        repo.add([@image_path], key_name: @key_name, pub_key: @public_key_filename)
      end

      # Check the CSV index and encrypted files are where they should be
      index_file = File.join(encrypted_dir, 'index.csv')
      assert_equal [%w[git_blobid path], [SAMPLE_IMAGE_GIT_BLOBID, @image_path]],
                   CSV.read(index_file), 'CSV index should contain ok.gif'

      # Move aside the file, and recover it from the encrypted repository
      FileUtils.mv(@image_filename, "#{@image_filename}.orig")
      Dir.chdir(@repo_dir) do
        repo.get([@image_path], key_name: @key_name, private_key: @private_key_filename,
                                passin: "pass:#{@passphrase}")
      end
      assert File.exist?(@image_filename), 'Should restore image file location'
      assert_equal SAMPLE_IMAGE_SHA256SUM, Digest::SHA256.hexdigest(File.binread(@image_filename)),
                   'Should restore identical image file'
    end
  end
end
