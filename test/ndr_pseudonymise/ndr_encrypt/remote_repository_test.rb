require 'test_helper'

require 'base64'
require 'ndr_pseudonymise/ndr_encrypt'
require 'securerandom'

module NdrPseudonymise
  module NdrEncrypt
    # Test NdrEncrypt::RemoteRepository
    # Demonstrate retrieving a file from a remote repository, using
    # existing encrypted data and public / private keys.
    # The keys used in this example are used nowhere else, and are
    # purely internally, to test the consistency of the code's behaviour.
    class RemoteRepositoryTest < ActiveSupport::TestCase
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

      # Private key created only for these examples, using:
      # openssl genpkey -algorithm RSA -out ourkey1.pem -aes-256-cbc -pkeyopt rsa_keygen_bits:4096
      SAMPLE_PRIVATE_KEY = <<~PRIVATE_KEY.freeze
        -----BEGIN ENCRYPTED PRIVATE KEY-----
        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
        g6XAYyA7FRae3WKTTAU2c4sYAA==
        -----END ENCRYPTED PRIVATE KEY-----
      PRIVATE_KEY
      SAMPLE_PUBLIC_KEY = <<~PUBLIC_KEY.freeze
        -----BEGIN PUBLIC KEY-----
        MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAqU4DUbHPVnoi60wYXTDg
        NMca1C1bCoTTi+Y1r4IkbZVP0MIauyNXjWb9V56C07jZekTcoemYSRBzeyWVrALe
        F2ahtfGbWOgzpgqtilUC3wLl9Rd3kHD+tgJq6sZBJZ+QCbYeOH7qn+xpFwc43fgE
        E4DDTQikyliAs0Z0B1IjIX4WA2iCZlil1f51ZTXNfO5NwnHJsE8Vko+t73uCxT2+
        rQLPiKjFViNNwPvjmHOJ6sCfzjJeSW1OM86Da+6xJ0mFPiAhMcICiY+ufrS+Ua/+
        ix9KySyBjXFH7+vMjfUPBlcP+R5HAZqQbzPTSrkWsfeq5ZsVGD/ME1O2MSGsRHrp
        bCJ7J+khwZlZurDwBrpT6u/lAEGw0nMeIyT7Z18RM3t2lyaqGAGd+wWbXevoTvz+
        bWSxnUS0eaLgz1iKpx0idMWLHmGVKijabVR5mC64GV7sJu2w6emMxVdU8plhQSrt
        vGWpl52I5QiNE7rWPsUpwo9jvkKzHRoQCTiT0fhHr4QQ9AUxbmv0Jo3HcaJlWCXH
        JXQ1G08/7WdTIVF+xTNoDuFeUn07SAzZDE0F7918Ky9Mzg4bpXTB0jFPbbD2nQZM
        fgJXJglT2f7nPegbdSWkqsAsTPv5uttZg0x2SNjUf97eQ3lj6oEJvCTWDOgC9Ump
        7ykS+aQTTzPQXOtd5c12KA0CAwEAAQ==
        -----END PUBLIC KEY-----
      PUBLIC_KEY
      # Randomly generated passphrase, only used for creating this example
      PASSPHRASE = '214cd06978dd0a7a79e5a6cf6c71f884762861846e3a150fd2e008756ea1194f'.freeze
      SAMPLE_ENCRYPTED_IMAGE_BASE64 = <<~ENCRYPTED_BASE64.freeze
        KeLF9MpQhHZq0CcunkVWDM7a0n4cuywD/fpks98YvGDm5Zs7WZo/v4RzGXLs9EEV5J7g/K
        NLzJL/mUTMawqU71wbqayC/4P6k7x7P17zObXyTRscdCuBK89Jg4xiXk2WKr1mmOFy9E71
        83lB6MkrYOeoQMLu41MBYBZAYleoiiUtIcrU3Fir2RbIL3PLDZsJ0gHISvDKyoU/Ytbav6
        GqZlI/PgRiEfzlNFGMktWrfWK0tDByr9V5ZdYrydpj/WQhkFlllAnjt1PkWJvFWAj2/wMd
        eHMbF9xcPm/dMiP/P8VswYd/U3+24uZYAQ8OQ5aS9O8JOsVH8OjfTTuhCU34mFw8RD/aoO
        J0e0wCBDUYwIeE/Aro5JYEbaNd5fGks3UhBo+mQwozGOWmq1ZRnyGGej2Isk0TnsVVMQIO
        m8JFV1fArs9Jzo20O6hlGZMtC2qQK/qfQK4c3nxitlTj6Mo28SBOfbnZjoq65cyPvw/evI
        YgBwF7naC4gVeqNf6lddYZO8La/8rmDfRrz+r6wQjOuOG4YCa/Gt3FRxUePyZhrDMwa8Kv
        BFmzb2O7Vd2TMlxIttrpjLNAJ4cW4w9QcTUZedDLWu9GyYSOWJRoeHsjKfVzyrTTvrKM9N
        3YVcTEfVdveRE5zAFMc8vMASICOarG3qpI4hy8Mw5fHUxmqHHDSJujPtxJHPMTBY+eCwsr
        nHV1SOimNk3ltjd0v6X+2RPC+KS+NPGm7HMLTNk11hH5La7xJIUa5Qhzd7j13ZEyQcPl/9
        uaiBqUa4X/6ronddHF7cKNlZY8W8d4429XpLHFAdh2AYfd2nOqkjPlSxtheb4gumi3qTxM
        kNb45c5rhQXWWw==
      ENCRYPTED_BASE64
      KEY_NAME = 'ourkey1'.freeze
      ENCRYPTED_ID = '5e7bfaadc549186d65846df2fbe8da97e34ffe27dc6e7b8a192cbdbe28780819'.freeze
      def setup
        # Create encrypted public / private key pair
        @key_dir = Dir.mktmpdir
        @key_name = KEY_NAME
        @private_key_filename = File.join(@key_dir, 'ourkey1.pem')
        @public_key_filename = File.join(@key_dir, 'ourkey1.pub')
        @passphrase = PASSPHRASE
        File.open(@private_key_filename, 'w') { |f| f << SAMPLE_PRIVATE_KEY }
        File.open(@public_key_filename, 'w') { |f| f << SAMPLE_PUBLIC_KEY }

        @sample_image_data = Base64.decode64(SAMPLE_IMAGE_BASE64) # Original image
        @sample_encrypted_image_data = Base64.decode64(SAMPLE_ENCRYPTED_IMAGE_BASE64)
      end

      def teardown
        FileUtils.remove_entry @key_dir
      end

      test 'programmatic retrieval of remote object' do
        # This is essentially the example given in README.md
        base_url = 'https://example.org/encrypted/storage/'
        git_blobid = 'f29bddf64c444f663d106568f4a81a22151ed3f97b0ec0c2a5ab25a0e8a02515'

        remote_repo = NdrPseudonymise::NdrEncrypt::RemoteRepository.new(base_url: base_url)
        # Fake object retrieval without running a webserver
        remote_repo.expects(:retrieve_remote_url).with(ENCRYPTED_ID).
          returns(@sample_encrypted_image_data)
        decrypted_data = remote_repo.cat_remote(
          git_blobid, key_name: @key_name, private_key: @private_key_filename,
                      passin: "pass:#{@passphrase}"
        )
        assert_equal(@sample_image_data.size, decrypted_data.size,
                     'Expected decrypted data to have same size as original image')
        assert_equal(@sample_image_data, decrypted_data,
                     'Expected decrypted data to be identical to original image')
      end

      # TODO: Test error handling
    end
  end
end
