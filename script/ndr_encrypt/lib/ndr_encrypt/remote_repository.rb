require 'net/http'
require 'uri'

module NdrEncrypt
  # Defines a local ndr_encrypt working copy
  class RemoteRepository
    def initialize(base_url:)
      @base_url = base_url
    end

    # Retrieve remote file(s) based on git_blobid
    def cat_remote(git_blobid, key_name:, private_key:, passin:)
      encrypted_id = NdrEncrypt::EncryptedObject.encrypted_id(git_blobid, key_name: key_name)
      uri = URI.join(@base_url, "#{encrypted_id[0..1]}/#{encrypted_id[2..]}")
      res = Net::HTTP.get_response(uri)
      # TODO: More finegrained error messages
      raise(ArgumentError, 'Could not retrieve URL') unless res.is_a?(Net::HTTPSuccess)

      rawdata = res.body
      contents = NdrEncrypt::EncryptedObject.decrypt(rawdata, private_key: private_key,
                                                              passin: passin)
      blob = NdrEncrypt::EncryptedObject.decompress(contents)
      NdrEncrypt::EncryptedObject.unpack_blob(blob)
    end
  end
end
