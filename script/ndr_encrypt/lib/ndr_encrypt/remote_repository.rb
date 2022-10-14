require 'net/http'
require 'uri'

module NdrEncrypt
  # Defines a local ndr_encrypt working copy
  class RemoteRepository
    def initialize(base_url: nil)
      # We need to support ruby 2.0 so cannot use required keyword arguments syntax
      raise(ArgumentError, 'missing keyword: :base_url') unless base_url

      @base_url = base_url
    end

    # Retrieve remote file(s) based on git_blobid
    def cat_remote(git_blobid, key_name: nil, private_key: nil, passin: nil)
      # We need to support ruby 2.0 so cannot use required keyword arguments syntax
      raise(ArgumentError, 'missing keyword: :key_name') unless key_name
      raise(ArgumentError, 'missing keyword: :private_key') unless private_key

      encrypted_id = NdrEncrypt::EncryptedObject.encrypted_id(git_blobid, key_name: key_name)
      uri = URI.join(@base_url, "#{encrypted_id[0..1]}/#{encrypted_id[2..-1]}")
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
