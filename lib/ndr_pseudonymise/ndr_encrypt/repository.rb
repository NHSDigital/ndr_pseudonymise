require 'csv'
require 'fileutils'
require 'set'
require 'stringio'

module NdrPseudonymise
  module NdrEncrypt
    # Defines a local ndr_encrypt working copy
    class Repository
      # rubocop:disable Style/SlicingWithRange
      CSV_COLUMNS = %w[git_blobid path].freeze
      ENCRYPTED_DIR = 'ndr_encrypted/'.freeze

      def initialize(repo_dir: nil)
        # We need to support ruby 2.0 so cannot use required keyword arguments syntax
        raise(ArgumentError, 'missing keyword: :repo_dir') unless repo_dir

        @repo_dir = repo_dir
      end

      # Create directory structure
      def init
        FileUtils.mkdir_p(object_dir)
        return false if valid_repository?

        CSV.open(index_filename, 'wb') { |csv| csv << CSV_COLUMNS }
        true
      end

      # Add file contents to the encrypted store and index
      def add(paths, key_name: nil, pub_key: nil)
        # We need to support ruby 2.0 so cannot use required keyword arguments syntax
        raise(ArgumentError, 'missing keyword: :key_name') unless key_name
        raise(ArgumentError, 'missing keyword: :pub_key') unless pub_key
        raise(ArgumentError, 'Invalid ndr_encrypted encrypted store') unless valid_repository?

        paths.each do |path|
          git_blobid, _encrypted_id = hash_object(path,
                                                  key_name: key_name, pub_key: pub_key, write: true)
          File.open(index_filename, 'ab') { |f| f << [git_blobid, path].to_csv }
        end
      end

      # Cleanup unnecessary index entries and optimize the encrypted store
      def gc(output_stream: StringIO.new)
        raise(ArgumentError, 'Invalid ndr_encrypted encrypted store') unless valid_repository?

        output_stream.print('Reading index: ')
        csv_data = CSV.read(index_filename)
        header = csv_data.shift
        raise(ArgumentError, 'Invalid header in index file') unless CSV_COLUMNS == header

        count0 = csv_data.size
        output_stream.print("#{count0} entries.\nRemoving duplicates: ")
        csv_data.each.with_index do |row, i|
          unless row.size == 2 && row[0] =~ /\A[0-9a-f]+\z/
            raise(ArgumentError, "Invalid index entry on data row #{i + 1}")
          end
        end
        csv_data = csv_data.sort.uniq
        count1 = csv_data.size
        output_stream.print("#{count1} entries remaining.\nWriting objects: ")
        # Move aside index file temporarily to reduce race conditions
        # Note: should use a proper lock file for all index interactions
        orig_filename = "#{index_filename}.orig"
        temp_filename = "#{index_filename}.new"
        FileUtils.mv(index_filename, "#{index_filename}.orig")
        CSV.open(temp_filename, 'wb') do |csv|
          csv << header
          csv_data.each { |row| csv << row }
        end
        FileUtils.mv(temp_filename, index_filename)
        FileUtils.rm(orig_filename)
        output_stream.puts("100% (#{count1}/#{count1}), done.\n")
        output_stream.puts("Total #{count1} (delta #{count0 - count1})")
      end

      # Retrieve local file(s) based on CSV entry
      def get(paths, key_name: nil, private_key: nil, passin: nil)
        # We need to support ruby 2.0 so cannot use required keyword arguments syntax
        raise(ArgumentError, 'missing keyword: :key_name') unless key_name
        raise(ArgumentError, 'missing keyword: :private_key') unless private_key
        raise(ArgumentError, 'Invalid ndr_encrypted encrypted store') unless valid_repository?

        path_set = Set.new(paths)
        paths = path_set.to_a # Keep only unique entries
        found = Set.new # index may have duplicate objects if not garbage collected
        CSV.foreach(index_filename, headers: true) do |row|
          # Only keep first matching entry for each path
          if path_set.include?(row['path'])
            found << row
            path_set.delete(row['path'])
            break if path_set.empty?
          end
        end
        raise(ArgumentError, 'Cannot find some files') unless found.size == paths.size

        found.each do |row|
          data = cat_file(row['git_blobid'], key_name: key_name, private_key: private_key,
                                             passin: passin)
          File.open(row['path'], 'wb') { |f| f << data }
        end
      end

      # Compute object IDs and optionally creates an encrypted object from a file
      # Returns [git_blobid, encrypted_id]
      def hash_object(path, key_name: nil, pub_key: nil, write: nil)
        # We need to support ruby 2.0 so cannot use required keyword arguments syntax
        raise(ArgumentError, 'missing keyword: :key_name') unless key_name
        raise(ArgumentError, 'missing keyword: :pub_key') unless pub_key

        data = File.binread(path)
        blob = NdrEncrypt::EncryptedObject.blob(data)
        git_blobid = NdrEncrypt::EncryptedObject.digest(blob)
        encrypted_id = NdrEncrypt::EncryptedObject.encrypted_id(git_blobid, key_name: key_name)
        if write
          encrypted_dir = File.join(object_dir, encrypted_id[0..1])
          encrypted_filename = File.join(encrypted_dir, encrypted_id[2..-1])
          unless File.exist?(encrypted_filename) # Don't override existing file
            contents = NdrEncrypt::EncryptedObject.compress(blob)
            encrypted_contents = NdrEncrypt::EncryptedObject.encrypt(contents, pub_key: pub_key)
            FileUtils.mkdir_p(encrypted_dir)
            File.open(encrypted_filename, 'wb') { |f| f << encrypted_contents }
          end
        end
        [git_blobid, encrypted_id]
      end

      # Retrieve local file(s) based on git_blobid
      def cat_file(git_blobid, key_name: nil, private_key: nil, passin: nil)
        # We need to support ruby 2.0 so cannot use required keyword arguments syntax
        raise(ArgumentError, 'missing keyword: :key_name') unless key_name
        raise(ArgumentError, 'missing keyword: :private_key') unless private_key

        encrypted_id = NdrEncrypt::EncryptedObject.encrypted_id(git_blobid, key_name: key_name)
        encrypted_filename = File.join(object_dir, encrypted_id[0..1], encrypted_id[2..-1])
        unless File.exist?(encrypted_filename)
          raise(ArgumentError, 'File does not exist in encrypted storage')
        end

        rawdata = File.binread(encrypted_filename)
        contents = NdrEncrypt::EncryptedObject.decrypt(rawdata, private_key: private_key,
                                                                passin: passin)
        blob = NdrEncrypt::EncryptedObject.decompress(contents)
        NdrEncrypt::EncryptedObject.unpack_blob(blob)
      end

      private

      # Does the repository have a valid structure
      def valid_repository?
        Dir.exist?(object_dir) && File.exist?(index_filename)
      end

      def object_dir
        File.join(@repo_dir, ENCRYPTED_DIR, 'objects')
      end

      def index_filename
        File.join(@repo_dir, ENCRYPTED_DIR, 'index.csv')
      end
      # rubocop:enable Style/SlicingWithRange
    end
  end
end
