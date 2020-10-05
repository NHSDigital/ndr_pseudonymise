require 'securerandom'
require 'json'
require 'csv'
require 'stringio'
require 'rsa_aes_cbc'

module NdrPseudonymise
  # Pseudonymise CSV data for matching purposes
  # Sample format spec:
  # {:core_demographics => [[[0, ' ']],
  #                         [[1, ' ', :upcase], [2, ' ', :upcase]]],
  #  :columns => [
  #    {:title => 'nhsnumber', :maxlength => 12, :format => '\A[0-9A-Z]*\Z',
  #     :format_msg => 'Must contain only numbers, or numbers and letters for old NHS numbers'},
  #    {:title => 'dob', :format => '\A([0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]|)\Z',
  #     :format_msg => 'Must have format YYYY-MM-DD, e.g. 2013-08-20',
  #     :canonical_title => 'birthdate'},
  #    {:title => 'postcode'},
  #    {:title => 'surname'},
  #    {:title => 'data1'},
  #    {:title => 'data2'},
  #  ],
  #  :demographics => [0, 1, 2, 3],
  # }
  # -- delete spaces, upcase, use columns 0+1, 0+2 as keys for core demographics
  # -- treat columns 0, 1, 2, 3 as demographics
  class PseudonymisationSpecification
    KEY_BYTES = 32 # length of randomly generated keys (32 bytes = 256 bits)
    PREAMBLE_V1_STRIPED = 'Pseudonymised matching data v1.0-striped'.freeze
    HEADER_ROW_PREFIX = 'HEADER_ROW'.freeze

    def initialize(format_spec, key_bundle)
      @format_spec = format_spec
      [:core_demographics, :columns, :demographics, :encrypt_clinical].each do |k|
        unless @format_spec.key?(k)
          raise(ArgumentError, "Expected format_spec to have a #{k.inspect} section")
        end
      end
      @format_spec[:columns].each_with_index do |col, i|
        raise(ArgumentError, "Expected format_spec to have a title for column #{i}") unless col.key?(:title)
      end
      unless [true, false].include?(@format_spec[:encrypt_clinical])
        raise(ArgumentError, 'Expected encrypt_clinical to be true or false')
      end
      @salt1 = key_bundle[:salt1]
      @salt2 = key_bundle[:salt2]
      raise(ArgumentError, 'Invalid salt1') unless @salt1 =~ /\A[0-9a-f]*\Z/ && @salt1.size >= 64
      raise(ArgumentError, 'Invalid salt2') unless @salt2 =~ /\A[0-9a-f]*\Z/ && @salt2.size >= 64
    end

    # Builds a pseudonymiser with the preferred pseudonymisation class of the given format spec
    def self.factory(format_spec, key_bundle)
      klass_name = format_spec[:pseudonymisation_class]
      if klass_name
        # Support existing format specifications.
        # (Pseudonymisation classes have now moved to NdrPseudonymise namespace.)
        klass_name = klass_name.sub!(/^Pseudonymisation::/, 'NdrPseudonymise::')
        klass = Object.const_get(klass_name)
        unless klass <= NdrPseudonymise::PseudonymisationSpecification
          raise(ArgumentError, "Invalid pseudonymisation_class #{klass_name}")
        end
      else
        klass = NdrPseudonymise::PseudonymisationSpecification
      end
      klass.new(format_spec, key_bundle)
    end

    def random_key
      SecureRandom.hex(KEY_BYTES)
    end

    # Returns arrays of core demographics field values, each of the form
    # e.g. [[['nhsnumber', '1234567881']],
    #       [['birthdate', '2010-08-21'], ['postcode', 'CB22 3AD']]]
    # Column titles can be remapped using a :canonical_title entry, to ensure
    # consistent pseudo_ids even when column titles are predefined.
    def core_demographics(row)
      @format_spec[:core_demographics].collect do |fields|
        fields.collect do |col_num, delchar, modifier|
          val = row[col_num].to_s
          val = val.to_s.delete(delchar) if delchar
          case modifier
          when :upcase
            val = val.upcase
          when nil
          else
            raise "Unknown modifier #{modifier.inspect} for core_demographics"
          end
          row_spec = @format_spec[:columns][col_num]
          [row_spec[:canonical_title] || row_spec[:title], val]
        end
      end
    end

    # List of pseudonymised ids, based on this row's core demographics + salt1
    def real_ids(row)
      core_demographics(row).collect do |fields|
        (fields.collect(&:first) +
         fields.collect(&:last)).collect { |s| s.gsub('_', '__') }.join('_')
      end
    end

    # Convert a real id to a pseudonymised id
    def pseudo_id(real_id)
      data_hash(real_id, @salt1)
    end

    def data_hash(value, salt)
      Digest::SHA2.hexdigest(value.to_s + salt.to_s)
    end

    def encrypt_data(data, pseudo_id, partial_crypt_key, salt)
      if [pseudo_id, partial_crypt_key, salt].any? { |s| s.to_s.blank? }
        raise(ArgumentError, 'Expected all key arguments to be non-blank')
      end
      key = "#{pseudo_id}#{partial_crypt_key}#{salt}"
      # unless key =~ /\A[0-9a-f]+\Z/
      #  raise(ArgumentError, 'Expected key to be all hex characters (0-9, a-f)')
      # end
      aes = OpenSSL::Cipher.new('AES-256-CBC')
      aes.encrypt
      aes.key = Digest::SHA256.digest(key)
      Base64.strict_encode64(aes.update(data) + aes.final)
    end

    def decrypt_data(data, pseudo_id, partial_crypt_key, salt)
      key = "#{pseudo_id}#{partial_crypt_key}#{salt}"
      aes = OpenSSL::Cipher.new('AES-256-CBC')
      aes.decrypt
      aes.key = Digest::SHA256.digest(key)
      aes.update(Base64.strict_decode64(data)) + aes.final
    end

    def self.get_key_bundle(key_fname, admin_password)
      data = File.read(key_fname)
      aes = OpenSSL::Cipher.new('AES-256-CBC')
      aes.decrypt
      aes.key = Digest::SHA256.digest(admin_password)
      begin
        bundle = YAML.load(aes.update(Base64.decode64(data)) + aes.final)
        # Check that the bundle decoded successfully
        raise('Invalid bundle - not a hash') unless bundle.is_a?(Hash)
        bundle
      rescue # => e # Lint/UselessAssignment
        raise('Wrong password or invalid bundle')
      end
    end

    def all_demographics(row)
      # TODO: What about rows with missing fields?
      result = []
      demographics_cols = @format_spec[:demographics]
      row.each_with_index do |x, i|
        result << x if demographics_cols.include?(i)
      end
      result
    end

    def clinical_data(row)
      # TODO: What about rows with missing fields?
      result = []
      demographics_cols = @format_spec[:demographics]
      row.each_with_index do |x, i|
        result << x unless demographics_cols.include?(i)
      end
      result
    end

    # Pseudonymise a row of data, returning 3 sets of rows:
    # [index_rows, demographics_rows, clinical_rows]
    def pseudonymise_row(row)
      index_rows = []
      demographics_rows = []
      clinical_rows = []
      real_ids(row).each do |real_id|
        pseudo = pseudo_id(real_id)
        row_key = random_key
        partial_crypt_key1 = random_key # middle bit of crypto key
        if @format_spec[:encrypt_clinical]
          partial_crypt_key2 = random_key # middle bit of crypto key
          index_rows << [pseudo, row_key, partial_crypt_key1, partial_crypt_key2]
        else
          index_rows << [pseudo, row_key, partial_crypt_key1]
        end
        # demographics and clinical files only have non-information-bearing keys
        demographics_rows << [row_key,
                              encrypt_data(safe_json(all_demographics(row)),
                                           pseudo, partial_crypt_key1, @salt2)]
        safe_clinical = safe_json(clinical_data(row))
        if @format_spec[:encrypt_clinical]
          safe_clinical = encrypt_data(safe_clinical,
                                       pseudo, partial_crypt_key2, @salt2)
        end
        clinical_rows << [row_key, safe_clinical]
      end
      [index_rows, demographics_rows, clinical_rows]
    end

    # Convert data to json, but raise exception if it won't safely deserialise
    def safe_json(data)
      result = data.to_json
      unless data == JSON.load(result)
        raise(ArgumentError, "Expected consistent JSON serialisation of #{data.inspect}")
      end
      result
    end

    # Return true if this row is a valid header row, according to the spec
    def header_row?(row)
      expected_keys = @format_spec[:columns].collect { |col| col[:title] }
      row_keys = row.collect(&:downcase)
      if (row_keys & expected_keys).size >= 3 # at least 3 common keys
        if row_keys == expected_keys
          true # Only expected keys, in right order
        else
          raise(ArgumentError, "Error: invalid header row; expected keys #{expected_keys.inspect}, actually #{row_keys.inspect}")
        end
      else
        false
      end
    end

    # Return false if this row is a valid data row, otherwise a list of errors
    def row_errors(row)
      @check_cols ||= begin
                        check_cols = []
                        @format_spec[:columns].each_with_index do |col, i|
                          # Unpack column checking meta-data proactively
                          if col[:maxlength] || col[:format]
                            check_cols << [col, i, col[:maxlength],
                                           col[:format] && Regexp.new(col[:format])]
                          end
                        end
                        check_cols
                      end
      @dmax ||= @format_spec[:core_demographics].flatten(1).collect(&:first).max
      if row.size <= @dmax + 1
        "Missing core demographics: at least #{@dmax} columns expected"
      elsif row[@format_spec[:columns].size..-1].to_a.any? { |s| !s.blank? }
        "Too many columns (#{row.size}); expected #{@format_spec[:columns].size}"
      else
        # Check field formats
        errs = []
        @check_cols.each do |col, i, col_maxlength, col_format_re|
          val = row[i].to_s # Missing columns treated as blank
          if col_maxlength && val.size > col_maxlength
            errs << "Field #{col[:title]} (column #{i + 1}) is longer than maxlength #{col[:maxlength]}."
          end
          if col_format_re
            unless col_format_re.match(val)
              if col[:format_msg]
                errs << "Field #{col[:title]} (column #{i + 1}) #{col[:format_msg]} -- invalid value: #{val}"
              else
                errs << "Field #{col[:title]} (column #{i + 1}) does not match format #{col[:format].inspect} -- invalid value: #{val}"
              end
            end
          end
        end
        if errs.empty?
          false
        else
          errs.join(', ')
        end
      end
    end

    # Header row for CSV data
    def csv_header_row
      [PREAMBLE_V1_STRIPED]
    end

    # Append the output of pseudonymise_row to a CSV file
    def emit_csv_rows(out_csv, pseudonymised_row)
      (index_rows, demographics_rows, clinical_rows) = pseudonymised_row
      unless index_rows.size == demographics_rows.size &&
             index_rows.size == clinical_rows.size
        raise(ArgumentError, <<-ERROR
Mismatch in number of index_rows (#{index_rows.size})
vs demographics_rows (#{demographics_rows.size})
vs clinical_rows (#{clinical_rows.size})
ERROR
            )
      end

      index_rows.zip(demographics_rows).zip(clinical_rows).collect do |(index_row, demographics_row), clinical_row|
        # Alternate each of 3 data types into 1 output file
        out_csv << index_row
        out_csv << demographics_row
        out_csv << clinical_row
      end
    end

    # csv_data can be an open IO object (a CSV file), or an array of data rows
    # out_data can be an open IO object or a StringIO -- CSV data is output
    # public_key_fname supports public key encryption of the output
    # progress_monitor is an object for reporting progress, that responds to
    #   log_progress(start_time, time_now, csv_row, progress, total)
    # where progress and total are in the same units, either bytes or rows
    def pseudonymise_csv(csv_data, out_data, public_key_fname = nil, progress_monitor = nil)
      csv_lib = CSV
      if csv_data.is_a?(IO) || csv_data.is_a?(StringIO)
        csv = csv_lib.new(csv_data)
      elsif csv_data.is_a?(Array)
        csv = csv_data
      else
        raise(ArgumentError, 'Expected an IO or Array of rows, not a filename for csv_data')
      end

      if public_key_fname
        unless File.exist?(public_key_fname)
          raise(ArgumentError, "Missing public key file: #{public_key_fname}")
        end
        rsa_aes_cbc = RSA_AES_CBC.new(File.read(public_key_fname), nil)
      end

      unless out_data.respond_to?('<<')
        raise(ArgumentError, 'Expected an IO or writeable structure for out_data')
      end
      out_buff = StringIO.new
      out_csv = csv_lib.new(out_buff)
      out_csv << csv_header_row
      out_buff.rewind
      out_data <<
        if public_key_fname
          rsa_aes_cbc.encrypt(out_buff.read) + "\n"
        else
          out_buff.read
        end

      i = 0
      t0 = Time.current
      csv_size = progress_monitor && csv_data.size
      csv.each do |row|
        out_buff = StringIO.new
        out_csv = csv_lib.new(out_buff)
        i += 1
        if i == 1 && header_row?(row)
          # Preserve header row in output
          out_csv << [HEADER_ROW_PREFIX] + row
        else
          errs = row_errors(row)
          raise("Invalid row #{i}: #{errs}") if errs
          begin
            emit_csv_rows(out_csv, pseudonymise_row(row))
          rescue ArgumentError, RuntimeError => e
            raise(ArgumentError, "Invalid row #{i}: #{e}", e.backtrace)
          end
        end
        out_buff.rewind
        out_data <<
          if public_key_fname
            rsa_aes_cbc.encrypt(out_buff.read) + "\n"
          else
            out_buff.read
          end

        # Current runs at about 325 rows per second for prescription data 2016-05-09 ruby 2.3.1
        # so try to log progress about every 15 seconds
        if (i % 5000) == 0 && progress_monitor
          progress_monitor.log_progress(t0, Time.current, i, csv.is_a?(Array) ? i : csv.pos, csv_size)
        end
      end
      if (i % 5000) != 0 && progress_monitor
        progress_monitor.log_progress(t0, Time.current, i, csv_size, csv_size)
      end
    end

    # Decrypt public key encrypted data to a CSV file
    # encrypted_data can be an open IO object (a file), or an array of data rows
    # out_data can be an open IO object or a StringIO -- CSV data is output
    def decrypt_to_csv(encrypted_data, out_data, public_key_fname, private_key_fname)
      rsa_aes_cbc = RSA_AES_CBC.new(File.read(public_key_fname),
                                    File.read(private_key_fname))
      encrypted_data.each do |crypto_data|
        out_data << rsa_aes_cbc.decrypt(crypto_data)
      end
    end
  end
end
