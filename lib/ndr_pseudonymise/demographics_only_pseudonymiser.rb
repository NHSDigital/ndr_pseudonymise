# Fast, simple pseudonymisation of prescription data with a very controlled
# format.
# Only the first 2 fields are potentially identifiable: nhs number and date of
# birth.

require 'ndr_pseudonymise/simple_pseudonymisation'
require 'ndr_pseudonymise/pseudonymisation_specification'

require 'json'

module NdrPseudonymise
  # Pseudonymise prescription data
  class DemographicsOnlyPseudonymiser < PseudonymisationSpecification
    PREAMBLE_V2_DEMOG_ONLY = 'Pseudonymised matching data v2.0-demog-only'.freeze

   # Pseudonymise a row of prescription data, returning an array of a single row:
    # [[packed_pseudoid_and_demographics, clinical_data1, ...]]
    # Where packed_pseudoid_and_demographics consists of
    # "pseudo_id1 (key_bundle) packed_pseudoid_and_demographics"
    def pseudonymise_row(row)
      @key_cache ||= {} # Cache pseudonymisation keys for more compact import
      # all_demographics = { 'nhsnumber' => row[0], 'birthdate' => row[1] }
      all_demographics_hash = {}
      demographics_cols = @format_spec[:demographics]
      row.each_with_index do |x, i|
        row_spec = @format_spec[:columns][i]
        all_demographics_hash[row_spec[:title]] = x if demographics_cols.include?(i)
      end

      # TODO: Refactor date handling into parent class's all_demographics_hash method
      demographics_cols = @format_spec[:demographics]
      row.each_with_index do |x, i|
        row_spec = @format_spec[:columns][i]
        if row_spec[:canonical_title]
          if x.present? && row_spec[:strptime] && row_spec[:strftime]
            # :strptime can contain a String (single format) or Array (a list of formats)
            # :strftime contains a single string format
            datetime = false
            [row_spec[:strptime]].flatten(1).each do |format|
              begin
                datetime = DateTime.strptime(x, format)
                break
              rescue ArgumentError # Keep trying after invalid date formats
              end
            end
            raise ArgumentError.new('Invalid date') if datetime == false # No formats matched
            val = datetime.strftime(row_spec[:strftime])
          else
            val = x
          end
          all_demographics_hash[row_spec[:canonical_title]] = val
        end

      end

      # Ensure NHS number is empty string (expected by SimplePseudonymisation), not nil
      all_demographics_hash['nhsnumber'] = all_demographics_hash['nhsnumber'].to_s
      nhsnumber = all_demographics_hash['nhsnumber']
      birthdate = all_demographics_hash['birthdate']
      key = all_demographics_hash.to_json
      if @key_cache.key?(key)
        pseudo_id1, key_bundle, demog_key = @key_cache[key]
      else
        pseudo_id1, key_bundle, demog_key = NdrPseudonymise::SimplePseudonymisation.
                                            generate_keys_nhsnumber_demog_only(@salt1, @salt2, nhsnumber)
        if !nhsnumber.to_s.empty? && !birthdate.to_s.empty? # && false to stop caching
          @key_cache = {} if @key_cache.size > 1000 # Limit cache size
          @key_cache[key] = [pseudo_id1, key_bundle, demog_key]
        end
      end
      encrypted_demographics = NdrPseudonymise::SimplePseudonymisation.
                               encrypt_data64(demog_key, all_demographics_hash.to_json)
      packed_pseudoid_and_demographics = format('%s (%s) %s', pseudo_id1, key_bundle,
                                                encrypted_demographics)
      [[packed_pseudoid_and_demographics] + clinical_data(row)]
    end

    # Header row for CSV data
    def csv_header_row
      [PREAMBLE_V2_DEMOG_ONLY]
    end

    # Append the output of pseudonymise_row to a CSV file
    def emit_csv_rows(out_csv, pseudonymised_row)
      out_csv << pseudonymised_row[0]
    end
  end
end
