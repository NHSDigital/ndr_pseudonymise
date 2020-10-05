require 'json'
require 'csv'
# require 'pry'
require 'logger'

# To convert files from the command line, see pseudonymised_file_converter.rb, which has a
# CLI set up. To use this wrapper to convert files from within a ruby program:
#
#  wrapper = PseudonymisedFileWrapper.new(<filename>)
#  wrapper.process
#  wrapper.pretty_write
#
# This will create an excel-readable copy of the file in the same location as the original.
# The new file will be named the same as the original, with .pseudo converted to _pretty.csv
# There is a column for every field present in any record, and the column name is prefixed
# by 'mapped' or 'raw' according to which column it was in in the .pseudo version.
# As this is only intended for human viewing, the values of encrypted fields are not output.
# This conveniently has the effect of making the csv files notable smaller than their
# .pseudo counterparts
# 

# Provide the ability to extract fieldnames and create CSV output from .pseudo files
class PseudonymisedFileWrapper
  def initialize(filename)
    @filename = filename
    @logger = Logger.new(STDOUT)
  end

  def available_fields
    (@all_fields1 + @all_fields2).sort.uniq
  end

  # Read in the source file, accumulating all the field names used in any row
  def process
    line_counter = 1
    processed_lines = []
    all_fields1 = []
    all_fields2 = []
    CSV.foreach(@filename) do |row|
      if row.size == 1
      # Header; do nothing
      elsif row.size == 7
        cur = { map1: JSON.parse(row[4]),
                map2: JSON.parse(row[6]),
                id1: row[0],
                id2: row[1],
                keys: row[2] }
        processed_lines.push(cur)
        all_fields1.push(*cur[:map1].keys).uniq!
        all_fields2.push(*cur[:map2].keys).uniq!
      else
        @logger.debug"Line #{line_counter} contained unexpected number of fields: #{row.size}"
      end
      line_counter += 1
    end
    @lines = line_counter
    @all_fields1 = all_fields1
    @all_fields2 = all_fields2
    @processed_lines = processed_lines
  end

  # Create an excel-readable CSV file, in the same location as the original
  def pretty_write
    /(?<base_name>.*)\.(?:csv|(?:zip|xlsx?)\.pseudo)/i.match(@filename)
    target_filename = "#{$LAST_MATCH_INFO[:base_name]}_pretty.csv"
    @logger.debug "Writing output to #{target_filename}"
    CSV.open(target_filename, 'w') do |file|
      headers = (@all_fields1.map { |name| "mapped:#{name}" } +
                 @all_fields2.map { |name| "raw:#{name}" } +
                 %w(pseudo_id1 pseudo_id2 key_bundle))
      file << headers
      @processed_lines.each do |line|
        output_fields = @all_fields1.map { |field| line[:map1][field] } +
                        @all_fields2.map { |field| line[:map2][field] }
        output_fields.push(line[:id1], line[:id2], line[:keys])
        file << output_fields
      end
    end
  end

  def pretty_data
    csv_string = CSV.generate do |csv|
      headers = (@all_fields1.map { |name| "mapped:#{name}" } +
      @all_fields2.map { |name| "raw:#{name}" } +
      %w(pseudo_id1 pseudo_id2 key_bundle))
      csv << headers
      @processed_lines.each do |line|
        output_fields = @all_fields1.map { |field| line[:map1][field] } +
        @all_fields2.map { |field| line[:map2][field] }
        output_fields.push(line[:id1], line[:id2], line[:keys])
        csv << output_fields
      end
    end
    csv_string
  end
end
