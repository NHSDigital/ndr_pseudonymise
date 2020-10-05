require 'optparse'
require 'logger'
require_relative 'pseudonymised_file_wrapper'

# This is primarily a CLI to pseudonymised_file_wrapper.rb, with a few additional bells
# and whistles. For details about the output format of individual files, see the comments
# in the wrapper.
#
# run: bundle exec ruby pseydonymised_file_converter.rb <filename>
logger = Logger.new(STDOUT)
options = { mode: :pretty_write,
            direction: :horizontal,
            include_name: true,
            comparison_mode: false }
OptionParser.new do |opts|
  opts.banner = 'Usage; pseudonymised_file_converter <filenames> [options]'
  opts.on('-f',
          '--fields',
          'Report available fields') { options[:mode] = :report_fields }
  opts.on('-v',
          '--vertical',
          'Report available fields vertically') { options[:direction] = :vertical }
  opts.on('-n',
          '--no-name',
          'Exclude filename in horizontal printing') { options[:include_name] = false }
  # Handy for inspecting numerous files form one provider with different field sets.
  # This option figures out which fields are common to all the provided files, then
  # groups files by the sets of fields which distinguish them
  opts.on('-c',
          '--compare-fields',
          'Figure out available filds') { options[:comparison_mode] = true }
  opts.on('-b', '--batch x y z', Array, 'Not yet implemented!') do |list|
    options[:files] = list
  end
end.parse!

raise 'No filename provided' unless ARGV

if options[:comparison_mode]
  results = {}
  (ARGV + STDIN.readlines.map(&:strip)).each do |file|
    fw = PseudonymisedFileWrapper.new(file)
    fw.process
    results[file] = fw.available_fields
  end

  common_fields = results.map { |_k, v| v }.inject(:&)
  logger.debug 'Common fields: '
  common_fields.each do |field|
    logger.debug "\t#{field}"
  end

  files_and_fields = results.map { |k, v| [k, v - common_fields] }

  files_and_fields.chunk { |_k, v| v } .each do |_k, v|
    logger.debug '********* Field Chunk *********'
    if v[0][0]
      v[0][1].each do |field|
        logger.debug "\t#{field}"
      end
    end

    logger.debug ''
    v.each do |file, _fields|
      logger.debug "\t#{file}"
    end
    logger.debug ''
  end
else
  ARGV.each do |file|
    logger.debug file
    logger.debug file.class
    fw = PseudonymisedFileWrapper.new(file)
    fw.process
    case options[:mode]
    when :pretty_write
      fw.pretty_write
    when :report_fields
      case options[:direction]
      when :horizontal
        logger.debug "#{file if options[:include_name]}: #{fw.available_fields.sort}"
      when :vertical
        logger.debug "#{file}: "
        fw.available_fields.sort.each do |field|
          logger.debug "\t#{field}"
        end
      end
    end
  end
end

# *************** Read in the file, parsing and recording fields in each line **************
