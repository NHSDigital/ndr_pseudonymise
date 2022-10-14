require 'optparse'

module NdrEncrypt
  # ndr_encrypt command line utility entry points.
  module CommandLine
    USAGE = <<-USAGE.gsub(/^      /, '').freeze
      usage: ndr_encrypt [-v | --version] [-h | --help]
                         <command> [<args>]

      These are common ndr_encrypt commands used in various situations:

      start a working area
         init          Create an empty Git ndr_encrypt working copy

      work with files
         add           Add file contents to the encrypted store and index
         rm            TODO: Remove files from the encrypted store and index

      encryption key rotation and repository maintenance
         gc            TODO: Cleanup unnecessary files and optimize the local repository
         resilver      TODO
         retire-key    TODO

      decrypt data
         cat-files     TODO: Retrieve local file based on git_blobid
         cat-remote    Retrieve remote file based on git_blobid
         get           Retrieve local file(s) based on path in CSV index
         TODO: decrypt single file without git_blobid

      Low-level Commands / Interrogators
         cat-file      TODO: Provide content or type and size information for encrypted objects
         ls-files      TODO: Show information about files in the index

      Low-level Commands / Manipulators
         hash-object   TODO: Compute object ID and optionally create an encrypted object from a file
    USAGE

    COMMANDS = %w[init add cat-remote get].freeze

    def self.run!
      options = {}
      parser = OptionParser.new do |opts|
        # Hide TODOs in usage message
        usage = USAGE.split("\n").reject { |s| s =~ /TODO/ }.join("\n")
        opts.banner = "#{usage.chomp}\n\nAdditional options:"

        opts.on('--base_url=URL', 'Remote repository URL') do |url|
          options[:base_url] = url
        end
        opts.on('--key_name=NAME', /[A-Z0-9_-]*/i, 'Key name') do |name|
          options[:key_name] = name
        end
        opts.on('--private_key=NAME', 'Private key filename') do |name|
          options[:private_key] = name
        end
        opts.on('--pub_key=NAME', 'Public key filename') do |name|
          options[:pub_key] = name
        end
        opts.on('--passin=OPTIONS', 'Pass in private key passphrase') do |name|
          options[:passin] = name
        end
        opts.on('-p', 'Print downloaded object') do |v|
          options[:pretty_print] = v
        end
      end

      begin
        parser.parse!
      rescue OptionParser::ParseError => e
        puts e
        exit 1
      end

      parser.parse('--help') if ARGV.empty?
      command = ARGV[0]
      unless COMMANDS.include?(command)
        warn <<-UNKNOWN_CMD
ndr_encrypt: '#{command}' is not an ndr_encrypt command. See 'ndr_encrypt --help'.
        UNKNOWN_CMD
        exit 1
      end
      send(command.gsub('-', '_'), ARGV[1..-1], options)
    end

    def self.init(args, options)
      required_options = %i[]
      allowed_options = required_options
      unless (options.keys - allowed_options).empty? &&
             required_options.all? { |sym| options.key?(sym) } &&
             args.size <= 1
        warn <<-USAGE
usage: ndr_encrypt init [<path>]
        USAGE
        exit 1
      end

      path = args[0] || Dir.pwd
      action = if NdrEncrypt::Repository.new(repo_dir: path).init
                 'Initialized empty'
               else
                 'Reinitialized existing'
               end
      $stdout.puts "#{action} ndr_encrypted encrypted store in " \
                   "#{File.join(File.expand_path(path), NdrEncrypt::Repository::ENCRYPTED_DIR)}"
    end

    def self.add(args, options)
      required_options = %i[key_name pub_key]
      allowed_options = required_options
      unless (options.keys - allowed_options).empty? &&
             required_options.all? { |sym| options.key?(sym) }
        warn <<-USAGE
usage: ndr_encrypt add --key_name=<keyname> --pub_key=<path> [<path>...]
        USAGE
        exit 1
      end
      if args.empty?
        warn 'Nothing specified, nothing added.'
        return
      end

      path = Dir.pwd
      repo = NdrEncrypt::Repository.new(repo_dir: path)
      repo.add(args, key_name: options[:key_name], pub_key: options[:pub_key])
    end

    def self.cat_remote(args, options)
      # TODO: Add -e option to check whether remote file exists
      required_options = %i[key_name private_key base_url pretty_print]
      allowed_options = required_options + %i[passin]
      unless (options.keys - allowed_options).empty? &&
             required_options.all? { |sym| options.key?(sym) } &&
             args.size == 1
        warn <<-USAGE
usage: ndr_encrypt cat-remote --key_name=<keyname> --private_key=<path> --base_url=<url>
                              -p <git_blobid>
        USAGE
        exit 1
      end

      git_blobid = args[0]
      remote_store = NdrEncrypt::RemoteRepository.new(base_url: options[:base_url])
      blob = remote_store.cat_remote(git_blobid, key_name: options[:key_name],
                                                 private_key: options[:private_key],
                                                 passin: options[:passin])
      # TODO: Add error handling, for connection issues / file not found
      $stdout.print blob
    end

    def self.get(args, options)
      required_options = %i[key_name private_key]
      allowed_options = required_options + %i[passin]
      unless (options.keys - allowed_options).empty? &&
             required_options.all? { |sym| options.key?(sym) }
        warn <<-USAGE
usage: ndr_encrypt get --key_name=<keyname> --private_key=<path> [<path>...]
        USAGE
        exit 1
      end
      if args.empty?
        warn 'Nothing specified, nothing to get.'
        return
      end

      path = Dir.pwd
      repo = NdrEncrypt::Repository.new(repo_dir: path)
      repo.get(args, key_name: options[:key_name], private_key: options[:private_key],
                     passin: options[:passin])
    end
  end
end
