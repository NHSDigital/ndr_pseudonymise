lib = File.expand_path('lib', __dir__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'ndr_pseudonymise/version'

Gem::Specification.new do |spec|
  spec.name          = 'ndr_pseudonymise'
  spec.version       = NdrPseudonymise::VERSION
  spec.authors       = ['NCRS development team']
  spec.email         = []

  spec.summary       = 'Provide pseudonymisation facilities.'
  spec.description   = 'Provide pseudonymisation facilities.'
  spec.homepage      = 'https://github.com/NHSDigital/ndr_pseudonymise'
  spec.license       = 'MIT'

  ignore_files_re    = %r{^(\.github|test|spec|features|gemfiles|)/|.travis.yml|code_safety.yml}
  spec.files         = `git ls-files -z`.split("\x0").
                       reject { |f| f.match(ignore_files_re) }
  spec.bindir        = 'exe'
  spec.executables   = spec.files.grep(%r{^exe/}) { |f| File.basename(f) }
  spec.require_paths = ['lib']

  # Object methods like .blank?
  spec.add_dependency 'activesupport'

  # We list development dependencies for all Rails versions here.
  # Rails version-specific dependencies can go in the relevant Gemfile.
  # rubocop:disable Gemspec/DevelopmentDependencies
  spec.add_development_dependency 'activesupport'
  spec.add_development_dependency 'bundler'
  spec.add_development_dependency 'minitest', '>= 5.0'
  spec.add_development_dependency 'mocha'
  spec.add_development_dependency 'ndr_dev_support', '>= 1.1'
  spec.add_development_dependency 'ndr_import'
  spec.add_development_dependency 'pry'
  spec.add_development_dependency 'rake', '>= 12.3.3'
  # rubocop:enable Gemspec/DevelopmentDependencies

  # Ruby 2.6.0 or later expected for normal operation, and needed for testing,
  # but we support 2.0.0 for the ndr_encrypt utility
  spec.required_ruby_version = '>= 2.0.0'
end
