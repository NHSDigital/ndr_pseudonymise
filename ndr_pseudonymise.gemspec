lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'ndr_pseudonymise/version'

Gem::Specification.new do |spec|
  spec.name          = 'ndr_pseudonymise'
  spec.version       = NdrPseudonymise::VERSION
  spec.authors       = ['NCRS development team']
  spec.email         = []

  spec.summary       = 'Provide pseudonymisation facilities.'
  spec.description   = 'Provide pseudonymisation facilities.'
  # spec.homepage    = 'TODO: Put your gem's website or public repo URL here.'

  # Prevent pushing this gem to RubyGems.org by setting 'allowed_push_host', or
  # delete this section to allow pushing this gem to any host.
  if spec.respond_to?(:metadata)
    spec.metadata['allowed_push_host'] = %(TODO: Set to 'http://mygemserver.com')
  else
    raise 'RubyGems 2.0 or newer is required to protect against public gem pushes.'
  end

  spec.files         = `git ls-files -z`.split("\x0").reject { |f| f.match(%r{^(test|spec|features)/}) }
  spec.bindir        = 'exe'
  spec.executables   = spec.files.grep(%r{^exe/}) { |f| File.basename(f) }
  spec.require_paths = ['lib']

  # Object methods like .blank?
  spec.add_dependency 'activesupport'

  spec.add_development_dependency 'activesupport'
  spec.add_development_dependency 'bundler'
  spec.add_development_dependency 'minitest', '>= 5.0'
  spec.add_development_dependency 'mocha'
  spec.add_development_dependency 'ndr_dev_support', '>= 6.0'
  spec.add_development_dependency 'ndr_import'
  spec.add_development_dependency 'pry'
  spec.add_development_dependency 'rake', '>= 10.0'
end
