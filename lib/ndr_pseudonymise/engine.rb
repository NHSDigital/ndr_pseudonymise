module NdrPseudo
  # base class for the engine
  class Engine < ::Rails::Engine
    config.eager_load_paths << File.expand_path('../../lib', __FILE__)
  end
end
