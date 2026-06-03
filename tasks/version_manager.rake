# lib/tasks/version.rake

namespace :version do
  desc "Show the current application version"
  task :current do
    if File.exist?('version')
      puts "Current Version: #{File.read('version').strip}"
    else
      puts "No VERSION file found. Use rake version:bump[major|minor|patch] to create one."
    end
  end

  desc "Bump the version (args: major, minor, or patch)"
  task :bump, [:type] => :environment do |t, args|
    type = args[:type] || 'patch'
    
    # Default initial version
    current_version = "0.0.0"
    
    if File.exist?('version')
      current_version = File.read('version').strip
    end
    
    # Split version into components
    major, minor, patch = current_version.split('.').map(&:to_i)
    
    case type.to_s.downcase
    when 'major'
      major += 1
      minor = 0
      patch = 0
    when 'minor'
      minor += 1
      patch = 0
    else # default to patch
      patch += 1
    end
    
    new_version = "#{major}.#{minor}.#{patch}"
    
    # Write the new version back to the file
    File.write('version', new_version)
    puts "Application bumped to version: #{new_version}"
  end
end
