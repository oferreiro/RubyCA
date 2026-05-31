require_relative 'task_header'
require 'fileutils'

namespace :deploy do
desc "Perform create puma necessary directories"
  task :puma_directories do
    directories = ["log", "tmp", "tmp/sockets", "tmp/pids"]
    for dir in directories
      unless Dir.exist?("#{$root_dir}/#{dir}")
        puts "Creating directory: #{$root_dir}/#{dir}"
        FileUtils.mkdir_p("#{$root_dir}/#{dir}")
      end
    end
  end
end