require_relative 'task_header'
require 'fileutils'

namespace :deploy do
desc "Perform puma necessary directories"
  task :puma_directories do
    unless Dir.exist?("#{$root_dir}/log")
      FileUtils.mkdir_p("#{$root_dir}/log")
    end
    unless Dir.exist?("#{$root_dir}/tmp")
      FileUtils.mkdir_p("#{$root_dir}/tmp")
    end
    
    unless Dir.exist?("#{$root_dir}/tmp/sockets")
      FileUtils.mkdir_p("#{$root_dir}/tmp/sockets")
    end

    unless Dir.exist?("#{$root_dir}/tmp/pids")
      FileUtils.mkdir_p("#{$root_dir}/tmp/pids")
    end
  end
end