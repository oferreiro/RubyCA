if __FILE__ == $0 then abort 'This file forms part of RubyCA and is not designed to be called directly. Please run ./RubyCA instead.' end

module Sinatra
  module Flash
    Style.module_eval do

      def styled_flash(key=:flash)
        return "" if flash(key).empty?
        id = (key == :flash ? "flash" : "flash_#{key}")
        #<div class="alert alert-${type} alert-dismissible" >`,
        # `   <div>${message}</div>`,
        # '   <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>',
        # '</div>'
        messages = flash(key).collect { |message|
          "<div class='alert alert-dismissible alert-#{message[0]}'><button type='button' class='btn-close' data-bs-dismiss='alert' aria-label='Close'></button><strong>#{message[0].capitalize}: </strong>#{message[1]}</div>\n"
        }
        messages.join
      end
      
    end
  end
end