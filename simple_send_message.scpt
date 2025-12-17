#!/usr/bin/osascript

-- Simple ChatGPT message sender
on run argv
	if (count of argv) < 1 then
		return "Usage: osascript simple_send_message.scpt 'Your message here'"
	end if

	set theMessage to item 1 of argv

	tell application "ChatGPT"
		activate
	end tell

	delay 1

	tell application "System Events"
		tell process "ChatGPT"
			-- Click in the message area (bottom center)
			try
				set frontmost to true
				delay 0.5

				-- Type the message
				keystroke theMessage
				delay 0.3

				-- Send with Enter
				keystroke return

				log "Message sent successfully"
				return "SUCCESS"
			on error errMsg
				log "Error: " & errMsg
				return "ERROR: " & errMsg
			end try
		end tell
	end tell
end run
