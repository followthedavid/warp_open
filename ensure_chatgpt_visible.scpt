#!/usr/bin/osascript

tell application "ChatGPT"
	activate
	reopen
end tell

delay 1

tell application "System Events"
	tell process "ChatGPT"
		set frontmost to true

		-- Try to unhide and bring all windows forward
		set visible to true

		try
			-- Get the main window
			set theWindows to windows
			if (count of theWindows) > 0 then
				set theWindow to window 1
				-- Make sure it's not minimized
				set value of attribute "AXMinimized" of theWindow to false
			end if
		end try
	end tell
end tell

delay 0.5

return "ChatGPT should now be visible"
