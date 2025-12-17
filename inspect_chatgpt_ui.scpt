-- UI Element Inspector for ChatGPT Desktop
-- This script enumerates all UI elements to find where responses are stored

tell application "ChatGPT"
	activate
end tell

delay 1

tell application "System Events"
	tell process "ChatGPT"
		-- Get the main window
		set frontWindow to window 1

		-- Function to recursively inspect UI elements
		set output to "ChatGPT UI Element Hierarchy:" & return & return

		-- Inspect window properties
		set output to output & "Window: " & (name of frontWindow) & return
		set output to output & "Role: " & (role of frontWindow) & return
		set output to output & "Subrole: " & (subrole of frontWindow) & return
		set output to output & return

		-- Get all UI elements in the window
		set allElements to entire contents of frontWindow
		set elementCount to count of allElements
		set output to output & "Total UI elements: " & elementCount & return & return

		-- Look for text areas, static text, and groups that might contain messages
		set messageElements to {}
		repeat with elem in allElements
			try
				set elemRole to role of elem
				if elemRole is in {"AXTextArea", "AXStaticText", "AXTextField", "AXGroup", "AXScrollArea"} then
					try
						set elemValue to value of elem
						if elemValue is not missing value and elemValue is not "" then
							set end of messageElements to {role:elemRole, value:elemValue}
							set output to output & "Found " & elemRole & ": " & elemValue & return
						end if
					end try
				end if
			end try
		end repeat

		set output to output & return & "Found " & (count of messageElements) & " elements with text content"

		return output
	end tell
end tell
