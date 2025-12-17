#!/usr/bin/osascript

-- Deep Accessibility Tree Scanner
-- Recursively explores ALL accessibility elements

on run
	tell application "System Events"
		tell process "ChatGPT"
			set allElements to {}
			set textElements to {}

			-- Get all UI elements recursively
			try
				set mainWindow to window 1
				set windowElements to UI elements of mainWindow

				log "Starting deep scan of " & (count of windowElements) & " elements..."

				-- Recursive function to traverse tree
				my scanElement(mainWindow, 0, allElements, textElements)

				log "Total elements found: " & (count of allElements)
				log "Elements with text: " & (count of textElements)

				-- Output text elements
				repeat with elem in textElements
					log "TEXT: " & elem
				end repeat

			on error errMsg
				log "Error: " & errMsg
			end try
		end tell
	end tell
end run

-- Recursive element scanner
on scanElement(elem, depth, allElements, textElements)
	try
		set elemInfo to description of elem
		set end of allElements to elemInfo

		-- Try to get value/text
		try
			set elemValue to value of elem
			if elemValue is not missing value and elemValue is not "" then
				set end of textElements to elemValue
				log (text 1 thru (depth * 2) of "                                        ") & "Found text: " & (text 1 thru 100 of (elemValue as string))
			end if
		end try

		-- Try to get children
		try
			set children to UI elements of elem
			if (count of children) > 0 then
				repeat with child in children
					my scanElement(child, depth + 1, allElements, textElements)
				end repeat
			end if
		end try

	on error
		-- Skip elements that can't be accessed
	end try
end scanElement
