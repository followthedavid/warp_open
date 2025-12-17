# Demo Video Script

**Duration:** 90 seconds
**Format:** Screen recording with text overlays
**Resolution:** 1920x1080 (or 4K for quality)
**Audio:** Optional background music, no voiceover needed

---

## Scene 1: Intro (5 seconds)

**Visual:** Terminal window fades in on dark background

**Text Overlay:**
```
Warp_Open
Local-first terminal + Agentic AI
```

---

## Scene 2: Modern UX (15 seconds)

**Actions:**
1. Show sleek terminal interface
2. Open command palette (Cmd+K)
3. Quick autocomplete demo
4. Switch between tabs
5. Split pane view

**Text Overlay:**
```
Warp-inspired UX
Modern. Fast. Intuitive.
```

---

## Scene 3: Command Blocks (15 seconds)

**Actions:**
1. Run `ls -la`
2. Show output collapses into a block
3. Run `git status`
4. Show another block forms
5. Click to expand/collapse blocks

**Text Overlay:**
```
Command Blocks
Organize your terminal output
```

---

## Scene 4: AI Agent Mode (25 seconds)

**Actions:**
1. Press Cmd+I to open AI panel
2. Type: "Create a Python script that reads a CSV and outputs JSON"
3. Show AI generating code
4. AI writes file automatically
5. AI runs the script
6. Show successful output

**Text Overlay:**
```
Agentic AI
Reads. Writes. Executes.
All locally with Ollama.
```

---

## Scene 5: Git Insights Plugin (10 seconds)

**Actions:**
1. Show Git Insights panel on side
2. Branch name, dirty state visible
3. Run `git commit -m "feat: add feature"`
4. Show panel updates automatically

**Text Overlay:**
```
Git Insights Plugin
Real-time repository status
```

---

## Scene 6: Command Linter (10 seconds)

**Actions:**
1. Type `rm -rf /`
2. Show warning popup appears
3. Type `chmod 777 file.sh`
4. Show another warning

**Text Overlay:**
```
Command Linter Plugin
Protects you from dangerous commands
```

---

## Scene 7: Metrics Dashboard (5 seconds)

**Actions:**
1. Run `npm run maintainer:metrics`
2. Show ASCII dashboard with GitHub stats

**Text Overlay:**
```
Built-in Maintainer Tools
Track your project's growth
```

---

## Scene 8: Call to Action (5 seconds)

**Visual:** Terminal fades, centered text

**Text Overlay:**
```
Warp_Open v1.0.0

100% Local. 100% Open Source.

github.com/warp-open/warp_open
```

---

## Production Notes

### Recording Tips
- Use a clean terminal theme (dark recommended)
- Clear terminal history before recording
- Pre-stage any files needed for demos
- Use slow, deliberate typing (or script it)
- Record at 2x speed, play back at 1x for smoothness

### Text Overlay Style
- Font: SF Mono or JetBrains Mono
- Color: White with subtle shadow
- Position: Bottom center or top left
- Animation: Fade in/out (0.3s)

### Suggested Tools
- **Recording:** OBS Studio, ScreenFlow, or Loom
- **Editing:** DaVinci Resolve (free), Final Cut Pro
- **GIF conversion:** ffmpeg, Gifski
- **Compression:** HandBrake for video, gifsicle for GIFs

### GIF Version (30 seconds)
For README/social media, create a shorter GIF:
1. Scene 2: Quick UX tour (5s)
2. Scene 4: AI agent writing code (15s)
3. Scene 6: Command linter warning (5s)
4. Scene 8: CTA (5s)

### File Outputs
- `demo-full.mp4` (90s, YouTube/Twitter)
- `demo-short.mp4` (30s, Twitter/LinkedIn)
- `demo.gif` (30s, README)
- `demo-thumbnail.png` (for video preview)

---

## Commands to Pre-stage

```bash
# Before recording, set up:

# Clean terminal
clear

# Create demo directory
mkdir -p ~/warp_demo && cd ~/warp_demo

# Create sample CSV for AI demo
echo "name,age,city" > sample.csv
echo "Alice,30,NYC" >> sample.csv
echo "Bob,25,LA" >> sample.csv

# Initialize git repo
git init
echo "# Demo" > README.md
git add . && git commit -m "initial"

# Start Ollama
ollama serve &

# Pull model if needed
ollama pull qwen2.5-coder:7b
```
