# Contributing to Warp_Open

Thank you for your interest in contributing to Warp_Open! This document provides guidelines and information for contributors.

## Development Setup

### Prerequisites

- **Node.js** 18+ and npm
- **Rust** (latest stable via rustup)
- **Platform-specific dependencies:**
  - macOS: Xcode Command Line Tools
  - Linux: `libgtk-3-dev libwebkit2gtk-4.0-dev libappindicator3-dev`
  - Windows: Visual Studio Build Tools with C++ workload

### Getting Started

```bash
# Clone the repository
git clone https://github.com/your-org/warp_open.git
cd warp_open/warp_tauri

# Install Node.js dependencies
npm install

# Build Rust backend (first time)
cd src-tauri && cargo build && cd ..

# Start development server
npm run tauri:dev
```

### Running Tests

```bash
# Run all Rust tests
cd src-tauri && cargo test

# Run with output
cargo test -- --nocapture

# Run specific test
cargo test test_session_save_load

# Frontend build check
npm run build
```

## Project Structure

```
src/                        # Vue 3 frontend
├── App.vue                 # Root component, keyboard handlers
├── components/             # Vue components
│   ├── CommandPalette.vue  # Command palette (Cmd+Shift+P)
│   ├── LayoutRenderer.vue  # Recursive pane tree renderer
│   ├── TerminalPane.vue    # Single terminal pane
│   └── ...
└── composables/            # Vue composition API hooks
    ├── useTabs.ts          # Tab and pane state management
    ├── useProject.ts       # File system operations
    └── ...

src-tauri/                  # Rust backend
├── src/
│   ├── main.rs             # Entry point, command registration
│   ├── commands.rs         # Tauri IPC commands (PTY ops)
│   ├── session.rs          # Session persistence
│   └── osc_handler.rs      # OSC sequence parsing
├── tests/                  # Integration tests
└── Cargo.toml              # Rust dependencies
```

## Architecture Decisions

### Binary Tree Layout Model

Split panes use a binary tree structure:
- `LeafNode`: Contains a single pane with PTY
- `SplitNode`: Contains two children (can be Leaf or Split)

This allows unlimited nesting while keeping the data structure simple. Each leaf owns its own PTY - PTYs are never shared.

### State Management

- Tab state lives in `useTabs.ts` using Vue's reactivity
- Session persistence serializes to JSON, excluding runtime data (PTY IDs)
- On restore, new PTYs are spawned for each saved pane

### Security Boundaries

1. **OSC 8 (Hyperlinks)**: Only http/https protocols
2. **OSC 52 (Clipboard)**: Write-only, no read
3. **AI Overlay**: Read-only access to terminal context

## Code Style

### TypeScript/Vue

- Use Vue 3 Composition API (`<script setup>`)
- TypeScript for `.ts` files, plain JS acceptable in `.vue` components
- Prefer `const` over `let`
- Use descriptive variable names

### Rust

- Follow standard Rust conventions (rustfmt)
- Use `#[allow(dead_code)]` for functions callable via IPC
- Add tests for new functionality

### Commits

- Use conventional commits: `feat:`, `fix:`, `docs:`, `refactor:`, etc.
- Keep commits focused and atomic
- Write clear, descriptive commit messages

Example:
```
feat: add drag-to-resize for split panes

- Add mouse event handlers in LayoutRenderer.vue
- Implement live ratio update during drag
- Clamp ratio to min/max (10%/90%)
- Emit resize event to parent for persistence
```

## Pull Request Process

1. **Fork** the repository
2. **Create a branch** from `main` with a descriptive name
3. **Make changes** with clear commits
4. **Run tests** locally: `cargo test` and `npm run build`
5. **Update documentation** if needed
6. **Submit PR** with description of changes

### PR Description Template

```markdown
## Summary
Brief description of what changed.

## Changes
- Item 1
- Item 2

## Testing
How you tested the changes.

## Screenshots (if UI change)
```

## Areas for Contribution

### Good First Issues
- Documentation improvements
- Test coverage for existing code
- CSS/styling refinements
- Accessibility improvements

### Medium Complexity
- Tab overflow handling
- Preferences panel improvements
- Additional keyboard shortcuts
- Performance optimizations

### Advanced
- Plugin system architecture
- SSH/remote connections
- Custom shell integrations
- Alternative LLM backends

## Reporting Issues

### Bug Reports

Include:
- OS and version
- Steps to reproduce
- Expected vs actual behavior
- Console logs (if applicable)
- Screenshots (if UI issue)

### Feature Requests

Include:
- Use case description
- Proposed solution
- Alternatives considered
- Any relevant mockups

## Code of Conduct

- Be respectful and constructive
- Focus on the code, not the person
- Welcome newcomers
- Assume good intentions

## Questions?

- Open a GitHub issue for project-related questions
- Check existing issues and documentation first

---

Thank you for contributing to Warp_Open!
