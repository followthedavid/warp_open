/**
 * useMarkdown - Markdown rendering with marked library
 *
 * Provides safe markdown rendering for AI chat messages
 */

import { marked } from 'marked'
import DOMPurify from 'dompurify'

// Configure marked for code blocks
marked.setOptions({
  gfm: true, // GitHub Flavored Markdown
  breaks: true, // Convert \n to <br>
})

// Custom renderer for code blocks
const renderer = new marked.Renderer()

// Add copy button to code blocks
renderer.code = function(code: string, language: string | undefined) {
  const lang = language || 'text'
  const escapedCode = code
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')

  return `
    <div class="code-block" data-language="${lang}">
      <div class="code-header">
        <span class="code-lang">${lang}</span>
        <button class="code-copy" onclick="navigator.clipboard.writeText(this.closest('.code-block').querySelector('code').textContent)">
          Copy
        </button>
      </div>
      <pre><code class="language-${lang}">${escapedCode}</code></pre>
    </div>
  `
}

// Inline code
renderer.codespan = function(code: string) {
  return `<code class="inline-code">${code}</code>`
}

// Links open in new tab
renderer.link = function(href: string, title: string | null, text: string) {
  const titleAttr = title ? ` title="${title}"` : ''
  return `<a href="${href}"${titleAttr} target="_blank" rel="noopener noreferrer">${text}</a>`
}

marked.use({ renderer })

export function useMarkdown() {
  /**
   * Render markdown to safe HTML
   */
  function render(markdown: string): string {
    if (!markdown) return ''

    try {
      // Parse markdown
      const html = marked.parse(markdown) as string

      // Sanitize HTML to prevent XSS
      const clean = DOMPurify.sanitize(html, {
        ALLOWED_TAGS: [
          'p', 'br', 'strong', 'em', 'u', 's', 'code', 'pre',
          'h1', 'h2', 'h3', 'h4', 'h5', 'h6',
          'ul', 'ol', 'li',
          'blockquote',
          'a',
          'table', 'thead', 'tbody', 'tr', 'th', 'td',
          'div', 'span',
          'button',
          'hr'
        ],
        ALLOWED_ATTR: [
          'href', 'title', 'target', 'rel',
          'class', 'data-language',
          'onclick' // Allow for copy button
        ]
      })

      return clean
    } catch (error) {
      console.error('Markdown render error:', error)
      return markdown
    }
  }

  /**
   * Render markdown inline (no block elements)
   */
  function renderInline(markdown: string): string {
    if (!markdown) return ''

    try {
      const html = marked.parseInline(markdown) as string
      return DOMPurify.sanitize(html)
    } catch {
      return markdown
    }
  }

  /**
   * Extract code blocks from markdown
   */
  function extractCodeBlocks(markdown: string): Array<{ language: string; code: string }> {
    const blocks: Array<{ language: string; code: string }> = []
    const regex = /```(\w*)\n([\s\S]*?)```/g
    let match

    while ((match = regex.exec(markdown)) !== null) {
      blocks.push({
        language: match[1] || 'text',
        code: match[2].trim()
      })
    }

    return blocks
  }

  /**
   * Check if text contains markdown
   */
  function hasMarkdown(text: string): boolean {
    // Check for common markdown patterns
    const patterns = [
      /\*\*.*\*\*/, // bold
      /\*.*\*/, // italic
      /```/, // code block
      /`[^`]+`/, // inline code
      /^#+\s/m, // headers
      /^\s*[-*]\s/m, // lists
      /\[.*\]\(.*\)/, // links
    ]

    return patterns.some(p => p.test(text))
  }

  return {
    render,
    renderInline,
    extractCodeBlocks,
    hasMarkdown
  }
}

export default useMarkdown
