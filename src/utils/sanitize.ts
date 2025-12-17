/**
 * HTML Sanitization Utilities
 *
 * Uses DOMPurify for defense-in-depth against XSS attacks.
 * All v-html content should be sanitized before rendering.
 */

import DOMPurify from 'dompurify'

/**
 * Sanitize HTML content for safe rendering.
 * Allows basic formatting tags but strips scripts and dangerous attributes.
 */
export function sanitizeHtml(dirty: string): string {
  return DOMPurify.sanitize(dirty, {
    ALLOWED_TAGS: [
      'b', 'i', 'em', 'strong', 'a', 'p', 'br', 'ul', 'ol', 'li',
      'code', 'pre', 'mark', 'span', 'div', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6',
      'blockquote', 'table', 'thead', 'tbody', 'tr', 'th', 'td',
    ],
    ALLOWED_ATTR: ['href', 'target', 'rel', 'class', 'style'],
    ALLOW_DATA_ATTR: false,
    ADD_ATTR: ['target'], // Ensure links open in new tab
  })
}

/**
 * Sanitize markdown-rendered HTML.
 * More permissive for markdown content but still safe.
 */
export function sanitizeMarkdown(dirty: string): string {
  return DOMPurify.sanitize(dirty, {
    ALLOWED_TAGS: [
      'b', 'i', 'em', 'strong', 'a', 'p', 'br', 'ul', 'ol', 'li',
      'code', 'pre', 'mark', 'span', 'div', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6',
      'blockquote', 'table', 'thead', 'tbody', 'tr', 'th', 'td',
      'img', 'hr', 'del', 'ins', 'sup', 'sub',
    ],
    ALLOWED_ATTR: ['href', 'target', 'rel', 'class', 'style', 'src', 'alt', 'title', 'width', 'height'],
    ALLOW_DATA_ATTR: false,
  })
}

/**
 * Sanitize plugin-rendered HTML.
 * Most restrictive - plugins should not inject arbitrary HTML.
 */
export function sanitizePluginHtml(dirty: string): string {
  return DOMPurify.sanitize(dirty, {
    ALLOWED_TAGS: [
      'div', 'span', 'p', 'br', 'ul', 'ol', 'li',
      'b', 'i', 'em', 'strong', 'code', 'pre',
      'h3', 'h4', 'h5', 'h6',
    ],
    ALLOWED_ATTR: ['class', 'style'],
    ALLOW_DATA_ATTR: false,
    FORBID_TAGS: ['script', 'iframe', 'object', 'embed', 'form', 'input'],
    FORBID_ATTR: ['onclick', 'onerror', 'onload', 'onmouseover'],
  })
}

/**
 * Escape HTML entities (for non-HTML text that needs escaping).
 * Use this when you just need to escape, not sanitize.
 */
export function escapeHtml(text: string): string {
  const div = document.createElement('div')
  div.textContent = text
  return div.innerHTML
}

/**
 * Strip all HTML tags, returning plain text.
 */
export function stripHtml(dirty: string): string {
  return DOMPurify.sanitize(dirty, { ALLOWED_TAGS: [] })
}
