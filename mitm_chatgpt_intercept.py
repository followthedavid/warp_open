"""
mitmproxy script to intercept ChatGPT Desktop API responses
Usage: mitmproxy -s mitm_chatgpt_intercept.py
"""
import json
import logging
from mitmproxy import http

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class ChatGPTInterceptor:
    def __init__(self):
        self.conversation_id = None
        self.last_response = None

    def request(self, flow: http.HTTPFlow) -> None:
        """Intercept requests to identify conversation context"""
        # Log all ChatGPT-related requests
        if "openai" in flow.request.pretty_host or "chatgpt" in flow.request.pretty_host:
            logger.info(f"[REQUEST] {flow.request.method} {flow.request.pretty_url}")

            # Try to extract conversation ID from request
            try:
                if flow.request.content:
                    data = json.loads(flow.request.content)
                    if "conversation_id" in data:
                        self.conversation_id = data["conversation_id"]
                        logger.info(f"[CONV_ID] {self.conversation_id}")
            except:
                pass

    def response(self, flow: http.HTTPFlow) -> None:
        """Intercept responses and extract chat completions"""
        # Only process OpenAI/ChatGPT responses
        if not ("openai" in flow.request.pretty_host or "chatgpt" in flow.request.pretty_host):
            return

        logger.info(f"[RESPONSE] {flow.response.status_code} {flow.request.pretty_url}")

        # Try to parse response
        try:
            if flow.response.content:
                # Handle different content types
                content_type = flow.response.headers.get("content-type", "")

                if "application/json" in content_type:
                    data = json.loads(flow.response.content)
                    self._extract_message(data, flow.request.pretty_url)

                elif "text/event-stream" in content_type:
                    # Handle SSE streaming responses
                    self._parse_sse_stream(flow.response.content, flow.request.pretty_url)

        except Exception as e:
            logger.error(f"[ERROR] Failed to parse response: {e}")

    def _extract_message(self, data: dict, url: str) -> None:
        """Extract message content from JSON response"""
        logger.info("[PARSING] Extracting message from JSON...")

        # Common ChatGPT API response formats
        message = None

        # Format 1: choices[].message.content
        if "choices" in data:
            for choice in data["choices"]:
                if "message" in choice and "content" in choice["message"]:
                    message = choice["message"]["content"]
                    break

        # Format 2: message.content.parts[]
        elif "message" in data:
            msg = data["message"]
            if "content" in msg:
                if isinstance(msg["content"], dict) and "parts" in msg["content"]:
                    message = " ".join(msg["content"]["parts"])
                elif isinstance(msg["content"], str):
                    message = msg["content"]

        # Format 3: Direct content field
        elif "content" in data:
            message = data["content"]

        if message:
            self.last_response = message
            logger.info("=" * 80)
            logger.info("[CHATGPT RESPONSE FOUND]")
            logger.info(f"URL: {url}")
            logger.info(f"Message: {message[:500]}...")
            logger.info("=" * 80)

            # Write to file for easy access
            with open("/tmp/chatgpt_last_response.txt", "w") as f:
                f.write(message)
            logger.info("[SAVED] Response saved to /tmp/chatgpt_last_response.txt")
        else:
            logger.debug(f"[NO MESSAGE] Response structure: {list(data.keys())}")

    def _parse_sse_stream(self, content: bytes, url: str) -> None:
        """Parse Server-Sent Events stream"""
        logger.info("[PARSING] Extracting from SSE stream...")

        lines = content.decode('utf-8', errors='ignore').split('\n')
        accumulated_content = []

        for line in lines:
            if line.startswith('data: '):
                data_str = line[6:]  # Remove 'data: ' prefix
                if data_str == '[DONE]':
                    break

                try:
                    data = json.loads(data_str)

                    # Extract delta content
                    if "choices" in data:
                        for choice in data["choices"]:
                            if "delta" in choice and "content" in choice["delta"]:
                                accumulated_content.append(choice["delta"]["content"])
                except:
                    pass

        if accumulated_content:
            message = "".join(accumulated_content)
            self.last_response = message
            logger.info("=" * 80)
            logger.info("[CHATGPT STREAMING RESPONSE]")
            logger.info(f"URL: {url}")
            logger.info(f"Message: {message[:500]}...")
            logger.info("=" * 80)

            with open("/tmp/chatgpt_last_response.txt", "w") as f:
                f.write(message)
            logger.info("[SAVED] Response saved to /tmp/chatgpt_last_response.txt")

# Create addon instance
addons = [ChatGPTInterceptor()]
