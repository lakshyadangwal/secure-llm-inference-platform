"""
Commit 15: refactor: move Ollama integration into dedicated service class
Encapsulates all Ollama CLI interaction in a clean OllamaService class.
"""

import subprocess
import logging
from app.config.settings import settings

logger = logging.getLogger(__name__)


class OllamaService:
    """Service class responsible for all interaction with the Ollama CLI."""

    def __init__(self):
        self.model: str = self._detect_model()
        logger.info(f"🤖 OllamaService initialized with model: {self.model}")

    # ------------------------------------------------------------------
    # Commit 20: add startup model warm-up ping to Ollama
    # ------------------------------------------------------------------
    def warm_up(self) -> bool:
        """Send a minimal prompt to pre-load the model into GPU/CPU memory."""
        try:
            logger.info("🔥 Warming up Ollama model — sending test prompt...")
            response: str = self.call("Hello, are you ready?", timeout=60)
            preview: str = response[:60]
            logger.info("✅ Warm-up complete. Model responded: %s...", preview)
            return True
        except Exception as exc:
            logger.warning(f"⚠️  Warm-up failed (non-fatal): {exc}")
            return False

    # ------------------------------------------------------------------
    # Core call method
    # ------------------------------------------------------------------
    def call(self, prompt: str, timeout: int | None = None) -> str:
        """
        Run a prompt through Ollama CLI and return the response text.

        Args:
            prompt: The text prompt to send.
            timeout: Override default timeout in seconds.

        Returns:
            The LLM response as a stripped string.

        Raises:
            RuntimeError: On Ollama errors, timeouts, or missing binary.
        """
        effective_timeout = timeout or settings.OLLAMA_TIMEOUT
        prompt_preview: str = prompt[:80]
        logger.info("📤 [%s] prompt (%d chars): %s...", self.model, len(prompt), prompt_preview)

        try:
            result = subprocess.run(
                ["ollama", "run", self.model, prompt],
                capture_output=True,
                text=True,
                timeout=effective_timeout,
            )

            if result.returncode != 0:
                err = result.stderr.strip()
                logger.error(f"❌ Ollama returned error: {err}")
                raise RuntimeError(f"Ollama error: {err}")

            response = result.stdout.strip()
            logger.info(f"📥 Response received ({len(response)} chars)")
            return response

        except subprocess.TimeoutExpired:
            logger.error(f"⏱️  Ollama timed out after {effective_timeout}s")
            raise RuntimeError(f"Ollama request timed out after {effective_timeout}s")

        except FileNotFoundError:
            logger.error("❌ Ollama binary not found on PATH")
            raise RuntimeError("Ollama not installed. Download: https://ollama.ai")

        except RuntimeError:
            raise  # Re-raise our own RuntimeErrors unchanged

        except Exception as exc:
            logger.error(f"❌ Unexpected Ollama error: {exc}")
            raise RuntimeError(f"Unexpected error calling Ollama: {exc}")

    # ------------------------------------------------------------------
    # Model detection helpers
    # ------------------------------------------------------------------
    def _detect_model(self) -> str:
        """Auto-detect the best available Ollama model at startup."""
        try:
            result = subprocess.run(
                ["ollama", "list"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            output = result.stdout
            logger.info(f"Ollama available models:\n{output}")

            for preferred in settings.PREFERRED_MODELS:
                if preferred in output:
                    logger.info(f"✓ Selected preferred model: {preferred}")
                    return preferred

            # Fall back to first model in list
            all_lines: list[str] = output.split("\n")
            lines: list[str] = [line for line in all_lines[1:] if line.strip()]
            if lines:
                first_model: str = lines[0].split()[0]
                logger.info("✓ Falling back to first available model: %s", first_model)
                return first_model

            logger.error("❌ No Ollama models found!")
            return "llama3"  # Last-resort default

        except Exception as exc:
            logger.warning(f"⚠️  Could not detect Ollama model: {exc}")
            return "llama3"

    def is_available(self) -> bool:
        """Check whether Ollama is reachable."""
        try:
            subprocess.run(
                ["ollama", "list"],
                capture_output=True,
                timeout=5,
            )
            return True
        except Exception:
            return False


# Module-level singleton
ollama_service = OllamaService()
