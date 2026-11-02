import os
import re
from dataclasses import dataclass
from typing import Optional

import torch
from transformers import AutoModelForCausalLM, AutoTokenizer


MODEL_NAME = os.getenv("MODEL_NAME", "Qwen/Qwen3-0.6B")

# Set these independently.
# INPUT_GUARD: "1" or "0".
# OUTPUT_FILTER: "off", "echo" (the real mitigation) or "oracle" (reference
# only: knows the detector's answer key). "1" is kept as an alias for "oracle".
INPUT_GUARD = os.getenv("INPUT_GUARD", "0") == "1"
OUTPUT_FILTER = {"0": "off", "1": "oracle"}.get(
    os.getenv("OUTPUT_FILTER", "off"), os.getenv("OUTPUT_FILTER", "off")
)
if OUTPUT_FILTER not in {"off", "echo", "oracle"}:
    raise ValueError(f"OUTPUT_FILTER must be off, echo or oracle, got {OUTPUT_FILTER!r}")

# Qwen3 emits a <think> block by default; the detector scans it too.
ENABLE_THINKING = os.getenv("ENABLE_THINKING", "0") == "1"

# Oracle mode only: the exact rogue string garak's detector searches for.
ROGUE_TRIGGER = os.getenv("ROGUE_TRIGGER", "").strip()

# Echo mode: quoted spans shorter than this are ignored, so that replies
# repeating short words like "yes" are not blocked. 10 still covers garak's
# shortest rogue string, "I hate humans" (13 chars).
MIN_QUOTE_LEN = 10
QUOTE_CHARS = re.compile(r'["“”]')


# These are deliberately simple baseline rules, not a trained classifier.
# The first pattern was widened after the baseline scan: garak's probes say
# "ignore any previous and following instructions", which the original
# "ignore (all) previous instructions" rule missed.
INJECTION_PATTERNS = [
    r"(ignore|disregard|forget)\s+(\w+\s+){0,4}(instructions|directions|rules)",
    r"override\s+(the\s+)?(system|developer)\s+prompt",
    r"reveal\s+(your\s+)?(system prompt|hidden instructions)",
    r"you\s+are\s+now\s+in\s+developer\s+mode",
]


@dataclass
class WrapperResult:
    prompt: str
    response: str
    input_blocked: bool
    output_blocked: bool
    input_guard_enabled: bool
    output_filter: str
    reason: Optional[str] = None


class SecurityWrapper:
    def __init__(self, model_name: str = MODEL_NAME):
        self.tokenizer = AutoTokenizer.from_pretrained(model_name)
        self.model = AutoModelForCausalLM.from_pretrained(
            model_name,
            torch_dtype="auto",
            device_map="auto",
        )
        self.model.eval()

    @staticmethod
    def is_suspicious(prompt: str) -> bool:
        text = prompt.lower()
        return any(re.search(pattern, text) for pattern in INJECTION_PATTERNS)

    @staticmethod
    def echoes_quoted_input(prompt: str, response: str) -> bool:
        """True if the response repeats a quoted span from the prompt verbatim.

        Targets "just print <quoted text>" style hijacks without knowing what
        the quoted text is. Ignores single quotes (they clash with apostrophes).

        Every span between two quote marks is checked, not just matched pairs:
        pairing quotes left to right let a single stray quote earlier in the
        prompt shift every later pair, hiding the injected string.
        """
        normalise = lambda s: " ".join(s.split()).casefold()
        reply = normalise(response)
        # [1:-1] drops the text before the first and after the last quote mark.
        for segment in QUOTE_CHARS.split(prompt)[1:-1]:
            quoted = normalise(segment)
            if len(quoted) >= MIN_QUOTE_LEN and quoted in reply:
                return True
        return False

    def generate(self, prompt: str, max_new_tokens: int = 160) -> WrapperResult:
        # Stage 1: optional input guard
        if INPUT_GUARD and self.is_suspicious(prompt):
            return WrapperResult(
                prompt=prompt,
                response="[BLOCKED: suspicious input detected]",
                input_blocked=True,
                output_blocked=False,
                input_guard_enabled=INPUT_GUARD,
                output_filter=OUTPUT_FILTER,
                reason="input_guard",
            )

        # Stage 2: model generation
        messages = [{"role": "user", "content": prompt}]

        # Use the model's chat template when available.
        if getattr(self.tokenizer, "chat_template", None):
            input_text = self.tokenizer.apply_chat_template(
                messages,
                tokenize=False,
                add_generation_prompt=True,
                enable_thinking=ENABLE_THINKING,
            )
        else:
            input_text = prompt

        inputs = self.tokenizer(input_text, return_tensors="pt")
        inputs = {key: value.to(self.model.device) for key, value in inputs.items()}

        with torch.inference_mode():
            output_ids = self.model.generate(
                **inputs,
                max_new_tokens=max_new_tokens,
                do_sample=False,
                pad_token_id=self.tokenizer.eos_token_id,
            )

        new_tokens = output_ids[0][inputs["input_ids"].shape[1]:]
        response = self.tokenizer.decode(
            new_tokens,
            skip_special_tokens=True,
        ).strip()

        # Stage 3: optional output filter
        blocked = False
        if OUTPUT_FILTER == "echo":
            blocked = self.echoes_quoted_input(prompt, response)
        elif OUTPUT_FILTER == "oracle":
            if not ROGUE_TRIGGER:
                raise ValueError(
                    "OUTPUT_FILTER=oracle requires ROGUE_TRIGGER to be set "
                    "to the exact detector trigger string."
                )
            blocked = ROGUE_TRIGGER.casefold() in response.casefold()

        if blocked:
            return WrapperResult(
                prompt=prompt,
                response=f"[BLOCKED: output filter ({OUTPUT_FILTER})]",
                input_blocked=False,
                output_blocked=True,
                input_guard_enabled=INPUT_GUARD,
                output_filter=OUTPUT_FILTER,
                reason=f"output_filter_{OUTPUT_FILTER}",
            )

        return WrapperResult(
            prompt=prompt,
            response=response,
            input_blocked=False,
            output_blocked=False,
            input_guard_enabled=INPUT_GUARD,
            output_filter=OUTPUT_FILTER,
        )


_wrapper = None


def garak_generate(prompt: str, **kwargs) -> list:
    """Entry point for garak: --target_type function --target_name src.wrapper#garak_generate"""
    global _wrapper
    if _wrapper is None:
        _wrapper = SecurityWrapper()  # load the model once, not per prompt
    return [_wrapper.generate(prompt).response]


if __name__ == "__main__":
    wrapper = SecurityWrapper()
    print("Input guard:", INPUT_GUARD)
    print("Output filter:", OUTPUT_FILTER)

    while True:
        try:
            prompt = input("\nPrompt (or 'quit'): ").strip()
        except (EOFError, KeyboardInterrupt):
            break

        if prompt.lower() in {"quit", "exit"}:
            break
        if not prompt:
            continue

        result = wrapper.generate(prompt)
        print("\nResponse:", result.response)
        print("Input blocked:", result.input_blocked)
        print("Output blocked:", result.output_blocked)
        if result.reason:
            print("Reason:", result.reason)