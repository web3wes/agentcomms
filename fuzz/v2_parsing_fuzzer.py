#!/usr/bin/env python3
"""Coverage-guided parser fuzzing for untrusted agentcomms v2 input."""

import json
import sys
from pathlib import Path

import atheris

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

with atheris.instrument_imports():
    import agentcomms_v2


def test_one_input(data):
    provider = atheris.FuzzedDataProvider(data)
    operation = provider.ConsumeIntInRange(0, 2)
    text = provider.ConsumeUnicodeNoSurrogates(262144)

    try:
        if operation == 0:
            agentcomms_v2.unb64u(text)
        elif operation == 1:
            agentcomms_v2.decode_envelope(text)
        else:
            try:
                value = json.loads(text)
            except json.JSONDecodeError:
                return
            agentcomms_v2.validate_directory_entry(value)
    except agentcomms_v2.SecurityError:
        # Rejection is the expected result for malformed, unauthenticated input.
        pass


def main():
    atheris.Setup(sys.argv, test_one_input)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
