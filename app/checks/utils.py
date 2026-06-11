"""Shared helpers used across all check modules."""


def v(d: dict, *keys: str) -> str:
    """Return the first non-empty string value from the dict for any of the given keys."""
    for k in keys:
        val = d.get(k, "")
        if val:
            return str(val).strip()
    return ""


def off(val: str) -> bool:
    """Return True when a config value means 'disabled'."""
    return str(val).lower() in ("disable", "disabled", "0", "false", "off", "no", "")
