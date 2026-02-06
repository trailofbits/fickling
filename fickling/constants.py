"""Fickling constants module - shared constants to avoid circular imports."""

# ClamAV-compatible exit codes for CI/CD integration
EXIT_CLEAN = 0  # No issues found
EXIT_UNSAFE = 1  # Potentially malicious content detected
EXIT_ERROR = 2  # Scan error (parse failure, file not found, etc.)
