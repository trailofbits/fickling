import pickle
import zipfile
from io import BytesIO

from fickling.analysis import AnalysisResults, Severity, check_safety
from fickling.exception import UnsafeFileError
from fickling.fickle import Pickled, PickleDecodeError, StackedPickle


def load(
    file,
    max_acceptable_severity=Severity.LIKELY_SAFE,
    print_results=False,
    json_output_path=None,
    *args,
    **kwargs,
):
    """Exposed as fickling.load()"""
    pickled_data = Pickled.load(file, fail_on_decode_error=False)
    result = check_safety(pickled=pickled_data, json_output_path=json_output_path)
    if result.severity <= max_acceptable_severity and not pickled_data.has_invalid_opcode:
        # We don't do pickle.load(file) because it could allow for a race
        # condition where the file we check is not the same that gets
        # loaded after the analysis.
        return pickle.loads(pickled_data.dumps(), *args, **kwargs)
    if pickled_data.has_invalid_opcode:
        raise UnsafeFileError(
            file,
            "This file contains an invalid opcode sequence. It is "
            "either corrupted or maliciously attempting to bypass "
            "pickle analysis tools",
        )
    raise UnsafeFileError(file, result.to_dict())


def loads(
    data,
    max_acceptable_severity=Severity.LIKELY_SAFE,
    print_results=False,
    json_output_path=None,
    *args,
    **kwargs,
):
    """Exposed as fickling.loads()

    Safely loads a pickle from bytes data after performing security analysis.

    Args:
        data: Bytes data containing the pickled object
        max_acceptable_severity: Maximum acceptable severity level (default: LIKELY_SAFE)
        print_results: Whether to print analysis results (default: False)
        json_output_path: Optional path to write JSON analysis results
        *args: Additional arguments passed to pickle.loads()
        **kwargs: Additional keyword arguments passed to pickle.loads()

    Returns:
        The unpickled object

    Raises:
        UnsafeFileError: If the pickle data is unsafe or contains invalid opcodes
    """
    # Convert bytes to file-like object
    file = BytesIO(data)

    # Reuse existing load() function which already handles all the logic
    return load(
        file,
        *args,
        max_acceptable_severity=max_acceptable_severity,
        print_results=print_results,
        json_output_path=json_output_path,
        **kwargs,
    )


class ScanResult:
    """Result of scanning a file or archive for malicious pickle content."""

    def __init__(
        self,
        filepath: str,
        severity: Severity,
        results: list[AnalysisResults],
        errors: list[str],
    ):
        self.filepath = filepath
        self.severity = severity
        self.results = results
        self.errors = errors

    @property
    def is_safe(self) -> bool:
        return self.severity <= Severity.LIKELY_SAFE

    def __bool__(self) -> bool:
        return self.is_safe and not self.errors

    def __repr__(self) -> str:
        return (
            f"ScanResult(filepath={self.filepath!r}, "
            f"severity={self.severity.name}, "
            f"results={len(self.results)}, errors={len(self.errors)})"
        )


def scan_file(
    filepath: str,
    graceful: bool = False,
    json_output_path: str | None = None,
) -> ScanResult:
    """Scan a file for malicious pickle content.

    Args:
        filepath: Path to the file to scan
        graceful: If True, continue on parse errors and report them.
                  If False, raise exceptions on parse errors.
        json_output_path: Optional path to write JSON analysis results

    Returns:
        ScanResult with severity, results list, and errors list
    """
    try:
        with open(filepath, "rb") as f:
            data = f.read()
    except Exception as e:
        if graceful:
            return ScanResult(
                filepath=filepath,
                severity=Severity.SUSPICIOUS,
                results=[],
                errors=[f"File error: {e!s}"],
            )
        raise
    return _scan_bytes(filepath, data, graceful, json_output_path)


def scan_archive(
    filepath: str,
    graceful: bool = False,
    json_output_path: str | None = None,
) -> dict[str, ScanResult]:
    """Scan a ZIP archive for malicious pickle content.

    Scans each file within the archive that has a pickle-related extension
    (.pkl, .pickle, .bin, .pt, .pth).

    Args:
        filepath: Path to the archive to scan
        graceful: If True, continue on parse errors and report them
        json_output_path: Optional path to write JSON analysis results

    Returns:
        Dict mapping archive member names to their ScanResults
    """
    from fickling.polyglot import RelaxedZipFile

    results: dict[str, ScanResult] = {}
    pickle_extensions = {".pkl", ".pickle", ".bin", ".pt", ".pth"}

    try:
        with RelaxedZipFile(filepath, "r") as archive:
            for info in archive.infolist():
                if info.is_dir():
                    continue
                ext = "." + info.filename.rsplit(".", 1)[-1].lower() if "." in info.filename else ""
                if ext not in pickle_extensions:
                    continue

                try:
                    data = archive.read(info)
                    results[info.filename] = _scan_bytes(
                        info.filename, data, graceful, json_output_path
                    )
                except Exception as e:
                    if graceful:
                        results[info.filename] = ScanResult(
                            filepath=info.filename,
                            severity=Severity.SUSPICIOUS,
                            results=[],
                            errors=[f"Error reading {info.filename}: {e!s}"],
                        )
                    else:
                        raise
    except zipfile.BadZipFile as e:
        if not graceful:
            raise
        results["<archive>"] = ScanResult(
            filepath=filepath,
            severity=Severity.SUSPICIOUS,
            results=[],
            errors=[f"Bad ZIP file: {e!s}"],
        )

    return results


def _scan_bytes(
    name: str,
    data: bytes,
    graceful: bool,
    json_output_path: str | None,
) -> ScanResult:
    """Scan bytes data for malicious pickle content."""
    results: list[AnalysisResults] = []
    errors: list[str] = []
    overall_severity = Severity.LIKELY_SAFE

    try:
        stacked = StackedPickle.load(BytesIO(data), fail_on_decode_error=not graceful)
        for pickled in stacked:
            try:
                result = check_safety(pickled, json_output_path=json_output_path)
                results.append(result)
                if result.severity > overall_severity:
                    overall_severity = result.severity
            except Exception as e:
                if graceful:
                    errors.append(f"Analysis error: {e!s}")
                    overall_severity = max(overall_severity, Severity.LIKELY_UNSAFE)
                else:
                    raise
    except PickleDecodeError as e:
        if graceful:
            errors.append(f"Parse error: {e!s}")
            overall_severity = max(overall_severity, Severity.SUSPICIOUS)
        else:
            raise
    except Exception as e:
        if graceful:
            errors.append(f"Unexpected error: {e!s}")
            overall_severity = max(overall_severity, Severity.SUSPICIOUS)
        else:
            raise

    return ScanResult(
        filepath=name,
        severity=overall_severity,
        results=results,
        errors=errors,
    )
