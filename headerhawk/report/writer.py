"""Report writing: JSON, SARIF and Markdown, chosen by output extension."""

import json
from datetime import datetime

from ..core.severity import DEFAULT_SEVERITY, severity_for
from .sarif import build_sarif

def save_results(output_file, tests, verbose):
    if not output_file or not tests:
        return
    extension = output_file.rsplit(".", 1)[-1].lower()
    results = []
    for test in tests:
        results.extend(test.all_results if verbose == 2 else [])
        results.extend(test.vulnerabilities_found)
    # Ensure every result carries a severity so JSON/SARIF/Markdown agree.
    for result in results:
        result.setdefault("severity", severity_for(result.get("test_type", "")))

    if extension == "json":
        with open(output_file, "w") as handle:
            json.dump(results, handle, indent=4)
        print(f"\nResults saved to {output_file}")
        return

    if extension == "sarif":
        with open(output_file, "w") as handle:
            json.dump(build_sarif(results), handle, indent=2)
        print(f"\nSARIF report saved to {output_file}")
        return

    targets = sorted({test.target_url for test in tests})
    target_line = (targets[0] if len(targets) == 1
                   else f"{len(targets)} targets ({', '.join(targets)})")
    lines = [
        "# Host Header Injection Testing Report",
        f"**Target(s):** {target_line}",
        f"**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"**Total Findings:** {sum(len(t.vulnerabilities_found) for t in tests)}\n",
    ]
    if results:
        lines.append("## Test Results\n")
        for result in results:
            lines.extend([
                f"### {result['test_type']}: {result['test_result']} "
                f"({result.get('severity', DEFAULT_SEVERITY)})",
                f"- **URL:** {result['url']}",
                f"- **Severity:** {result.get('severity', DEFAULT_SEVERITY)}",
                f"- **Method:** {result['method']}",
                f"- **Headers:** {result.get('headers', {})}",
                f"- **Parameter:** {result.get('param_name', '')}",
                f"- **Payload:** {result.get('payload', '')}",
                f"- **Status Code:** {result['status_code']}",
                f"- **Response Time:** {result.get('response_time', 0):.2f} seconds",
                f"- **Analysis:** {result['analysis']}",
                f"- **Reproduce:** `{result['repro']}`\n" if result.get("repro") else "",
            ])
    else:
        lines.append("No vulnerabilities were found.\n")
    with open(output_file, "w") as handle:
        handle.write("\n".join(line for line in lines if line is not None))
    print(f"\nReport saved to {output_file}")
