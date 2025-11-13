from __future__ import annotations

import shlex
from typing import Dict, List, Sequence

from cybercheck.scanners.runner import run_tool

_OPERATION_LABELS = {
    "sniff": "Unified sniffing",
    "scan": "Host discovery",
    "mitm": "Man-in-the-middle",
    "custom": "Custom command",
}


def _format_target(value: str | None) -> str:
    val = (value or "").strip()
    if not val:
        return "//"
    # Ettercap expects /target/ notation; normalize if the user only provided raw text
    if not val.startswith("/"):
        val = f"/{val}"
    if not val.endswith("/"):
        val = f"{val}/"
    return val


def _sanitize_plugin(value: str | None) -> list[str]:
    if not value:
        return []
    plugins = []
    for chunk in value.split(","):
        name = chunk.strip()
        if name:
            plugins.append(name)
    return plugins


def _build_summary(
    *,
    operation: str,
    interface: str,
    args: Sequence[str],
    target_a: str | None,
    target_b: str | None,
    plugins: Sequence[str],
    filter_script: str | None,
    log_file: str | None,
    pcap_file: str | None,
    extra_args: Sequence[str] | None,
) -> Dict[str, object]:
    label = _OPERATION_LABELS.get(operation, operation)
    commandline = "ettercap " + " ".join(shlex.quote(a) for a in args)
    return {
        "operation": operation,
        "operation_label": label,
        "interface": interface,
        "targets": {
            "a": (target_a or "//") if operation != "custom" else target_a or "(custom)",
            "b": (target_b or "//") if operation != "custom" else target_b or "(custom)",
        },
        "plugins": list(plugins),
        "filter_script": filter_script or "",
        "log_file": log_file or "",
        "pcap_file": pcap_file or "",
        "extra_args": list(extra_args or []),
        "commandline": commandline,
    }


def run_ettercap(
    *,
    user: str,
    interface: str,
    operation: str,
    quiet: bool = True,
    text_mode: bool = True,
    target_a: str | None = None,
    target_b: str | None = None,
    mitm_method: str | None = None,
    plugin: str | None = None,
    filter_script: str | None = None,
    log_file: str | None = None,
    pcap_file: str | None = None,
    extra_args: Sequence[str] | None = None,
    custom_args: Sequence[str] | None = None,
) -> Dict[str, object]:
    plugins = _sanitize_plugin(plugin)

    args: List[str] = []
    if text_mode:
        args.append("-T")
    if quiet:
        args.append("-q")
    if interface:
        args.extend(["-i", interface])
    if log_file:
        args.extend(["-L", log_file])
    if pcap_file:
        args.extend(["-w", pcap_file])
    if filter_script:
        args.extend(["-F", filter_script])
    if plugins:
        args.extend(["-P", ",".join(plugins)])

    formatted_target_a = _format_target(target_a)
    formatted_target_b = _format_target(target_b)

    if operation == "mitm":
        method = (mitm_method or "arp").strip() or "arp"
        args.extend(["-M", method, formatted_target_a, formatted_target_b])
    elif operation == "scan":
        # Use remote ARP poisoning with broadcast to enumerate hosts
        args.extend(["-M", "arp:remote", formatted_target_a, formatted_target_b])
    elif operation == "sniff":
        if target_a or target_b:
            args.extend([formatted_target_a, formatted_target_b])
    elif operation == "custom":
        args = args  # base options already applied
        if not custom_args:
            raise ValueError("Custom Ettercap operation requires arguments.")
        args.extend(list(custom_args))
    else:
        raise ValueError(f"Unsupported Ettercap operation: {operation}")

    if extra_args:
        args.extend(extra_args)

    target_display = " ".join(filter(None, [target_a, target_b])).strip() or interface or "ettercap"
    result = run_tool(user=user, tool="ettercap", target=target_display, args=args)

    summary = _build_summary(
        operation=operation,
        interface=interface or "(unspecified)",
        args=args,
        target_a=target_a,
        target_b=target_b,
        plugins=plugins,
        filter_script=filter_script,
        log_file=log_file,
        pcap_file=pcap_file,
        extra_args=extra_args,
    )
    result["ettercap_summary"] = summary
    result["command_args"] = args
    return result
