"""Display formatting for host and backend metrics."""


def display_bytes(value):
    """Format a byte count for human-readable dashboard display.

    Returns:
        A scaled byte string, or "Unavailable" when value is None.
    """
    if value is None:
        return "Unavailable"
    value = float(value)
    units = ("B", "KiB", "MiB", "GiB", "TiB")
    unit = 0
    while value >= 1024 and unit < len(units) - 1:
        value /= 1024
        unit += 1
    return f"{value:.0f} {units[unit]}" if unit == 0 else f"{value:.1f} {units[unit]}"


def format_uptime(value):
    """Format a non-negative uptime in seconds as a compact duration.

    Returns:
        A human-readable duration, or "Unavailable" for invalid input.
    """
    if not isinstance(value, (int, float)) or isinstance(value, bool) or value < 0:
        return "Unavailable"
    seconds = int(value)
    days, seconds = divmod(seconds, 86400)
    hours, seconds = divmod(seconds, 3600)
    minutes = seconds // 60
    parts = []
    if days:
        parts.append(f"{days}d")
    if hours or days:
        parts.append(f"{hours}h")
    parts.append(f"{minutes}m")
    return " ".join(parts)


def host_context(system, backend):
    """Format host and backend metrics shared by the overview and system pages.

    Returns:
        A dictionary of display values consumed by the page templates.
    """
    system = system or {}
    backend = backend or {}
    loads = system.get("load_average") or []
    cpu_load = " / ".join("—" if value is None else f"{float(value):.2f}" for value in loads[:3]) or "Unavailable"
    return {
        "system": system,
        "backend": backend,
        "cpu_load": cpu_load,
        "host_uptime": format_uptime(system.get("uptime_seconds")),
        "backend_uptime": format_uptime(backend.get("uptime_seconds")),
        "memory_percent": system.get("memory_usage_percent"),
        "memory_detail": f"{display_bytes(system.get('memory_used_bytes'))} used of {display_bytes(system.get('memory_total_bytes'))}",
        "disk_percent": system.get("disk_usage_percent"),
        "disk_detail": f"{display_bytes(system.get('disk_used_bytes'))} used of {display_bytes(system.get('disk_total_bytes'))}",
    }
