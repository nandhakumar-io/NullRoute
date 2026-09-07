import os

candidate_dirs = [
    "/usr/lib/x86_64-linux-gnu",
    "/lib/x86_64-linux-gnu",
    "/usr/local/lib",
    "/var/lib/flatpak/runtime/org.freedesktop.Platform/x86_64/25.08/fdad08cc10905f9175f0224652a7b1c1b4d37fc1a5fa8c97843ccef846c642a0/files/lib/x86_64-linux-gnu",
    "/home/kenpachi-zaraki/.local/share/Steam/steamrt64/pv-runtime/steam-runtime-steamrt/steamrt3c_platform_3c.0.20260618.246540/files/lib/x86_64-linux-gnu",
]

ld_library_path = os.environ.get("LD_LIBRARY_PATH", "")
paths = [p for p in [*ld_library_path.split(":"), *candidate_dirs] if p and os.path.isdir(p)]
seen = set()
filtered = []
for p in paths:
    if p not in seen:
        seen.add(p)
        filtered.append(p)
os.environ["LD_LIBRARY_PATH"] = ":".join(filtered)
os.environ["LIBRARY_PATH"] = os.environ.get("LIBRARY_PATH", "")
