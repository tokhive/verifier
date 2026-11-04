#!/usr/bin/env python3
"""Build versioned CLI and browser archives from a clean, pinned checkout."""
import argparse
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import re
import subprocess
import tarfile
import tempfile

ROOT = Path(__file__).resolve().parents[1]
TARGETS = (("linux", "amd64"), ("linux", "arm64"), ("darwin", "amd64"), ("darwin", "arm64"))


def run(*args, env=None):
    return subprocess.check_output(args, cwd=ROOT, env=env, text=True).strip()


def archive(path, files):
    with path.open("xb") as raw:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as compressed:
            with tarfile.open(fileobj=compressed, mode="w") as tar:
                for name, content, mode in sorted(files):
                    info = tarfile.TarInfo(name)
                    info.size, info.mode, info.mtime = len(content), mode, 0
                    tar.addfile(info, io.BytesIO(content))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", required=True, help="release tag, e.g. v0.1.0")
    parser.add_argument("--output", type=Path, required=True, help="new output directory")
    args = parser.parse_args()
    if not re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+(?:-[a-zA-Z0-9.-]+)?", args.version):
        parser.error("version must be a release tag such as v0.1.0")
    if run("git", "status", "--porcelain", "--untracked-files=normal"):
        parser.error("release builds require a clean committed checkout")
    os.environ["GOWORK"] = "off"
    commit = run("git", "rev-parse", "HEAD")
    module = json.loads(run("go", "list", "-m", "-json", "github.com/tokhive/tee"))
    if module.get("Replace") or not module.get("Version"):
        parser.error("TEE dependency must be a pinned module without a local replacement")
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    subprocess.run(["make", "web"], cwd=ROOT, check=True)
    metadata = {"version": 1, "release": args.version, "source_commit": commit,
                "tee_module": module["Version"], "go_version": run("go", "version"),
                "source_dirty": False, "targets": [f"{system}/{arch}" for system, arch in TARGETS]}
    manifest = (json.dumps(metadata, indent=2) + "\n").encode()
    common = [("README.md", (ROOT / "README.md").read_bytes(), 0o644),
              ("API.md", (ROOT / "API.md").read_bytes(), 0o644),
              ("manifest.json", manifest, 0o644)]
    with tempfile.TemporaryDirectory() as temporary:
        binary = Path(temporary) / "tokhive-verify"
        for system, arch in TARGETS:
            env = {**os.environ, "CGO_ENABLED": "0", "GOOS": system, "GOARCH": arch}
            flags = f"-s -w -X github.com/tokhive/verifier/internal/cli.Version={args.version} -X github.com/tokhive/verifier/internal/cli.Commit={commit}"
            subprocess.run(["go", "build", "-mod=readonly", "-trimpath", "-buildvcs=true", "-ldflags", flags,
                            "-o", str(binary), "./cmd/tokhive-verify"], cwd=ROOT, env=env, check=True)
            archive(output / f"tokhive-verify-{args.version}-{system}-{arch}.tar.gz",
                    common + [("tokhive-verify", binary.read_bytes(), 0o755)])
    assets = ROOT / "web/static"
    archive(output / f"tokhive-verify-{args.version}-web.tar.gz", common + [
        ("web/" + p.relative_to(assets).as_posix(), p.read_bytes(), 0o644)
        for p in assets.rglob("*") if p.is_file()])
    if run("git", "rev-parse", "HEAD") != commit or run("git", "status", "--porcelain", "--untracked-files=normal"):
        raise RuntimeError("source changed during release build; discard the incomplete output")
    (output / "manifest.json").write_bytes(manifest)
    checksums = "".join(hashlib.sha256(p.read_bytes()).hexdigest() + "  " + p.name + "\n"
                        for p in sorted(output.iterdir()) if p.is_file())
    (output / "SHA256SUMS").write_text(checksums)
    print(output)


if __name__ == "__main__":
    main()
