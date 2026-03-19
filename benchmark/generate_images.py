#!/usr/bin/env python3
"""
Test image set generator for vulnerability scanner benchmarks.

Models a realistic container registry workload:
- Real base images (ubuntu, alpine, fedora, python, node, golang)
- Derivative images with OS/pip/npm/Go dependencies
- CI/CD simulation: multiple "versions" of the same image (shared layers, different app layer)

Usage:
    python generate_images.py --registry localhost:5000 --derivatives-per-base 3
    python generate_images.py --dry-run
"""

import argparse
import json
import logging
import random
import subprocess
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Optional

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Package pools
# ---------------------------------------------------------------------------

APT_PACKAGES = [
    "curl", "wget", "vim-tiny", "git", "build-essential", "libssl-dev",
    "nginx-light", "postgresql-client", "redis-tools", "jq", "htop",
    "strace", "tcpdump", "net-tools", "dnsutils", "ca-certificates",
    "openssh-client", "rsync", "unzip", "file", "less", "procps",
    "libpq-dev", "libffi-dev", "libxml2-dev", "libxslt1-dev",
]

APK_PACKAGES = [
    "curl", "git", "openssh", "nginx", "python3", "py3-pip", "nodejs",
    "npm", "jq", "htop", "strace", "tcpdump", "bind-tools", "ca-certificates",
    "rsync", "unzip", "file", "less", "procps", "build-base",
    "libffi-dev", "openssl-dev", "musl-dev",
]

DNF_PACKAGES = [
    "curl", "wget", "vim-minimal", "git", "gcc", "gcc-c++", "make",
    "openssl-devel", "nginx", "postgresql", "redis", "jq", "htop",
    "strace", "tcpdump", "net-tools", "bind-utils", "ca-certificates",
    "openssh-clients", "rsync", "unzip", "file", "less", "procps-ng",
    "libffi-devel", "libxml2-devel",
]

PIP_PACKAGES = [
    "requests==2.31.0", "flask==3.0.0", "django==4.2.7",
    "numpy==1.26.2", "pandas==2.1.3", "boto3==1.29.7",
    "celery==5.3.6", "redis==5.0.1", "psycopg2-binary==2.9.9",
    "sqlalchemy==2.0.23", "pydantic==2.5.2", "httpx==0.25.2",
    "gunicorn==21.2.0", "pillow==10.1.0", "cryptography==41.0.7",
    "paramiko==3.4.0", "jinja2==3.1.2", "pyyaml==6.0.1",
    "marshmallow==3.20.1", "click==8.1.7",
]

NPM_PACKAGES = [
    "express@4.18.2", "lodash@4.17.21", "axios@1.6.2",
    "moment@2.29.4", "webpack@5.89.0", "typescript@5.3.2",
    "react@18.2.0", "react-dom@18.2.0", "next@14.0.3",
    "dotenv@16.3.1", "winston@3.11.0", "uuid@9.0.0",
    "cors@2.8.5", "jsonwebtoken@9.0.2", "bcryptjs@2.4.3",
    "mongoose@8.0.2", "sequelize@6.35.1", "pg@8.11.3",
    "redis@4.6.11", "ioredis@5.3.2",
]

GO_MODULES = {
    "github.com/gin-gonic/gin": "v1.9.1",
    "github.com/spf13/cobra": "v1.8.0",
    "github.com/spf13/viper": "v1.18.1",
    "go.uber.org/zap": "v1.26.0",
    "gorm.io/gorm": "v1.25.5",
    "gorm.io/driver/postgres": "v1.5.4",
    "github.com/go-redis/redis/v8": "v8.11.5",
    "github.com/gorilla/mux": "v1.8.1",
    "github.com/prometheus/client_golang": "v1.17.0",
    "google.golang.org/grpc": "v1.60.0",
}

# ---------------------------------------------------------------------------
# Base image definitions
# ---------------------------------------------------------------------------

@dataclass
class BaseImage:
    image: str           # e.g. "ubuntu:22.04"
    name: str            # short name for tags, e.g. "ubuntu"
    pkg_manager: str     # apt | apk | dnf
    extra_types: list    # additional derivative types: pip, npm, go


BASE_IMAGES = [
    BaseImage("ubuntu:22.04", "ubuntu", "apt", []),
    BaseImage("alpine:3.18", "alpine", "apk", []),
    BaseImage("fedora:39", "fedora", "dnf", []),
    BaseImage("python:3.11-slim", "python", "apt", ["pip"]),
    BaseImage("node:20-slim", "node", "apt", ["npm"]),
    BaseImage("golang:1.21", "golang", "apt", ["go"]),
]

# ---------------------------------------------------------------------------
# Image model
# ---------------------------------------------------------------------------

@dataclass
class ImageSpec:
    """Specification of a single image to build."""
    base: BaseImage
    name: str                    # image name (without registry prefix)
    tag: str
    derivative_type: str         # os-deps | pip | npm | go
    os_packages: list = field(default_factory=list)
    pip_packages: list = field(default_factory=list)
    npm_packages: list = field(default_factory=list)
    go_modules: dict = field(default_factory=dict)
    app_layer_size_mb: int = 0
    version: int = 1


@dataclass
class BuiltImage:
    """Build result stored in manifest.json."""
    ref: str
    base_image: str
    derivative_type: str
    version: int
    layers: list = field(default_factory=list)
    size_bytes: int = 0

# ---------------------------------------------------------------------------
# Dockerfile and build context generation
# ---------------------------------------------------------------------------

def _install_cmd(pkg_manager: str, packages: list[str]) -> str:
    if not packages:
        return ""
    pkgs = " ".join(packages)
    if pkg_manager == "apt":
        return f"RUN apt-get update && apt-get install -y --no-install-recommends {pkgs} && rm -rf /var/lib/apt/lists/*"
    elif pkg_manager == "apk":
        return f"RUN apk add --no-cache {pkgs}"
    elif pkg_manager == "dnf":
        return f"RUN dnf install -y {pkgs} && dnf clean all"
    return ""


def generate_dockerfile(spec: ImageSpec) -> str:
    lines = [f"FROM {spec.base.image}"]

    if spec.os_packages:
        lines.append(_install_cmd(spec.base.pkg_manager, spec.os_packages))

    if spec.pip_packages:
        lines.append("COPY requirements.txt /tmp/requirements.txt")
        lines.append("RUN pip install --no-cache-dir -r /tmp/requirements.txt")

    if spec.npm_packages:
        lines.append("WORKDIR /app")
        lines.append("COPY package.json /app/package.json")
        lines.append("RUN npm install --production")

    if spec.go_modules:
        lines.append("WORKDIR /build")
        lines.append("COPY go.mod /build/")
        lines.append("COPY main.go /build/")
        lines.append("RUN go mod tidy")
        lines.append("RUN CGO_ENABLED=0 go build -o /app/server .")

    if spec.app_layer_size_mb > 0:
        lines.append(f"COPY app-binary /app/binary-v{spec.version}")

    lines.append('CMD ["sleep", "infinity"]')
    return "\n".join(lines)


def generate_go_files(modules: dict) -> tuple[str, str]:
    """Return (go.mod, main.go) content."""
    require_lines = [f"\t{mod} {ver}" for mod, ver in modules.items()]

    go_mod = f"""module benchmark/app

go 1.21

require (
{chr(10).join(require_lines)}
)
"""
    imports = [f'\t_ "{mod}"' for mod in modules]

    main_go = f"""package main

import (
{chr(10).join(imports)}
)

func main() {{}}
"""
    return go_mod, main_go


def write_build_context(spec: ImageSpec, build_dir: Path):
    """Write Dockerfile and supporting files into build_dir."""
    build_dir.mkdir(parents=True, exist_ok=True)

    (build_dir / "Dockerfile").write_text(generate_dockerfile(spec))

    if spec.pip_packages:
        (build_dir / "requirements.txt").write_text(
            "\n".join(spec.pip_packages) + "\n"
        )

    if spec.npm_packages:
        pkg_json = {
            "name": "benchmark-app",
            "version": "1.0.0",
            "dependencies": {},
        }
        for pkg in spec.npm_packages:
            if "@" in pkg and not pkg.startswith("@"):
                name, ver = pkg.rsplit("@", 1)
                pkg_json["dependencies"][name] = ver
            else:
                pkg_json["dependencies"][pkg] = "*"
        (build_dir / "package.json").write_text(
            json.dumps(pkg_json, indent=2) + "\n"
        )

    if spec.go_modules:
        go_mod, main_go = generate_go_files(spec.go_modules)
        (build_dir / "go.mod").write_text(go_mod)
        (build_dir / "main.go").write_text(main_go)

    if spec.app_layer_size_mb > 0:
        app_path = build_dir / "app-binary"
        with open(app_path, "wb") as f:
            # First 1024 bytes are unique (version seed), rest is zero-padded
            seed = f"version={spec.version},name={spec.name},tag={spec.tag}".encode()
            f.write(seed)
            f.write(b"\x00" * (1024 - len(seed)))
            remaining = spec.app_layer_size_mb * 1024 * 1024 - 1024
            if remaining > 0:
                f.write(b"\x00" * remaining)


# ---------------------------------------------------------------------------
# Image matrix generation
# ---------------------------------------------------------------------------

def generate_image_matrix(
    derivatives_per_base: int,
    versions_per_derivative: int,
    app_layer_size_mb: int,
    seed: int,
) -> list[ImageSpec]:
    rng = random.Random(seed)
    specs = []

    for base in BASE_IMAGES:
        available_types = ["os-deps"] + base.extra_types

        for d in range(derivatives_per_base):
            deriv_type = available_types[d % len(available_types)]

            pkg_pool = {
                "apt": APT_PACKAGES,
                "apk": APK_PACKAGES,
                "dnf": DNF_PACKAGES,
            }[base.pkg_manager]
            os_pkgs = sorted(rng.sample(pkg_pool, k=rng.randint(3, 8)))

            pip_pkgs = []
            npm_pkgs = []
            go_mods = {}

            if deriv_type == "pip":
                pip_pkgs = sorted(rng.sample(PIP_PACKAGES, k=rng.randint(4, 10)))
            elif deriv_type == "npm":
                npm_pkgs = sorted(rng.sample(NPM_PACKAGES, k=rng.randint(4, 10)))
            elif deriv_type == "go":
                mod_keys = rng.sample(list(GO_MODULES.keys()), k=rng.randint(3, 6))
                go_mods = {k: GO_MODULES[k] for k in mod_keys}
                os_pkgs = []  # golang base already has everything needed

            name = f"bench/{base.name}-{deriv_type}-{d:03d}"

            for v in range(1, versions_per_derivative + 1):
                specs.append(ImageSpec(
                    base=base,
                    name=name,
                    tag=f"v{v}",
                    derivative_type=deriv_type,
                    os_packages=os_pkgs,
                    pip_packages=pip_pkgs,
                    npm_packages=npm_pkgs,
                    go_modules=go_mods,
                    app_layer_size_mb=app_layer_size_mb,
                    version=v,
                ))

    return specs


# ---------------------------------------------------------------------------
# Build and push
# ---------------------------------------------------------------------------

def docker_build(spec: ImageSpec, registry: str, build_dir: Path) -> Optional[str]:
    """Build an image, return full image ref or None on failure."""
    ref = f"{registry}/{spec.name}:{spec.tag}" if registry else f"{spec.name}:{spec.tag}"

    write_build_context(spec, build_dir)

    log.info(f"Building {ref}")
    result = subprocess.run(
        ["docker", "build", "-t", ref, "."],
        cwd=build_dir,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        log.error(f"Build failed for {ref}:\n{result.stderr}")
        return None
    return ref


def docker_push(ref: str) -> bool:
    log.info(f"Pushing {ref}")
    result = subprocess.run(
        ["docker", "push", ref],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        log.error(f"Push failed for {ref}:\n{result.stderr}")
        return False
    return True


def docker_inspect(ref: str) -> Optional[dict]:
    result = subprocess.run(
        ["docker", "inspect", ref],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        return None
    data = json.loads(result.stdout)
    if not data:
        return None
    return data[0]


def collect_image_info(ref: str, spec: ImageSpec) -> BuiltImage:
    info = docker_inspect(ref)
    layers = []
    size = 0
    if info:
        layers = info.get("RootFS", {}).get("Layers", [])
        size = info.get("Size", 0)

    return BuiltImage(
        ref=ref,
        base_image=spec.base.image,
        derivative_type=spec.derivative_type,
        version=spec.version,
        layers=layers,
        size_bytes=size,
    )


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Generate a test set of OCI images for vulnerability scanner benchmarks"
    )
    p.add_argument(
        "--registry", default="",
        help="Registry address (e.g. localhost:5000). Empty = local Docker only"
    )
    p.add_argument(
        "--derivatives-per-base", type=int, default=5,
        help="Number of derivative images per base image (default: 5)"
    )
    p.add_argument(
        "--versions-per-derivative", type=int, default=3,
        help="Number of versions (different app layer) per derivative (default: 3)"
    )
    p.add_argument(
        "--app-layer-size", type=int, default=10,
        help="Synthetic app layer size in MB (default: 10)"
    )
    p.add_argument(
        "--seed", type=int, default=42,
        help="Random seed for reproducibility (default: 42)"
    )
    p.add_argument(
        "--push", action="store_true",
        help="Push images to the registry after building"
    )
    p.add_argument(
        "--dry-run", action="store_true",
        help="Only print the build plan, do not build anything"
    )
    p.add_argument(
        "--build-dir", type=Path, default=Path("images"),
        help="Directory for Dockerfiles and build contexts (default: images/)"
    )
    p.add_argument(
        "--output-manifest", type=Path, default=Path("manifest.json"),
        help="Path to save the image manifest (default: manifest.json)"
    )
    p.add_argument(
        "-v", "--verbose", action="store_true",
        help="Verbose output"
    )
    return p.parse_args()


def main():
    args = parse_args()
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
    )

    specs = generate_image_matrix(
        derivatives_per_base=args.derivatives_per_base,
        versions_per_derivative=args.versions_per_derivative,
        app_layer_size_mb=args.app_layer_size,
        seed=args.seed,
    )

    unique_derivatives = {s.name for s in specs}

    log.info(
        f"Matrix: {len(BASE_IMAGES)} bases x {args.derivatives_per_base} derivatives "
        f"x {args.versions_per_derivative} versions = {len(specs)} images "
        f"({len(unique_derivatives)} unique derivatives)"
    )

    if args.dry_run:
        print(f"\n{'='*70}")
        print(f"DRY RUN: {len(specs)} images to build")
        print(f"{'='*70}\n")
        for spec in specs:
            ref = f"{args.registry}/{spec.name}:{spec.tag}" if args.registry else f"{spec.name}:{spec.tag}"
            pkg_info = []
            if spec.os_packages:
                pkg_info.append(f"{len(spec.os_packages)} os-pkgs")
            if spec.pip_packages:
                pkg_info.append(f"{len(spec.pip_packages)} pip")
            if spec.npm_packages:
                pkg_info.append(f"{len(spec.npm_packages)} npm")
            if spec.go_modules:
                pkg_info.append(f"{len(spec.go_modules)} go-mods")
            if spec.app_layer_size_mb:
                pkg_info.append(f"{spec.app_layer_size_mb}MB app")
            print(f"  {ref:55s}  [{', '.join(pkg_info)}]")
        return

    # Build
    built: list[BuiltImage] = []
    failed = 0

    for i, spec in enumerate(specs):
        log.info(f"[{i+1}/{len(specs)}] {spec.name}:{spec.tag}")

        build_dir = args.build_dir / f"{spec.name.replace('/', '_')}_{spec.tag}"
        ref = docker_build(spec, args.registry, build_dir)
        if ref is None:
            failed += 1
            continue

        if args.push:
            if not docker_push(ref):
                failed += 1
                continue

        img = collect_image_info(ref, spec)
        built.append(img)

    # Manifest
    manifest = {
        "generator": "benchmark/generate_images.py",
        "params": {
            "registry": args.registry,
            "derivatives_per_base": args.derivatives_per_base,
            "versions_per_derivative": args.versions_per_derivative,
            "app_layer_size_mb": args.app_layer_size,
            "seed": args.seed,
        },
        "images": [asdict(img) for img in built],
    }

    args.output_manifest.write_text(json.dumps(manifest, indent=2) + "\n")
    log.info(f"Manifest saved to {args.output_manifest}")

    # Summary
    all_layers = set()
    total_size = 0
    for img in built:
        all_layers.update(img.layers)
        total_size += img.size_bytes

    print(f"\n{'='*50}")
    print(f"Built:   {len(built)} images ({failed} failed)")
    print(f"Layers:  {sum(len(img.layers) for img in built)} total, {len(all_layers)} unique")
    print(f"Size:    {total_size / 1024**3:.1f} GB (sum, including shared layers)")
    print(f"{'='*50}")


if __name__ == "__main__":
    main()
