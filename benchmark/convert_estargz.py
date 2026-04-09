#!/usr/bin/env python3

"""
Convert benchmark images to eStargz format and push to registry.

For each image in manifest.json:
  1. sudo ctr-remote images pull <ref>
  2. sudo ctr-remote images convert --estargz --oci <ref> <ref><suffix>
  3. sudo ctr-remote images push --user <user> <ref><suffix>
"""

import argparse
import json
import logging
import subprocess
import sys
from pathlib import Path

log = logging.getLogger(__name__)


def run(cmd: list[str]) -> bool:
    log.debug("$ %s", " ".join(cmd))
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        log.error("Command failed: %s\n%s", " ".join(cmd), result.stderr.strip()[-500:])
        return False
    return True


def estargz_ref(ref: str, suffix: str) -> str:
    if ":" in ref.split("/")[-1]:
        base, tag = ref.rsplit(":", 1)
        return f"{base}:{tag}{suffix}"
    return f"{ref}{suffix}"


def convert_image(ref: str, suffix: str, user: str) -> bool:
    dst = estargz_ref(ref, suffix)
    ok = (
        run(["sudo", "ctr-remote", "images", "pull", ref])
        and run(["sudo", "ctr-remote", "images", "convert", "--estargz", "--oci", ref, dst])
        and run(["sudo", "ctr-remote", "images", "push", "--user", user, dst])
    )
    run(["sudo", "ctr-remote", "images", "remove", ref])
    run(["sudo", "ctr-remote", "images", "remove", dst])
    return ok


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Convert benchmark images to eStargz format and push to registry"
    )
    p.add_argument("--manifest", type=Path, required=True,
                   help="Path to manifest.json from generate_images.py")
    p.add_argument("--user", default="admin:Harbor12345",
                   help="Registry credentials in user:password format for push")
    p.add_argument("--suffix", default="-estargz",
                   help="Tag suffix for converted images (default: -estargz)")
    p.add_argument("-v", "--verbose", action="store_true")
    return p.parse_args()


def main() -> int:
    args = parse_args()
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
    )

    manifest = json.loads(args.manifest.read_text())
    images = [img["ref"] for img in manifest["images"]]

    log.info("Converting %d images from %s", len(images), args.manifest)

    ok = err = 0
    for i, ref in enumerate(images, 1):
        log.info("[%d/%d] %s", i, len(images), ref)
        if convert_image(ref, args.suffix, args.user):
            ok += 1
        else:
            err += 1

    log.info("Done: %d converted, %d errors", ok, err)
    return 0 if err == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
