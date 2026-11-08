#!/usr/bin/env python3
"""Rewrite a docker-archive/OCI image tar into the classic `docker save`
layout (Docker < 25): <id>/layer.tar, <config>.json, manifest.json,
repositories.

RouterOS `/container add file=…` fails with "could not load next layer" on
the OCI layout that buildx and Docker 25+ write (layers under blobs/sha256/).

Usage: legacy-tar.py IN.tar OUT.tar
"""
import gzip
import hashlib
import io
import json
import sys
import tarfile


def add_bytes(out: tarfile.TarFile, name: str, data: bytes) -> None:
    info = tarfile.TarInfo(name)
    info.size = len(data)
    info.mode = 0o644
    out.addfile(info, io.BytesIO(data))


def add_dir(out: tarfile.TarFile, name: str) -> None:
    info = tarfile.TarInfo(name)
    info.type = tarfile.DIRTYPE
    info.mode = 0o755
    out.addfile(info)


def main(src: str, dst: str) -> None:
    with tarfile.open(src) as t:
        manifest = json.load(t.extractfile("manifest.json"))
        if len(manifest) != 1:
            sys.exit(f"{src}: expected one image, found {len(manifest)}")
        m = manifest[0]
        config = t.extractfile(m["Config"]).read()
        layers = []
        for path in m["Layers"]:
            data = t.extractfile(path).read()
            if data[:2] == b"\x1f\x8b":  # gzip: store uncompressed
                data = gzip.decompress(data)
            layers.append(data)

    config_name = hashlib.sha256(config).hexdigest() + ".json"
    repo, _, tag = m["RepoTags"][0].rpartition(":")
    layer_paths = []
    with tarfile.open(dst, "w", format=tarfile.USTAR_FORMAT) as out:
        parent = None
        for data in layers:
            layer_id = hashlib.sha256(data).hexdigest()
            add_dir(out, layer_id)
            add_bytes(out, f"{layer_id}/VERSION", b"1.0")
            meta = {"id": layer_id}
            if parent:
                meta["parent"] = parent
            add_bytes(out, f"{layer_id}/json", json.dumps(meta).encode())
            add_bytes(out, f"{layer_id}/layer.tar", data)
            layer_paths.append(f"{layer_id}/layer.tar")
            parent = layer_id
        add_bytes(out, config_name, config)
        add_bytes(out, "manifest.json", json.dumps(
            [{"Config": config_name, "RepoTags": [f"{repo}:{tag}"], "Layers": layer_paths}]).encode())
        add_bytes(out, "repositories", json.dumps({repo: {tag: parent}}).encode())


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    main(sys.argv[1], sys.argv[2])
