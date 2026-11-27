param(
    [string]$OutPath = "dist\r3x-sbom.cdx.json"
)

$ErrorActionPreference = "Stop"

$outDir = Split-Path -Parent $OutPath
if ($outDir -and !(Test-Path $outDir)) {
    New-Item -ItemType Directory -Path $outDir -Force | Out-Null
}

$pyScript = @'
import datetime, json, subprocess, sys, uuid

out_path = sys.argv[1]
raw = subprocess.check_output(["cargo", "metadata", "--format-version", "1", "--locked"])
meta = json.loads(raw.decode("utf-8"))

components = []
for pkg in meta.get("packages", []):
    name = pkg["name"]
    version = pkg["version"]
    comp = {
        "type": "application" if name.startswith("r3x") else "library",
        "name": name,
        "version": version,
        "purl": f"pkg:cargo/{name}@{version}",
    }
    if pkg.get("license"):
        comp["licenses"] = [{"license": {"id": pkg["license"]}}]
    components.append(comp)

sbom = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.5",
    "serialNumber": f"urn:uuid:{uuid.uuid4()}",
    "version": 1,
    "metadata": {
        "timestamp": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "component": {
            "type": "application",
            "name": "r3x-app",
            "version": "0.1.0",
        },
    },
    "components": components,
}

with open(out_path, "w", encoding="utf-8") as fh:
    json.dump(sbom, fh, indent=2)

print(f"Generated CycloneDX SBOM: {out_path} ({len(components)} packages)")
'@

$pythonCmd = Get-Command python -ErrorAction SilentlyContinue
if ($null -eq $pythonCmd) {
    $pythonCmd = Get-Command python3 -ErrorAction SilentlyContinue
}
if ($null -eq $pythonCmd) {
    throw "Python 3 is required to generate CycloneDX SBOM from cargo metadata cleanly (avoids PS 5.1 case-insensitive JSON key collisions)."
}

$pyScript | & $pythonCmd.Source - $OutPath
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
