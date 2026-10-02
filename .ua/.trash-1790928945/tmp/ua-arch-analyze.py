#!/usr/bin/env python3
"""Structural analysis script for architecture-analyzer (Phase 1)."""
import json, sys, os, collections

def main():
    if len(sys.argv) < 3:
        print("usage: script <input.json> <output.json>", file=sys.stderr)
        return 1
    inp_path, out_path = sys.argv[1], sys.argv[2]
    try:
        data = json.load(open(inp_path, encoding="utf-8"))
    except Exception as e:
        print("failed to read input: %s" % e, file=sys.stderr)
        return 1

    fileNodes = data.get("fileNodes", [])
    importEdges = data.get("importEdges", [])
    allEdges = data.get("allEdges", [])

    node_by_id = {n["id"]: n for n in fileNodes}
    all_ids = set(node_by_id)

    def fpath(nid):
        n = node_by_id.get(nid)
        if not n:
            return None
        return n.get("filePath") or n.get("name") or ""

    # ---- A. Directory grouping ----
    paths = [fpath(n["id"]) for n in fileNodes]
    # common prefix by directory segments
    split_paths = [p.split("/") for p in paths if p]
    common = []
    if split_paths:
        for segs in zip(*[s[:-1] for s in split_paths]):
            if len(set(segs)) == 1:
                common.append(segs[0])
            else:
                break
    prefix = "/".join(common)
    prefix_len = len(common)

    directoryGroups = collections.defaultdict(list)
    for n in fileNodes:
        p = fpath(n["id"])
        segs = p.split("/")
        if len(segs) > prefix_len + 1:
            grp = segs[prefix_len]
        else:
            grp = "(root)"
        directoryGroups[grp].append(n["id"])

    # ---- B. Node type grouping ----
    nodeTypeGroups = collections.defaultdict(list)
    for n in fileNodes:
        nodeTypeGroups[n.get("type", "file")].append(n["id"])

    # ---- C. Import adjacency ----
    fan_out = collections.Counter()
    fan_in = collections.Counter()
    dir_of = {}
    for n in fileNodes:
        p = fpath(n["id"])
        segs = p.split("/")
        dir_of[n["id"]] = segs[prefix_len] if len(segs) > prefix_len + 1 else "(root)"
    for e in importEdges:
        s, t = e.get("source"), e.get("target")
        if s in all_ids and t in all_ids:
            fan_out[s] += 1
            fan_in[t] += 1

    # ---- D. Cross-category edges ----
    def id_type(nid):
        if ":" in nid:
            pre = nid.split(":", 1)[0]
            if pre in ("file", "config", "document", "service", "pipeline", "table", "schema", "resource", "endpoint"):
                return pre
        n = node_by_id.get(nid)
        return n.get("type") if n else nid.split(":", 1)[0]
    cross = collections.Counter()
    for e in allEdges:
        s, t = e.get("source"), e.get("target")
        cross[(id_type(s), id_type(t), e.get("type", ""))] += 1
    crossCategoryEdges = [
        {"fromType": k[0], "toType": k[1], "edgeType": k[2], "count": v}
        for k, v in sorted(cross.items(), key=lambda x: -x[1])
    ]

    # ---- E. Inter-group import frequency ----
    inter = collections.Counter()
    intra = collections.Counter()
    for e in importEdges:
        s, t = e.get("source"), e.get("target")
        if s in all_ids and t in all_ids:
            gs, gt = dir_of[s], dir_of[t]
            if gs == gt:
                intra[gs] += 1
            else:
                inter[(gs, gt)] += 1
    interGroupImports = [{"from": k[0], "to": k[1], "count": v} for k, v in sorted(inter.items(), key=lambda x: -x[1])]

    # ---- F. Intra-group density ----
    intraGroupDensity = {}
    for g, members in directoryGroups.items():
        internal = intra.get(g, 0)
        total = internal
        for (a, b), c in inter.items():
            if a == g or b == g:
                total += c
        intraGroupDensity[g] = {"internalEdges": internal, "totalEdges": total, "density": round(internal / total, 3) if total else 0.0}

    # ---- G. Directory pattern matching ----
    dir_patterns = {
        "routes": "api", "api": "api", "controllers": "api", "controller": "api", "endpoints": "api",
        "handlers": "api", "routers": "api", "serializers": "api", "blueprints": "api",
        "services": "service", "core": "service", "lib": "service", "domain": "service", "logic": "service",
        "internal": "service", "signals": "service", "composables": "service", "mailers": "service",
        "jobs": "service", "channels": "service", "src/main/java": "service",
        "models": "data", "db": "data", "data": "data", "persistence": "data", "repository": "data",
        "entities": "data", "entity": "data", "migrations": "data", "sql": "data", "database": "data",
        "schema": "data",
        "components": "ui", "views": "ui", "pages": "ui", "ui": "ui", "layouts": "ui", "screens": "ui",
        "middleware": "middleware", "plugins": "middleware", "interceptors": "middleware", "guards": "middleware",
        "utils": "utility", "helpers": "utility", "common": "utility", "shared": "utility", "tools": "utility",
        "pkg": "utility", "templatetags": "utility",
        "config": "config", "constants": "config", "env": "config", "settings": "config",
        "management": "config", "commands": "config",
        "__tests__": "test", "test": "test", "tests": "test", "spec": "test", "specs": "test",
        "src/test/java": "test",
        "types": "types", "interfaces": "types", "schemas": "types", "contracts": "types", "dtos": "types",
        "dto": "types", "request": "types", "response": "types",
        "hooks": "hooks",
        "store": "state", "state": "state", "reducers": "state", "actions": "state", "slices": "state",
        "assets": "assets", "static": "assets", "public": "assets",
        "cmd": "entry", "bin": "entry",
        "docs": "documentation", "documentation": "documentation", "wiki": "documentation",
        "deploy": "infrastructure", "deployment": "infrastructure", "infra": "infrastructure",
        "infrastructure": "infrastructure", "k8s": "infrastructure", "kubernetes": "infrastructure",
        "helm": "infrastructure", "charts": "infrastructure", "terraform": "infrastructure", "tf": "infrastructure",
        "docker": "infrastructure",
        ".github": "ci-cd", ".gitlab": "ci-cd", ".circleci": "ci-cd",
    }
    patternMatches = {}
    for g in directoryGroups:
        if g in dir_patterns:
            patternMatches[g] = dir_patterns[g]
    # file-level patterns
    for n in fileNodes:
        p = fpath(n["id"])
        base = os.path.basename(p)
        if base.startswith("test_") and base.endswith(".py"):
            patternMatches.setdefault("(file-pattern)", "test")
        if base in ("__init__.py",) :
            patternMatches.setdefault("(file-pattern)", "entry")

    # ---- H. Deployment topology ----
    infra = []
    hasDocker = hasCompose = hasK8s = hasTF = hasCI = False
    for n in fileNodes:
        p = fpath(n["id"])
        b = os.path.basename(p)
        if b.startswith("Dockerfile") or b.startswith("docker-compose"):
            hasDocker = hasDocker or b.startswith("Dockerfile")
            hasCompose = hasCompose or b.startswith("docker-compose")
            infra.append(p)
        if b.endswith(".tf") or b.endswith(".tfvars"):
            hasTF = True; infra.append(p)
        if p.endswith(".github/workflows") or ".github/workflows/" in p:
            hasCI = True; infra.append(p)
        if b in ("Makefile", "Jenkinsfile") or p.endswith(".gitlab-ci.yml"):
            if b == "Makefile":
                infra.append(p)
            else:
                hasCI = True; infra.append(p)
    deploymentTopology = {"hasDockerfile": hasDocker, "hasCompose": hasCompose, "hasK8s": hasK8s,
                          "hasTerraform": hasTF, "hasCI": hasCI, "infraFiles": sorted(set(infra))}

    # ---- I. Data pipeline ----
    schemaFiles, migrationFiles, dataModelFiles, apiHandlerFiles = [], [], [], []
    for n in fileNodes:
        p = fpath(n["id"])
        t = n.get("type")
        if p.endswith((".graphql", ".gql", ".proto", ".prisma", ".sql")):
            schemaFiles.append(p)
        if "migrations" in p and p.endswith(".sql"):
            migrationFiles.append(p)
        if t in ("schema", "table"):
            schemaFiles.append(p)
        if "model" in p.lower() and p.endswith((".json", ".joblib")):
            dataModelFiles.append(p)
    dataPipeline = {"schemaFiles": sorted(set(schemaFiles)), "migrationFiles": sorted(set(migrationFiles)),
                    "dataModelFiles": sorted(set(dataModelFiles)), "apiHandlerFiles": sorted(set(apiHandlerFiles))}

    # ---- J. Documentation coverage ----
    doc_groups = set()
    for n in fileNodes:
        if n.get("type") == "document":
            doc_groups.add(dir_of[n["id"]])
    total_groups = len(directoryGroups)
    docCoverage = {
        "groupsWithDocs": len(doc_groups),
        "totalGroups": total_groups,
        "coverageRatio": round(len(doc_groups) / total_groups, 3) if total_groups else 0.0,
        "undocumentedGroups": sorted([g for g in directoryGroups if g not in doc_groups]),
    }

    # ---- K. Dependency direction ----
    dep = []
    seen = set()
    for (a, b), c in inter.items():
        if (b, a) in inter:
            if c > inter[(b, a)] and (a, b) not in seen:
                dep.append({"dependent": a, "dependsOn": b}); seen.add((a, b))
        else:
            if (a, b) not in seen:
                dep.append({"dependent": a, "dependsOn": b}); seen.add((a, b))
    dependencyDirection = dep

    fileStats = {
        "totalFileNodes": len(fileNodes),
        "filesPerGroup": {g: len(v) for g, v in sorted(directoryGroups.items())},
        "nodeTypeCounts": {k: len(v) for k, v in sorted(nodeTypeGroups.items())},
    }

    result = {
        "scriptCompleted": True,
        "directoryGroups": {k: v for k, v in sorted(directoryGroups.items())},
        "nodeTypeGroups": {k: v for k, v in sorted(nodeTypeGroups.items())},
        "crossCategoryEdges": crossCategoryEdges,
        "interGroupImports": interGroupImports,
        "intraGroupDensity": intraGroupDensity,
        "patternMatches": patternMatches,
        "deploymentTopology": deploymentTopology,
        "dataPipeline": dataPipeline,
        "docCoverage": docCoverage,
        "dependencyDirection": dependencyDirection,
        "fileStats": fileStats,
        "fileFanIn": dict(fan_in.most_common()),
        "fileFanOut": dict(fan_out.most_common()),
    }
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(result, f, ensure_ascii=False, indent=2)
    print("OK: wrote %s" % out_path)
    return 0

if __name__ == "__main__":
    sys.exit(main())
