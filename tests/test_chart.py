"""Chart render: web, service and sweeper Deployments, RBAC, secrets split, required values."""

import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest
import yaml

CHART = Path(__file__).resolve().parent.parent / "chart" / "agents-vault"

DB_PASS = "".join(["db", "-", "fixture", "-", "value"])
ORCH_TOKEN = "".join(["orch", "-", "fixture", "-", "value"])

BASE = {
    "image": {"tag": "1.2.3"},
    "postgres": {"url": "postgresql://" + "u:" + DB_PASS + "@db:5432/v"},
    "orchestrator": {"url": "http://orch.agents.svc", "token": ORCH_TOKEN},
    "serviceListener": {"tokensSecret": {"name": "vault-service-tokens"}},
}
COMPONENTS = ("web", "service", "sweeper")
TOKENS_DIR = "/var/run/agents-vault/service-tokens"


def _merge(a: dict, b: dict) -> dict:
    out = dict(a)
    for k, v in b.items():
        out[k] = _merge(out[k], v) if isinstance(v, dict) and isinstance(out.get(k), dict) else v
    return out


def _run(values: dict) -> subprocess.CompletedProcess:
    helm = shutil.which("helm")
    assert helm, "helm binary not found on PATH; the chart tests require it"
    with tempfile.TemporaryDirectory() as tmp:
        vf = Path(tmp) / "values.yaml"
        vf.write_text(yaml.safe_dump(values))
        return subprocess.run(
            [helm, "template", "agents-vault", str(CHART), "-n", "agents", "-f", str(vf)],
            capture_output=True,
            text=True,
        )


def render(overrides: dict | None = None) -> list[dict]:
    proc = _run(_merge(BASE, overrides or {}))
    assert proc.returncode == 0, proc.stderr
    return [d for d in yaml.safe_load_all(proc.stdout) if d]


def of_kind(docs: list[dict], kind: str) -> list[dict]:
    return [d for d in docs if d["kind"] == kind]


def deployments(docs: list[dict]) -> dict[str, dict]:
    return {
        d["metadata"]["labels"]["app.kubernetes.io/component"]: d
        for d in of_kind(docs, "Deployment")
    }


def pod(dep: dict) -> dict:
    return dep["spec"]["template"]["spec"]


def env_of(container: dict) -> dict:
    return {e["name"]: e for e in container.get("env", [])}


def test_three_deployments_with_args_and_migrate_init():
    deps = deployments(render())
    assert set(deps) == set(COMPONENTS)
    args = {"web": ["serve-web"], "service": ["serve-service"], "sweeper": ["sweeper"]}
    for name, dep in deps.items():
        spec = pod(dep)
        assert dep["metadata"]["name"] == f"agents-vault-{name}"
        assert spec["containers"][0]["command"] == ["vault"]
        assert spec["containers"][0]["args"] == args[name]
        init = spec["initContainers"]
        assert [c["name"] for c in init] == ["migrate"]
        assert init[0]["command"] == ["vault"] and init[0]["args"] == ["migrate"]
        assert spec["containers"][0]["image"].endswith("agents-vault:1.2.3")
    assert pod(deps["web"])["containers"][0]["ports"][0]["containerPort"] == 8000
    assert pod(deps["service"])["containers"][0]["ports"][0]["containerPort"] == 8002


def test_sweeper_is_singleton_recreate_without_ports_or_probes():
    sweeper = deployments(render())["sweeper"]
    assert sweeper["spec"]["replicas"] == 1
    assert sweeper["spec"]["strategy"] == {"type": "Recreate"}
    container = pod(sweeper)["containers"][0]
    for key in ("ports", "livenessProbe", "readinessProbe"):
        assert key not in container


def test_no_service_for_the_sweeper():
    names = {s["metadata"]["name"] for s in of_kind(render(), "Service")}
    assert names == {"agents-vault-web", "agents-vault-service"}
    svc = {s["metadata"]["name"]: s for s in of_kind(render(), "Service")}
    assert svc["agents-vault-web"]["spec"]["ports"][0]["port"] == 80
    assert svc["agents-vault-web"]["spec"]["ports"][0]["targetPort"] == "http"
    assert svc["agents-vault-service"]["spec"]["ports"][0]["port"] == 8002


def test_automount_true_on_web_and_sweeper_false_on_service():
    deps = deployments(render())
    assert pod(deps["web"])["automountServiceAccountToken"] is True
    assert pod(deps["sweeper"])["automountServiceAccountToken"] is True
    assert pod(deps["service"])["automountServiceAccountToken"] is False


def test_role_has_exactly_create_patch_delete_on_secrets():
    docs = render()
    (role,) = of_kind(docs, "Role")
    assert role["metadata"]["namespace"] == "agents"
    assert role["rules"] == [
        {"apiGroups": [""], "resources": ["secrets"], "verbs": ["create", "patch", "delete"]}
    ]
    (binding,) = of_kind(docs, "RoleBinding")
    assert binding["roleRef"]["name"] == role["metadata"]["name"]
    (sa,) = of_kind(docs, "ServiceAccount")
    assert binding["subjects"] == [
        {"kind": "ServiceAccount", "name": sa["metadata"]["name"], "namespace": "agents"}
    ]


def test_rbac_can_be_disabled():
    docs = render({"rbac": {"create": False}})
    assert not of_kind(docs, "Role") and not of_kind(docs, "RoleBinding")


def test_service_tokens_volume_and_env_only_in_service_deployment():
    deps = deployments(render())
    for name, dep in deps.items():
        spec = pod(dep)
        container = spec["containers"][0]
        vols = {v["name"]: v for v in spec["volumes"]}
        mounts = {m["name"]: m for m in container["volumeMounts"]}
        for init in spec["initContainers"]:
            assert [m["mountPath"] for m in init["volumeMounts"]] == ["/tmp"]
        if name == "service":
            assert vols["service-tokens"]["secret"] == {
                "secretName": "vault-service-tokens",
                "items": [{"key": "tokens", "path": "tokens"}],
            }
            assert mounts["service-tokens"]["mountPath"] == TOKENS_DIR
            assert mounts["service-tokens"]["readOnly"] is True
            assert env_of(container)["VAULT_SERVICE_TOKENS_FILE"]["value"] == f"{TOKENS_DIR}/tokens"
        else:
            assert "service-tokens" not in vols and "service-tokens" not in mounts
            assert "VAULT_SERVICE_TOKENS_FILE" not in env_of(container)
        for init in spec["initContainers"]:
            assert "VAULT_SERVICE_TOKENS_FILE" not in env_of(init)


def test_tokens_secret_key_is_configurable():
    deps = deployments(render({"serviceListener": {"tokensSecret": {"key": "list"}}}))
    vol = next(v for v in pod(deps["service"])["volumes"] if v["name"] == "service-tokens")
    assert vol["secret"]["items"] == [{"key": "list", "path": "tokens"}]


def test_secret_values_come_from_secret_refs():
    deps = deployments(render())
    for dep in deps.values():
        env = env_of(pod(dep)["containers"][0])
        assert env["VAULT_DATABASE_URL"]["valueFrom"]["secretKeyRef"] == {
            "name": "agents-vault",
            "key": "database-uri",
        }
        assert env["VAULT_ORCHESTRATOR_TOKEN"]["valueFrom"]["secretKeyRef"] == {
            "name": "agents-vault",
            "key": "orchestrator-token",
        }


def test_existing_secrets_are_referenced_and_no_chart_secret_rendered():
    docs = render(
        {
            "postgres": {"url": "", "existingSecret": "pg", "existingSecretKey": "dsn"},
            "orchestrator": {"token": "", "existingSecret": "orch", "existingSecretKey": "tok"},
        }
    )
    assert not of_kind(docs, "Secret")
    env = env_of(pod(deployments(docs)["web"])["containers"][0])
    assert env["VAULT_DATABASE_URL"]["valueFrom"]["secretKeyRef"] == {"name": "pg", "key": "dsn"}
    assert env["VAULT_ORCHESTRATOR_TOKEN"]["valueFrom"]["secretKeyRef"] == {
        "name": "orch",
        "key": "tok",
    }


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"orchestrator": {"existingSecret": "orch"}}, "orchestrator token"),
        ({"orchestrator": {"token": ""}}, "orchestrator token"),
        ({"postgres": {"existingSecret": "pg"}}, "postgres.url and postgres.existingSecret"),
        ({"postgres": {"url": ""}}, "Postgres connection is required"),
        ({"orchestrator": {"url": ""}}, "orchestrator.url is required"),
        (
            {"serviceListener": {"tokensSecret": {"name": ""}}},
            "agents-vault: serviceListener.tokensSecret.name is required",
        ),
        ({"env": {"OTHER_KEY": "x"}}, "must start with VAULT_"),
    ],
)
def test_bad_values_fail_the_render(overrides: dict, message: str):
    proc = _run(_merge(BASE, overrides))
    assert proc.returncode != 0
    assert message in proc.stderr


def test_settings_configmap_has_namespace_and_extra_env():
    docs = render({"env": {"VAULT_LOG_LEVEL": "debug"}})
    (cm,) = of_kind(docs, "ConfigMap")
    assert cm["metadata"]["name"] == "agents-vault-settings"
    data = cm["data"]
    assert data["VAULT_NAMESPACE"] == "agents"
    assert data["VAULT_ORCHESTRATOR_URL"] == "http://orch.agents.svc"
    assert data["VAULT_HTTP_PORT"] == "8000" and data["VAULT_SERVICE_PORT"] == "8002"
    assert data["VAULT_ALLOWED_CIDRS"] == "127.0.0.1/32"
    assert data["VAULT_LOG_LEVEL"] == "debug"
    assert "VAULT_SERVICE_TOKENS_FILE" not in data


def test_ingress_off_by_default_and_routes_only_web_under_vault():
    assert not of_kind(render(), "Ingress")
    (ing,) = of_kind(render({"ingress": {"enabled": True}}), "Ingress")
    backends = [
        (p["path"], p["backend"]["service"]["name"], p["pathType"])
        for rule in ing["spec"]["rules"]
        for p in rule["http"]["paths"]
    ]
    assert backends == [("/vault", "agents-vault-web", "Prefix")]


def test_no_fixture_value_outside_the_chart_secret():
    docs = render()
    (secret,) = of_kind(docs, "Secret")
    assert secret["stringData"]["orchestrator-token"] == ORCH_TOKEN
    for doc in docs:
        if doc["kind"] == "Secret":
            continue
        text = yaml.safe_dump(doc)
        assert ORCH_TOKEN not in text and DB_PASS not in text, doc["kind"]
