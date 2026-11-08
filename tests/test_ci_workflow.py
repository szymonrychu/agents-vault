"""CI workflow publishes the image and chart; chart-version.sh names main builds."""

import re
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent
TEXT = (ROOT / ".github/workflows/ci.yaml").read_text()
WF = yaml.safe_load(TEXT)
JOBS = WF["jobs"]
MAIN = "github.event_name == 'push' && github.ref == 'refs/heads/main'"


def steps_text(job: str) -> str:
    return yaml.safe_dump(JOBS[job]["steps"])


def test_workflow_jobs_and_targets():
    for job in ("lint", "test", "images", "chart-publish", "release"):
        assert job in JOBS
    on = WF.get("on", WF.get(True))
    assert "pull_request" in on
    assert on["push"]["branches"] == ["main"]
    assert "mise run lint" in steps_text("lint")
    assert "mise run test" in steps_text("test")
    assert "e2e" not in JOBS
    images = steps_text("images")
    assert "docker build" in images and "docker run --rm agents-vault:ci --help" in images
    assert "harbor.szymonrichert.pl/containers/agents-vault" in TEXT
    assert "$IMAGE:$SHORTSHA" in images and "--blob-chunk" in images
    for step in JOBS["images"]["steps"]:
        if "regctl" in str(step) or "HARBOR" in str(step):
            assert step.get("if") == MAIN, step
    assert JOBS["chart-publish"]["if"] == MAIN
    assert JOBS["chart-publish"]["env"]["CHART_REPO"] == "oci://harbor.szymonrichert.pl/charts"
    assert "$CHART_REPO/agents-vault" in steps_text("chart-publish")
    assert "chart/agents-vault" in steps_text("chart-publish")
    assert "chart-version.sh branch" in steps_text("chart-publish")
    assert "secrets." not in str({k: v for k, v in WF.items() if k != "jobs"})
    for name in ("lint", "test"):
        assert "secrets." not in steps_text(name)


def test_images_job_checks_uid_and_no_dev_deps():
    steps = JOBS["images"]["steps"]
    names = [str(s.get("name", "")) for s in steps]
    runs = [str(s.get("run", "")) for s in steps]
    uid = 'test "$(docker run --rm --entrypoint id agents-vault:ci -u)" = 1000'
    no_dev = "! docker run --rm --entrypoint python agents-vault:ci -c 'import pytest'"
    smoke = next(i for i, r in enumerate(runs) if "agents-vault:ci --help" in r)
    uid_at = next(i for i, r in enumerate(runs) if uid in r)
    dev_at = next(i for i, r in enumerate(runs) if no_dev in r)
    first_push = min(i for i, s in enumerate(steps) if s.get("if") == MAIN)
    assert smoke < uid_at < first_push, names
    assert smoke < dev_at < first_push, names


def test_regctl_installer_pinned_by_sha():
    uses = re.findall(r"regclient/actions/regctl-installer@(\S+)", TEXT)
    assert uses
    assert all(re.fullmatch(r"[0-9a-f]{40}", u) for u in uses)


def test_dockerfile_shape():
    text = (ROOT / "Dockerfile").read_text()
    assert re.search(r"^FROM python:3\.12-slim", text, re.M)
    assert "uv sync --frozen --no-dev" in text
    assert "USER 1000" in text
    assert 'ENTRYPOINT ["vault"]' in text


@pytest.fixture
def script_tree(tmp_path: Path) -> Path:
    (tmp_path / "scripts").mkdir()
    shutil.copy(ROOT / "scripts/chart-version.sh", tmp_path / "scripts/chart-version.sh")
    chart = tmp_path / "chart/agents-vault"
    chart.mkdir(parents=True)
    (chart / "Chart.yaml").write_text("apiVersion: v2\nname: agents-vault\nversion: 0.4.2\n")
    return tmp_path


@pytest.mark.parametrize(
    ("args", "code", "out"),
    [
        (["branch", "main", "abcdef1234567"], 0, "0.4.2-main.abcdef1"),
        (["tag", "v0.4.2", "abcdef1234567"], 2, ""),
        (["tag", "v9.9.9", "abcdef1234567"], 2, ""),
        (["branch", "feature", "abcdef1234567"], 2, ""),
    ],
)
def test_chart_version_script(script_tree: Path, args: list[str], code: int, out: str):
    r = subprocess.run(
        ["bash", str(script_tree / "scripts/chart-version.sh"), *args],
        capture_output=True,
        text=True,
    )
    assert r.returncode == code, r.stderr
    assert r.stdout.strip() == out
    if code == 2:
        assert r.stdout == ""


def test_dockerfile_pins_uv():
    text = (ROOT / "Dockerfile").read_text()
    match = re.search(r"COPY --from=ghcr\.io/astral-sh/uv:(\S+) ", text)
    assert match is not None
    assert re.fullmatch(r"\d+\.\d+\.\d+", match.group(1)), match.group(1)
    mise = (ROOT / ".mise.toml").read_text()
    assert f'uv = "{match.group(1)}"' in mise


RELEASED = "steps.version.outputs.version != ''"
RELEASE_IMAGE = "harbor.szymonrichert.pl/containers/agents-vault"


def _copy_steps(steps: list[dict]) -> list[int]:
    return [i for i, s in enumerate(steps) if "regctl image copy" in s.get("run", "")]


def test_release_job_runs_last_on_main_push():
    job = JOBS["release"]
    assert job["if"] == MAIN
    assert set(job["needs"]) == set(JOBS) - {"release"}
    assert set(job["needs"]) == {"lint", "test", "images", "chart-publish"}
    assert job["permissions"] == {"contents": "write"}
    assert job["concurrency"] == {"group": "release", "cancel-in-progress": False}


def test_release_job_fetches_full_history_and_tags():
    checkout = JOBS["release"]["steps"][0]
    assert checkout["uses"].startswith("actions/checkout@")
    assert checkout["with"]["fetch-depth"] == 0
    assert checkout["with"]["fetch-tags"] is True


def test_release_job_computes_version_with_script():
    steps = JOBS["release"]["steps"]
    version = next(i for i, s in enumerate(steps) if s.get("id") == "version")
    # A bare assignment fails the step (bash -e) when the script fails; inside echo it would not.
    assert "shell" not in steps[version]
    assert steps[version]["run"].strip().splitlines() == [
        'version="$(python3 scripts/next_version.py)"',
        'echo "version=$version" >> "$GITHUB_OUTPUT"',
    ]
    later = steps[version + 1 :]
    assert later
    assert all(s.get("if") == RELEASED for s in later)


def test_release_job_retags_manifest_only():
    job = JOBS["release"]
    steps = job["steps"]
    assert job["env"]["IMAGE"] == RELEASE_IMAGE
    assert job["env"]["HARBOR_URL"] == "harbor.szymonrichert.pl"
    copies = [
        line.strip()
        for s in steps
        for line in s.get("run", "").splitlines()
        if "regctl image copy" in line
    ]
    assert copies == [
        'regctl image copy "$IMAGE:$SHORTSHA" "$IMAGE:$VERSION"',
        'regctl image copy "$IMAGE:$SHORTSHA" "$IMAGE:$VERSION_MINOR"',
        'regctl image copy "$IMAGE:$SHORTSHA" "$IMAGE:$VERSION_MAJOR"',
    ]
    tag = steps[_copy_steps(steps)[0]]["run"]
    assert 'SHORTSHA="${GITHUB_SHA::7}"' in tag
    assert 'VERSION_MINOR="${VERSION%.*}"' in tag
    assert 'VERSION_MAJOR="${VERSION%%.*}"' in tag
    installers = [s["uses"] for s in steps if "regctl-installer" in s.get("uses", "")]
    assert len(installers) == 1
    assert re.fullmatch(r"regclient/actions/regctl-installer@[0-9a-f]{40}", installers[0])
    logins = [s for s in steps if "regctl registry login" in s.get("run", "")]
    assert len(logins) == 1
    assert logins[0]["env"] == {
        "HARBOR_USERNAME": "${{ secrets.HARBOR_USERNAME }}",
        "HARBOR_PASSWORD": "${{ secrets.HARBOR_PASSWORD }}",
    }
    text = yaml.safe_dump(job)
    for banned in ("docker", "regctl image import", "--blob-chunk"):
        assert banned not in text, banned


def test_release_job_pushes_git_tag_last():
    steps = JOBS["release"]["steps"]
    last = steps[-1]["run"].strip().splitlines()
    assert [line.strip() for line in last] == [
        'git tag "v$VERSION" "$GITHUB_SHA"',
        'git push origin "refs/tags/v$VERSION"',
    ]
    assert max(_copy_steps(steps)) < len(steps) - 1
    assert steps[-1]["env"]["VERSION"] == "${{ steps.version.outputs.version }}"
    for s in steps:
        assert not re.search(r"(^|\s)(--force|-f)(\s|$)", s.get("run", "")), s
    assert "secrets.GITHUB_TOKEN" not in TEXT


def test_no_tag_trigger_or_tag_publish_job():
    on = WF.get("on", WF.get(True))
    assert "tags" not in on["push"]
    assert "chart-publish-tag" not in JOBS
    assert "startsWith(github.ref, 'refs/tags" not in TEXT


def test_ci_release_job_needs_all_and_tags_last():
    job = JOBS["release"]
    assert set(job["needs"]) == set(JOBS) - {"release"}
    assert job["if"] == MAIN
    assert "git push origin" in job["steps"][-1]["run"]
    assert "refs/tags/v$VERSION" in job["steps"][-1]["run"]
