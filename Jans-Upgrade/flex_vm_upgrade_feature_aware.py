#!/usr/bin/env python3
"""
Feature-aware Flex VM upgrader: 5.16.0 -> 6.0.0

Includes:
- discovery-first upgrade flow
- upgrade only installed/selected components
- Admin UI migration
- policy-store.cjar validation/fix for trusted issuer hostname
- DB patch for adminUISession
- DB patch for Admin UI jansConfApp compatibility
- local PostgreSQL-only guardrails
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import shutil
import socket
import subprocess
import tarfile
import tempfile
import zipfile


# ----------------------------
# Static paths on target host
# ----------------------------
JANS_PROPERTIES = Path("/etc/jans/conf/jans.properties")
JANS_SQL_PROPERTIES = Path("/etc/jans/conf/jans-sql.properties")
APP_INFO_JSON = Path("/opt/jans/jans-setup/app_info.json")
VERSION_PY = Path("/opt/jans/jans-setup/flex/flex-linux-setup/version.py")
OS_RELEASE = Path("/etc/os-release")

AUTH_WAR = Path("/opt/jans/jetty/jans-auth/webapps/jans-auth.war")
CONFIG_API_WAR = Path("/opt/jans/jetty/jans-config-api/webapps/jans-config-api.war")
CASA_WAR = Path("/opt/jans/jetty/jans-casa/webapps/jans-casa.war")
FIDO2_WAR = Path("/opt/jans/jetty/jans-fido2/webapps/jans-fido2.war")
SCIM_WAR = Path("/opt/jans/jetty/jans-scim/webapps/jans-scim.war")

AUTH_CUSTOM_LIBS = Path("/opt/jans/jetty/jans-auth/custom/libs")
CONFIG_API_CUSTOM_LIBS = Path("/opt/jans/jetty/jans-config-api/custom/libs")
ADMIN_UI_DIR = Path("/var/www/html/admin")
AUI_CONFIG_LIVE = Path("/opt/jans/jans-setup/flex/auiConfiguration.json")
FLEX_TEMPLATE_DIR = Path("/opt/jans/jans-setup/flex/flex-linux-setup/templates")
CONFIG_API_ADMINUI_POLICY_DIR = Path("/opt/jans/jetty/jans-config-api/custom/config/adminUI")
CONFIG_API_SERVER_INI = Path("/opt/jans/jetty/jans-config-api/start.d/server.ini")
CONFIG_API_JAVA_SECURITY_DIR = Path("/opt/jans/jetty/jans-config-api/etc/jetty/security")
CONFIG_API_JAVA_SECURITY = CONFIG_API_JAVA_SECURITY_DIR / "java.security"

EXPECTED_SERVICES = [
    "jans-auth",
    "jans-config-api",
    "jans-scim",
    "jans-fido2",
    "jans-casa",
    "apache2",
]

SERVICE_DEFS = {
    "jans-auth": {
        "unit": "/etc/systemd/system/jans-auth.service",
        "runtime_dir": "/opt/jans/jetty/jans-auth",
        "webapp": str(AUTH_WAR),
        "conf_dn": "ou=jans-auth,ou=configuration,o=jans",
    },
    "jans-config-api": {
        "unit": "/etc/systemd/system/jans-config-api.service",
        "runtime_dir": "/opt/jans/jetty/jans-config-api",
        "webapp": str(CONFIG_API_WAR),
        "conf_dn": "ou=jans-config-api,ou=configuration,o=jans",
    },
    "jans-scim": {
        "unit": "/etc/systemd/system/jans-scim.service",
        "runtime_dir": "/opt/jans/jetty/jans-scim",
        "webapp": str(SCIM_WAR),
        "conf_dn": "ou=jans-scim,ou=configuration,o=jans",
    },
    "jans-fido2": {
        "unit": "/etc/systemd/system/jans-fido2.service",
        "runtime_dir": "/opt/jans/jetty/jans-fido2",
        "webapp": str(FIDO2_WAR),
        "conf_dn": "ou=jans-fido2,ou=configuration,o=jans",
    },
    "jans-casa": {
        "unit": "/etc/systemd/system/jans-casa.service",
        "runtime_dir": "/opt/jans/jetty/jans-casa",
        "webapp": str(CASA_WAR),
        "conf_dn": "ou=jans-casa,ou=configuration,o=jans",
    },
    "jans-lock": {
        "unit": "/etc/systemd/system/jans-lock.service",
        "runtime_dir": "/opt/jans/jetty/jans-lock",
        "webapp": "/opt/jans/jetty/jans-lock/webapps/jans-lock.war",
        "conf_dn": "ou=jans-lock,ou=configuration,o=jans",
    },
    "jans-kc": {
        "unit": "/etc/systemd/system/jans-kc.service",
        "runtime_dir": "/opt/jans/jetty/jans-kc",
        "webapp": "/opt/jans/jetty/jans-kc/webapps/jans-kc.war",
        "conf_dn": "ou=jans-kc,ou=configuration,o=jans",
    },
}

ADMIN_UI_SIGNS = {
    "frontend": "/var/www/html/admin/index.html",
    "config": "/opt/jans/jans-setup/flex/auiConfiguration.json",
    "plugin": "/opt/jans/jetty/jans-config-api/custom/libs/gluu-flex-admin-ui-plugin.jar",
}

SERVICE_DRIVEN_OPTIONALS = {"jans-scim", "jans-fido2", "jans-casa"}
DB_DRIVEN_OPTIONALS = {"jans-lock", "jans-kc"}

CONFIG_API_JAVA_SECURITY_PROP = "-Djava.security.properties=./etc/jetty/security/java.security"

CASA_EXTRA_CLIENT_SCOPE = "https://jans.io/oauth/config/agama.readonly"


class UpgradeError(RuntimeError):
    pass


@dataclass
class HostInfo:
    fqdn: str = ""
    os: str = ""
    init_system: str = ""
    apache_version: str = ""
    java_home: str = ""


@dataclass
class PersistenceInfo:
    type: str = ""
    mode: str = ""
    db_name: str = ""
    db_host: str = ""
    db_port: int | None = None
    db_user: str = ""


@dataclass
class InstallInfo:
    profile: str = ""
    installed_version: str = ""
    persistence: PersistenceInfo = field(default_factory=PersistenceInfo)


@dataclass
class DiscoveryReport:
    host: HostInfo = field(default_factory=HostInfo)
    install: InstallInfo = field(default_factory=InstallInfo)
    services: dict[str, bool] = field(default_factory=dict)
    db_features: dict[str, bool] = field(default_factory=dict)
    upgrade_plan: dict[str, list[str]] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)


@dataclass
class UpgradeContext:
    source_root: Path
    flex_fqdn: str
    backup_root: Path
    dry_run: bool = False
    skip_backup: bool = False
    skip_db: bool = False
    skip_restart: bool = False
    discovery: DiscoveryReport | None = None
    backup_dir: Path | None = None
    warnings: list[str] = field(default_factory=list)


def log(msg: str) -> None:
    print(msg)


def section(title: str) -> None:
    print(f"\n=== {title} ===")


def ensure_exists(path: Path) -> None:
    if not path.exists():
        raise UpgradeError(f"Required path does not exist: {path}")


def run(cmd: list[str], *, dry_run: bool = False, check: bool = True) -> subprocess.CompletedProcess[str]:
    if dry_run:
        print("DRY-RUN:", " ".join(cmd))
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")
    result = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if check and result.returncode != 0:
        raise UpgradeError(
            f"Command failed ({result.returncode}): {' '.join(cmd)}\nSTDOUT:\n{result.stdout}\nSTDERR:\n{result.stderr}"
        )
    return result


def read_properties(path: Path) -> dict[str, str]:
    props: dict[str, str] = {}
    if not path.exists():
        return props
    for raw in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        props[k.strip()] = v.strip().strip('"').strip("'")
    return props


def require_root() -> None:
    if os.geteuid() != 0:
        raise UpgradeError("This script must be run as root")


def detect_os() -> tuple[str, str]:
    os_name = "unknown"
    if OS_RELEASE.exists():
        data = read_properties(OS_RELEASE)
        pretty = data.get("PRETTY_NAME") or f"{data.get('NAME', '')} {data.get('VERSION_ID', '')}".strip()
        if pretty:
            os_name = pretty.strip('"').strip("'")
    init_system = "systemd" if Path("/run/systemd/system").exists() else "unknown"
    return os_name, init_system


def detect_apache_version() -> str:
    result = subprocess.run(["apache2", "-v"], capture_output=True, text=True, check=False)
    if result.returncode != 0:
        return ""
    m = re.search(r"Apache/(\d+\.\d+)", result.stdout)
    return m.group(1) if m else (result.stdout.strip().splitlines()[0] if result.stdout.strip() else "")


def detect_profile() -> str:
    for candidate in (Path("/opt/jans/jans-setup/profile"), Path("/opt/jans/jans-setup/.profile")):
        if candidate.exists():
            value = candidate.read_text(encoding="utf-8", errors="ignore").strip()
            if value:
                return value
    return "jans"


def detect_installed_version() -> str:
    if APP_INFO_JSON.exists():
        try:
            data = json.loads(APP_INFO_JSON.read_text(encoding="utf-8", errors="ignore"))
            for key in ("VERSION", "version", "JANS_APP_VERSION"):
                if isinstance(data.get(key), str):
                    return data[key]
        except json.JSONDecodeError:
            pass
    if VERSION_PY.exists():
        text = VERSION_PY.read_text(encoding="utf-8", errors="ignore")
        m = re.search(r"(\d+\.\d+\.\d+)", text)
        if m:
            return m.group(1)
    return "unknown"


def parse_jdbc_uri(uri: str) -> tuple[str, int | None, str]:
    if uri.startswith("jdbc:postgresql://"):
        rest = uri.removeprefix("jdbc:postgresql://")
    elif uri.startswith("jdbc:mysql://"):
        rest = uri.removeprefix("jdbc:mysql://")
    else:
        return "", None, ""
    hostport, db_name = rest.split("/", 1)
    hostport = hostport.split("?", 1)[0]
    db_name = db_name.split("?", 1)[0]
    if ":" in hostport:
        host, port_s = hostport.split(":", 1)
        try:
            port = int(port_s)
        except ValueError:
            port = None
    else:
        host = hostport
        port = None
    return host, port, db_name


def detect_persistence() -> PersistenceInfo:
    jans_props = read_properties(JANS_PROPERTIES)
    sql_props = read_properties(JANS_SQL_PROPERTIES)
    info = PersistenceInfo()
    info.type = jans_props.get("persistence.type", "")
    uri = sql_props.get("connection.uri", "")
    if uri:
        host, port, db_name = parse_jdbc_uri(uri)
        info.db_host = host
        info.db_port = port
        info.db_name = db_name
        info.db_user = sql_props.get("auth.userName", "")
        if "postgresql" in uri or info.type == "sql":
            info.type = "pgsql" if "postgresql" in uri else info.type
        elif "mysql" in uri:
            info.type = "mysql"
        info.mode = "local" if host in ("localhost", "127.0.0.1", "") else "remote"
    return info


def systemd_unit_exists(name: str) -> bool:
    result = subprocess.run(["systemctl", "status", name], capture_output=True, text=True, check=False)
    return result.returncode in (0, 3, 4)


def detect_service_installation() -> dict[str, bool]:
    service_state: dict[str, bool] = {}
    for name, facts in SERVICE_DEFS.items():
        score = 0
        if systemd_unit_exists(name):
            score += 1
        if Path(facts["runtime_dir"]).exists():
            score += 1
        if Path(facts["webapp"]).exists():
            score += 1
        service_state[name] = score >= 2
    admin_signals = sum(1 for p in ADMIN_UI_SIGNS.values() if Path(p).exists())
    service_state["admin-ui"] = admin_signals >= 2
    service_state["apache2"] = systemd_unit_exists("apache2") or Path("/etc/apache2").exists()
    return service_state


def db_query_exists(db_name: str, sql: str) -> bool:
    result = subprocess.run(
        ["sudo", "-u", "postgres", "psql", "-d", db_name, "-t", "-A", "-c", sql],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        return False
    return bool(result.stdout.strip())


def detect_db_features(db_name: str) -> dict[str, bool]:
    features: dict[str, bool] = {}
    if not db_name:
        return features
    for name, facts in SERVICE_DEFS.items():
        dn = facts["conf_dn"]
        sql = f"SELECT dn FROM public.\"jansAppConf\" WHERE dn='{dn}';"
        features[name] = db_query_exists(db_name, sql)
    return features


def build_upgrade_plan(services: dict[str, bool], db_features: dict[str, bool]) -> dict[str, list[str]]:
    base_components: list[str] = []
    optional_components: list[str] = []
    skip_components: list[str] = []

    for base in ("jans-auth", "jans-config-api", "apache2"):
        if services.get(base):
            base_components.append(base)
        else:
            skip_components.append(base)

    for opt in sorted(SERVICE_DRIVEN_OPTIONALS):
        if services.get(opt, False):
            optional_components.append(opt)
        else:
            skip_components.append(opt)

    for opt in sorted(DB_DRIVEN_OPTIONALS):
        installed = services.get(opt, False)
        configured = db_features.get(opt, False)
        if installed and configured:
            optional_components.append(opt)
        else:
            skip_components.append(opt)

    if services.get("admin-ui"):
        optional_components.append("admin-ui")
    else:
        skip_components.append("admin-ui")

    return {
        "base_components": base_components,
        "optional_components": optional_components,
        "skip_components": skip_components,
    }


def collect_discovery_warnings(report: DiscoveryReport) -> list[str]:
    warnings: list[str] = []
    if report.install.persistence.type not in ("pgsql", "mysql", "sql"):
        warnings.append(f"Unexpected persistence type: {report.install.persistence.type!r}")
    if report.install.persistence.db_name == "":
        warnings.append("Database name could not be detected")
    for opt in sorted(DB_DRIVEN_OPTIONALS):
        if report.services.get(opt) and not report.db_features.get(opt, False):
            warnings.append(f"{opt} appears installed on disk but no DB configuration entry was detected")
    return warnings


def discover() -> DiscoveryReport:
    report = DiscoveryReport()
    os_name, init_system = detect_os()
    report.host.fqdn = socket.getfqdn()
    report.host.os = os_name
    report.host.init_system = init_system
    report.host.apache_version = detect_apache_version()
    report.host.java_home = os.environ.get("JAVA_HOME", "/opt/jre" if Path("/opt/jre").exists() else "")
    report.install.profile = detect_profile()
    report.install.installed_version = detect_installed_version()
    report.install.persistence = detect_persistence()
    report.services = detect_service_installation()
    report.db_features = detect_db_features(report.install.persistence.db_name)
    report.upgrade_plan = build_upgrade_plan(report.services, report.db_features)
    report.warnings = collect_discovery_warnings(report)
    return report


def source_path(ctx: UpgradeContext, relative: str) -> Path:
    p = ctx.source_root / relative
    ensure_exists(p)
    return p


def build_artifact_plan(ctx: UpgradeContext) -> dict[str, list[tuple[Path, Path]]]:
    if ctx.discovery is None:
        raise UpgradeError("Discovery report is not initialized")

    services = ctx.discovery.services
    plan: dict[str, list[tuple[Path, Path]]] = {
        "wars": [],
        "config_api_plugins": [],
        "auth_custom_libs": [],
        "templates": [],
    }

    plan["wars"].append((source_path(ctx, "dist/jans-auth.war"), AUTH_WAR))
    plan["wars"].append((source_path(ctx, "dist/jans-config-api.war"), CONFIG_API_WAR))

    if services.get("jans-casa"):
        plan["wars"].append((source_path(ctx, "dist/jans_casa/jans-casa.war"), CASA_WAR))
    if services.get("jans-fido2"):
        plan["wars"].append((source_path(ctx, "dist/jans-fido2.war"), FIDO2_WAR))
    if services.get("jans-scim"):
        plan["wars"].append((source_path(ctx, "dist/jans-scim.war"), SCIM_WAR))

    if services.get("jans-fido2"):
        plan["config_api_plugins"].append((source_path(ctx, "dist/fido2-plugin.jar"), CONFIG_API_CUSTOM_LIBS / "fido2-plugin.jar"))
    if services.get("jans-scim"):
        plan["config_api_plugins"].append((source_path(ctx, "dist/scim-plugin.jar"), CONFIG_API_CUSTOM_LIBS / "scim-plugin.jar"))
    if services.get("admin-ui"):
        plan["config_api_plugins"].append((source_path(ctx, "dist/gluu-flex-admin-ui-plugin.jar"), CONFIG_API_CUSTOM_LIBS / "gluu-flex-admin-ui-plugin.jar"))
        plan["config_api_plugins"].append((source_path(ctx, "dist/user-mgt-plugin.jar"), CONFIG_API_CUSTOM_LIBS / "user-mgt-plugin.jar"))

    if services.get("jans-casa"):
        plan["auth_custom_libs"].append((source_path(ctx, "dist/jans_casa/jans-casa-config.jar"), AUTH_CUSTOM_LIBS / "jans-casa-config.jar"))
        if (ctx.source_root / "dist/jans_casa/twilio.jar").exists():
            plan["auth_custom_libs"].append((source_path(ctx, "dist/jans_casa/twilio.jar"), AUTH_CUSTOM_LIBS / "twilio.jar"))
        else:
            plan["auth_custom_libs"].append((source_path(ctx, "dist/app/twilio.jar"), AUTH_CUSTOM_LIBS / "twilio.jar"))
    if services.get("jans-fido2") or services.get("jans-casa"):
        plan["auth_custom_libs"].append((source_path(ctx, "dist/jans-fido2-client.jar"), AUTH_CUSTOM_LIBS / "jans-fido2-client.jar"))
        plan["auth_custom_libs"].append((source_path(ctx, "dist/jans-fido2-model.jar"), AUTH_CUSTOM_LIBS / "jans-fido2-model.jar"))

    if services.get("admin-ui"):
        plan["templates"].append((source_path(ctx, "templates/policy-store.cjar"), FLEX_TEMPLATE_DIR / "policy-store.cjar"))
        plan["templates"].append((source_path(ctx, "templates/policy-store.cjar"), CONFIG_API_ADMINUI_POLICY_DIR / "policy-store.cjar"))
    plan["templates"].append((source_path(ctx, "templates/java.security"), CONFIG_API_JAVA_SECURITY))

    return plan


def build_backup_dir(ctx: UpgradeContext) -> Path:
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    return ctx.backup_root / f"feature-aware-upgrade-{timestamp}"


def copy_path(src: Path, dst: Path, *, dry_run: bool) -> None:
    if dry_run:
        print(f"DRY-RUN: copy {src} -> {dst}")
        return
    if src.is_dir():
        shutil.copytree(src, dst, dirs_exist_ok=True)
    else:
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)


def dump_db(ctx: UpgradeContext, output_file: Path, schema_only: bool) -> None:
    if ctx.discovery is None:
        raise UpgradeError("Discovery report is not initialized")
    db_name = ctx.discovery.install.persistence.db_name

    cmd = ["sudo", "-u", "postgres", "pg_dump"]
    if schema_only:
        cmd.append("-s")
    cmd.extend(["-d", db_name])

    if ctx.dry_run:
        print("DRY-RUN:", " ".join(cmd), ">", str(output_file))
        return
    output_file.parent.mkdir(parents=True, exist_ok=True)
    with output_file.open("w", encoding="utf-8") as fh:
        result = subprocess.run(cmd, stdout=fh, stderr=subprocess.PIPE, text=True, check=False)
    if result.returncode != 0:
        raise UpgradeError(f"pg_dump failed: {result.stderr}")


def create_backups(ctx: UpgradeContext, artifact_plan: dict[str, list[tuple[Path, Path]]]) -> None:
    section("Backups")
    if ctx.skip_backup:
        log("Skipping backups due to --skip-backup")
        return
    ctx.backup_dir = build_backup_dir(ctx)
    if not ctx.dry_run:
        ctx.backup_dir.mkdir(parents=True, exist_ok=True)
    unique_targets = {target for pairs in artifact_plan.values() for _, target in pairs}
    unique_targets.update({AUI_CONFIG_LIVE, CONFIG_API_SERVER_INI, ADMIN_UI_DIR})
    for target in sorted(unique_targets):
        if target.exists():
            rel = str(target).lstrip("/")
            copy_path(target, ctx.backup_dir / rel, dry_run=ctx.dry_run)
    dump_db(ctx, ctx.backup_dir / "db" / "schema.sql", schema_only=True)
    dump_db(ctx, ctx.backup_dir / "db" / "full.sql", schema_only=False)
    metadata = {
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "discovery": asdict(ctx.discovery) if ctx.discovery else {},
    }
    if ctx.dry_run:
        print(f"DRY-RUN: write metadata to {ctx.backup_dir / 'metadata.json'}")
    else:
        (ctx.backup_dir / "metadata.json").write_text(json.dumps(metadata, indent=2), encoding="utf-8")


def stop_services(ctx: UpgradeContext) -> None:
    section("Stopping services")
    order = ["apache2", "jans-casa", "jans-scim", "jans-fido2", "jans-config-api", "jans-auth"]
    for service in order:
        if ctx.discovery and ctx.discovery.services.get(service, False):
            run(["systemctl", "stop", service], dry_run=ctx.dry_run)


def start_services(ctx: UpgradeContext) -> None:
    section("Starting services")
    order = ["jans-auth", "jans-config-api", "jans-fido2", "jans-scim", "jans-casa", "apache2"]
    for service in order:
        if ctx.discovery and ctx.discovery.services.get(service, False):
            run(["systemctl", "start", service], dry_run=ctx.dry_run)


def replace_file(src: Path, dst: Path, *, dry_run: bool) -> None:
    if dry_run:
        print(f"DRY-RUN: replace {dst} <- {src}")
        return
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src, dst)


def replace_wars(ctx: UpgradeContext, artifact_plan: dict[str, list[tuple[Path, Path]]]) -> None:
    section("Replacing WARs")
    for src, dst in artifact_plan["wars"]:
        replace_file(src, dst, dry_run=ctx.dry_run)


def replace_plugins_and_libs(ctx: UpgradeContext, artifact_plan: dict[str, list[tuple[Path, Path]]]) -> None:
    section("Replacing selected plugins and auth custom libs")
    for bucket in ("config_api_plugins", "auth_custom_libs"):
        for src, dst in artifact_plan[bucket]:
            replace_file(src, dst, dry_run=ctx.dry_run)


def regenerate_env_config(ctx: UpgradeContext) -> None:
    if ctx.discovery is None:
        raise UpgradeError("Discovery report is not initialized")
    hostname = ctx.discovery.host.fqdn
    content = (
        f'const AUTH_SERVER_HOSTNAME = "{hostname}"\n'
        f'const CONFIG_API_BASE_URL = "https://{hostname}/jans-config-api"\n'
        f'const API_BASE_URL = "https://{hostname}/jans-config-api/admin-ui"\n'
        'const BASE_PATH = "/admin/"\n\n'
        'window.authServerHostname =  AUTH_SERVER_HOSTNAME\n'
        'window.configApiBaseUrl = CONFIG_API_BASE_URL\n'
        'window.apiBaseUrl = API_BASE_URL\n'
        'window.basePath = BASE_PATH\n'
    )
    env_cfg = ADMIN_UI_DIR / "env-config.js"
    if ctx.dry_run:
        print(f"DRY-RUN: write {env_cfg}")
        return
    env_cfg.write_text(content, encoding="utf-8")


def get_expected_configuration_endpoint(ctx: UpgradeContext) -> str:
    if ctx.discovery is None:
        raise UpgradeError("Discovery report is not initialized")
    host = ctx.discovery.host.fqdn.strip()
    if not host:
        raise UpgradeError("Could not determine current host FQDN")
    return f"https://{host}/.well-known/openid-configuration"


def patch_policy_store_cjar(ctx: UpgradeContext, policy_store_path: Path) -> None:
    expected_endpoint = get_expected_configuration_endpoint(ctx)
    internal_member = "trusted-issuers/GluuFlexAdminUI.json"

    ensure_exists(policy_store_path)

    if ctx.dry_run:
        print(f"DRY-RUN: inspect {policy_store_path}::{internal_member}")
        print(f"DRY-RUN: expected configuration_endpoint = {expected_endpoint}")
        return

    with zipfile.ZipFile(policy_store_path, "r") as zin:
        members = zin.namelist()
        if internal_member not in members:
            raise UpgradeError(
                f"{internal_member} not found inside policy store archive: {policy_store_path}"
            )

        raw = zin.read(internal_member).decode("utf-8")
        try:
            issuer_doc = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise UpgradeError(
                f"Invalid JSON in {internal_member} inside {policy_store_path}: {exc}"
            ) from exc

        old_endpoint = issuer_doc.get("configuration_endpoint")
        if old_endpoint == expected_endpoint:
            log(
                f"Policy store trusted issuer already correct: "
                f"{internal_member} -> {expected_endpoint}"
            )
            return

        issuer_doc["configuration_endpoint"] = expected_endpoint
        new_raw = json.dumps(issuer_doc, indent=2) + "\n"

        fd, tmp_name = tempfile.mkstemp(
            prefix="policy-store-", suffix=".cjar", dir=str(policy_store_path.parent)
        )
        os.close(fd)
        tmp_path = Path(tmp_name)

        try:
            with zipfile.ZipFile(policy_store_path, "r") as src_zip, \
                 zipfile.ZipFile(tmp_path, "w", compression=zipfile.ZIP_DEFLATED) as dst_zip:
                for item in src_zip.infolist():
                    data = src_zip.read(item.filename)
                    if item.filename == internal_member:
                        data = new_raw.encode("utf-8")
                    dst_zip.writestr(item, data)

            shutil.copystat(policy_store_path, tmp_path)
            tmp_path.replace(policy_store_path)
        finally:
            if tmp_path.exists():
                tmp_path.unlink(missing_ok=True)

        log(
            f"Policy store trusted issuer updated: "
            f"{internal_member} -> {expected_endpoint} "
            f"(previous: {old_endpoint})"
        )


def validate_policy_store_endpoint(ctx: UpgradeContext, policy_store_path: Path) -> None:
    expected_endpoint = get_expected_configuration_endpoint(ctx)
    internal_member = "trusted-issuers/GluuFlexAdminUI.json"

    ensure_exists(policy_store_path)

    with zipfile.ZipFile(policy_store_path, "r") as zf:
        if internal_member not in zf.namelist():
            raise UpgradeError(
                f"{internal_member} missing in {policy_store_path}"
            )
        issuer_doc = json.loads(zf.read(internal_member).decode("utf-8"))

    actual = issuer_doc.get("configuration_endpoint")
    if actual != expected_endpoint:
        raise UpgradeError(
            f"Policy store issuer mismatch in {policy_store_path}: "
            f"expected {expected_endpoint}, found {actual}"
        )


def migrate_policy_store(ctx: UpgradeContext) -> None:
    live_json = CONFIG_API_ADMINUI_POLICY_DIR / "policy-store.json"
    template_json = FLEX_TEMPLATE_DIR / "policy-store.json"
    live_cjar = CONFIG_API_ADMINUI_POLICY_DIR / "policy-store.cjar"
    template_cjar = FLEX_TEMPLATE_DIR / "policy-store.cjar"
    src = source_path(ctx, "templates/policy-store.cjar")

    if ctx.dry_run:
        print(f"DRY-RUN: replace {live_cjar} <- {src}")
        print(f"DRY-RUN: replace {template_cjar} <- {src}")
        print(
            "DRY-RUN: patch policy store trusted issuer inside "
            f"{live_cjar} to {get_expected_configuration_endpoint(ctx)}"
        )
        print(
            "DRY-RUN: patch policy store trusted issuer inside "
            f"{template_cjar} to {get_expected_configuration_endpoint(ctx)}"
        )
        return

    CONFIG_API_ADMINUI_POLICY_DIR.mkdir(parents=True, exist_ok=True)
    FLEX_TEMPLATE_DIR.mkdir(parents=True, exist_ok=True)

    shutil.copy2(src, live_cjar)
    shutil.copy2(src, template_cjar)

    if live_json.exists():
        live_json.rename(live_json.with_suffix(".json.bak"))
    if template_json.exists():
        template_json.rename(template_json.with_suffix(".json.bak"))

    patch_policy_store_cjar(ctx, live_cjar)
    patch_policy_store_cjar(ctx, template_cjar)

    run(
        ["chown", "-R", "jetty:jetty", str(CONFIG_API_ADMINUI_POLICY_DIR.parent)],
        dry_run=ctx.dry_run,
    )


def patch_admin_ui_db_config(ctx: UpgradeContext) -> None:
    if ctx.discovery is None:
        raise UpgradeError("Discovery report is not initialized")
    if not ctx.discovery.services.get("admin-ui"):
        return
    if ctx.skip_db:
        log("Skipping Admin UI DB config patch due to --skip-db")
        return

    db_name = ctx.discovery.install.persistence.db_name
    sql = r'''UPDATE public."jansAppConf"
SET "jansConfApp" = regexp_replace(
    regexp_replace(
        regexp_replace(
            regexp_replace(
                "jansConfApp",
                '"auiDefaultPolicyStorePath"[[:space:]]*:[[:space:]]*"\./custom/config/adminUI/policy-store\.json"',
                '"auiDefaultPolicyStorePath":"./custom/config/adminUI/policy-store.cjar"',
                'g'
            ),
            ',?[[:space:]]*"cedarlingPolicyStoreRetrievalPoint"[[:space:]]*:[[:space:]]*"default"',
            '',
            'g'
        ),
        ',[[:space:]]*}',
        '}',
        'g'
    ),
    '"cedarlingLogType"[[:space:]]*:[[:space:]]*"on"',
    '"cedarlingLogType":"std_out"',
    'g'
)
WHERE dn='ou=admin-ui,ou=configuration,o=jans';'''
    run(["sudo", "-u", "postgres", "psql", "-d", db_name, "-c", sql], dry_run=ctx.dry_run)


def migrate_admin_ui(ctx: UpgradeContext) -> None:
    if ctx.discovery is None or not ctx.discovery.services.get("admin-ui"):
        return
    section("Migrating Admin UI")
    tarball = source_path(ctx, "dist/admin-ui-main-built.tar.gz")
    if ctx.dry_run:
        print(f"DRY-RUN: replace Admin UI bundle from {tarball} into {ADMIN_UI_DIR}")
    else:
        if ADMIN_UI_DIR.exists():
            shutil.rmtree(ADMIN_UI_DIR)
        ADMIN_UI_DIR.mkdir(parents=True, exist_ok=True)
        with tarfile.open(tarball, "r:gz") as tf:
            tf.extractall(ADMIN_UI_DIR)

        dist_dir = ADMIN_UI_DIR / "dist"
        if dist_dir.exists() and (dist_dir / "index.html").exists():
            for item in list(dist_dir.iterdir()):
                target = ADMIN_UI_DIR / item.name
                if target.exists():
                    if target.is_dir():
                        shutil.rmtree(target)
                    else:
                        target.unlink()
                shutil.move(str(item), str(target))
            dist_dir.rmdir()

    regenerate_env_config(ctx)
    migrate_policy_store(ctx)
    patch_admin_ui_db_config(ctx)


def patch_server_ini(ctx: UpgradeContext) -> None:
    section("Patching Config API runtime")
    lines = CONFIG_API_SERVER_INI.read_text(encoding="utf-8", errors="ignore").splitlines() if CONFIG_API_SERVER_INI.exists() else []
    new_lines: list[str] = []
    replaced = False
    for line in lines:
        if line.strip().startswith("-Djava.security.properties"):
            if not replaced:
                new_lines.append(CONFIG_API_JAVA_SECURITY_PROP)
                replaced = True
            continue
        new_lines.append(line)
    if not replaced:
        new_lines.append(CONFIG_API_JAVA_SECURITY_PROP)
    content = "\n".join(new_lines) + "\n"
    if ctx.dry_run:
        print(f"DRY-RUN: patch {CONFIG_API_SERVER_INI}")
    else:
        CONFIG_API_SERVER_INI.write_text(content, encoding="utf-8")
    if ctx.dry_run:
        print(f"DRY-RUN: ensure {CONFIG_API_JAVA_SECURITY_DIR}")
        print(f"DRY-RUN: replace {CONFIG_API_JAVA_SECURITY} <- {source_path(ctx, 'templates/java.security')}")
    else:
        CONFIG_API_JAVA_SECURITY_DIR.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source_path(ctx, "templates/java.security"), CONFIG_API_JAVA_SECURITY)

def update_roles_model(ctx: UpgradeContext) -> None:
    # Function to handle changes done to roles and role-to-scope mappings between versions
    if ctx.discovery is None:
        raise UpgradeError("Discovery report is not initialized")

    db_name = ctx.discovery.install.persistence.db_name

    log('Creating new admin UI session permissions..')
    permissions_sql = r'''UPDATE public."jansAppConf"
SET "jansConfDyn" = jsonb_set(
    "jansConfDyn"::jsonb,
    '{permissions}',
    ("jansConfDyn"::jsonb -> 'permissions')
    ||
'[
{"tag":"adminui_session","permission":"https://jans.io/oauth/jans-auth-server/config/adminui/user/session.readonly","description":"","defaultPermissionInToken":true,"essentialPermissionInAdminUI":false},{"tag":"adminui_session","permission":"https://jans.io/oauth/jans-auth-server/config/adminui/user/session.write","description":"","defaultPermissionInToken":true,"essentialPermissionInAdminUI":false},{"tag":"adminui_session","permission":"https://jans.io/oauth/jans-auth-server/config/adminui/user/session.delete","description":"","defaultPermissionInToken":true,"essentialPermissionInAdminUI":false}
]'::jsonb
)::text
WHERE "doc_id" = 'admin-ui';'''
    run(["sudo", "-u", "postgres", "psql", "-d", db_name, "-c", permissions_sql], dry_run=ctx.dry_run)

    log('Adding new permissions mandatory to access admin UI to all non-admin legacy roles..')
    # Granting the new mandatory permissions to every legacy non-admin role present in rolePermissionMapping that is supposed to access admin UI
    # existing permissions are preserved, and a role that already holds one of these permissions is not given a duplicate
    session_permissions_sql = r'''UPDATE public."jansAppConf"
SET "jansConfDyn" = jsonb_set(
    "jansConfDyn"::jsonb,
    '{rolePermissionMapping}',
    COALESCE(
        (
            SELECT jsonb_agg(
                jsonb_set(
                    mapping.value,
                    '{permissions}',
                    COALESCE(
                        (
                            SELECT jsonb_agg(merged.perm ORDER BY merged.ord)
                            FROM (
                                SELECT existing.perm, existing.ord
                                FROM jsonb_array_elements_text(
                                         COALESCE(mapping.value -> 'permissions', '[]'::jsonb)
                                     ) WITH ORDINALITY AS existing(perm, ord)
                                UNION ALL
                                SELECT added.perm, 1000000 + added.ord
                                FROM unnest(ARRAY[
                                         'https://jans.io/oauth/jans-auth-server/config/adminui/user/session.readonly',
                                         'https://jans.io/oauth/jans-auth-server/config/adminui/user/session.write',
                                         'https://jans.io/oauth/jans-auth-server/config/adminui/user/session.delete',
                                         'https://jans.io/oauth/jans-auth-server/config/adminui/license.readonly',
                                         'https://jans.io/oauth/jans-auth-server/config/adminui/security.readonly',
                                         'https://jans.io/oauth/config/data.readonly'
                                     ]) WITH ORDINALITY AS added(perm, ord)
                                WHERE NOT COALESCE(mapping.value -> 'permissions', '[]'::jsonb) ? added.perm
                            ) AS merged
                        ),
                        '[]'::jsonb
                    )
                )
                ORDER BY mapping.ord
            )
            FROM jsonb_array_elements("jansConfDyn"::jsonb -> 'rolePermissionMapping')
                 WITH ORDINALITY AS mapping(value, ord)
        ),
        '[]'::jsonb
    )
)::text
WHERE "doc_id" = 'admin-ui'
  AND jsonb_typeof("jansConfDyn"::jsonb -> 'rolePermissionMapping') = 'array';'''
    run(["sudo", "-u", "postgres", "psql", "-d", db_name, "-c", session_permissions_sql], dry_run=ctx.dry_run)

    # Adding the default "admin" role existing in 6.0 package OOTB; pre-upgrade (old) roles are preserved
    log('Adding a new default admin role and importing default set of permissions for it..')
    roles_sql = r'''UPDATE public."jansAppConf"
SET "jansConfDyn" = jsonb_set(
    "jansConfDyn"::jsonb,
    '{roles}',
    ("jansConfDyn"::jsonb -> 'roles')
    ||
'{"role":"admin","description":"Auto-created role for admin","deletable":true}'
)::text
WHERE "doc_id" = 'admin-ui';'''
    run(["sudo", "-u", "postgres", "psql", "-d", db_name, "-c", roles_sql], dry_run=ctx.dry_run)

    # Importing default permissions/scopes for "admin" role  to ensure access to admin UI post-upgrade; mappings for pre-upgrade (old) roles are preserved
    role_permission_mapping_sql = r'''UPDATE public."jansAppConf"
SET "jansConfDyn" = jsonb_set(
    "jansConfDyn"::jsonb,
    '{rolePermissionMapping}',
    ("jansConfDyn"::jsonb -> 'rolePermissionMapping')
    ||
'{"role":"admin","permissions":["https://jans.io/oauth/jans-auth-server/config/adminui/user/session.readonly","https://jans.io/oauth/jans-auth-server/config/adminui/user/session.write","https://jans.io/oauth/jans-auth-server/config/adminui/user/session.delete","https://jans.io/oauth/config/attributes.readonly","https://jans.io/oauth/config/attributes.write","https://jans.io/oauth/config/attributes.delete","https://jans.io/oauth/config/acrs.readonly","https://jans.io/oauth/config/acrs.write","https://jans.io/oauth/config/acrs.delete","https://jans.io/oauth/config/scopes.readonly","https://jans.io/oauth/config/scopes.write","https://jans.io/oauth/config/scopes.delete","https://jans.io/oauth/config/scripts.readonly","https://jans.io/oauth/config/scripts.write","https://jans.io/oauth/config/scripts.delete","https://jans.io/oauth/config/openid/clients.readonly","https://jans.io/oauth/config/openid/clients.write","https://jans.io/oauth/config/openid/clients.delete","https://jans.io/oauth/config/smtp.readonly","https://jans.io/oauth/config/smtp.write","https://jans.io/oauth/config/smtp.delete","https://jans.io/oauth/config/logging.readonly","https://jans.io/oauth/config/logging.write","https://jans.io/oauth/config/uma/resources.readonly","https://jans.io/oauth/config/uma/resources.write","https://jans.io/oauth/config/uma/resources.delete","https://jans.io/oauth/config/database/ldap.readonly","https://jans.io/oauth/config/database/ldap.write","https://jans.io/oauth/config/database/ldap.delete","https://jans.io/oauth/config/jwks.readonly","https://jans.io/oauth/config/jwks.write","https://jans.io/oauth/config/fido2.readonly","https://jans.io/oauth/config/fido2.write","https://jans.io/oauth/config/message.readonly","https://jans.io/oauth/config/message.write","https://jans.io/oauth/config/cache.readonly","https://jans.io/oauth/config/cache.write","https://jans.io/oauth/config/database/sql.readonly","https://jans.io/oauth/config/database/sql.write","readonly","https://jans.io/oauth/config/stats.readonly","jans_stat","https://jans.io/oauth/jans-auth-server/config/adminui/user/role.readonly","https://jans.io/oauth/jans-auth-server/config/adminui/user/role.write","https://jans.io/oauth/jans-auth-server/config/adminui/user/permission.readonly","https://jans.io/oauth/jans-auth-server/config/adminui/user/permission.write","https://jans.io/oauth/jans-auth-server/config/adminui/user/rolePermissionMapping.readonly","https://jans.io/oauth/jans-auth-server/config/adminui/user/rolePermissionMapping.write","https://jans.io/oauth/jans-auth-server/config/adminui/license.readonly","https://jans.io/oauth/jans-auth-server/config/adminui/license.write","https://jans.io/scim/bulk","https://jans.io/scim/users.write","https://jans.io/scim/fido.read","https://jans.io/scim/all-resources.search","https://jans.io/scim/fido2.read","https://jans.io/scim/groups.write","https://jans.io/scim/users.read","https://jans.io/scim/groups.read","https://jans.io/scim/fido2.write","https://jans.io/scim/fido.write","https://jans.io/oauth/jans-auth-server/config/properties.write","https://jans.io/auth/ssa.admin","https://jans.io/auth/ssa.portal","https://jans.io/auth/ssa.developer","https://jans.io/oauth/jans-auth-server/config/adminui/webhook.readonly","https://jans.io/oauth/jans-auth-server/config/adminui/webhook.write","https://jans.io/oauth/jans-auth-server/config/adminui/webhook.delete","https://jans.io/oauth/jans-auth-server/config/adminui/properties.readonly","https://jans.io/oauth/jans-auth-server/config/adminui/properties.write","https://jans.io/oauth/jans-auth-server/config/adminui/logging.write","https://jans.io/oauth/jans-auth-server/session.delete","revoke_session","https://jans.io/oauth/config/data.readonly","https://jans.io/oauth/config/ssa.delete","https://jans.io/oauth/jans-auth-server/config/adminui/security.readonly","https://jans.io/oauth/jans-auth-server/config/adminui/security.write","https://jans.io/oauth/jans-auth-server/config/properties.readonly","https://jans.io/oauth/config/fido2.delete","https://jans.io/oauth/config/jwks.delete","https://jans.io/scim/config.readonly","https://jans.io/scim/config.write","https://jans.io/oauth/config/organization.readonly","https://jans.io/oauth/config/organization.write","https://jans.io/oauth/config/user.readonly","https://jans.io/oauth/config/user.write","https://jans.io/oauth/config/user.delete","https://jans.io/oauth/config/agama.readonly","https://jans.io/oauth/config/agama.write","https://jans.io/oauth/config/agama.delete","https://jans.io/oauth/jans-auth-server/session.readonly","https://jans.io/oauth/jans-auth-server/config/adminui/user/role.delete","https://jans.io/oauth/jans-auth-server/config/adminui/user/permission.delete","https://jans.io/oauth/jans-auth-server/config/adminui/user/rolePermissionMapping.delete","https://jans.io/oauth/config/plugin.readonly","https://jans.io/oauth/config/properties.readonly","https://jans.io/oauth/config/properties.write","https://jans.io/oauth/client/authorizations.readonly","https://jans.io/oauth/client/authorizations.delete","https://jans.io/oauth/config/jans-link.readonly","https://jans.io/oauth/config/jans-link.write","https://jans.io/oauth/config/saml.readonly","https://jans.io/oauth/config/saml.write","https://jans.io/oauth/config/saml-config.readonly","https://jans.io/oauth/config/saml-config.write","https://jans.io/oauth/config/saml-scope.readonly","https://jans.io/oauth/config/saml-scope.write","https://jans.io/idp/config.readonly","https://jans.io/idp/config.write","https://jans.io/idp/realm.readonly","https://jans.io/idp/realm.write","https://jans.io/idp/saml.readonly","https://jans.io/idp/saml.write","https://jans.io/idp/saml.delete","https://jans.io/oauth/config/app-version.readonly","https://jans.io/oauth/lock-config.readonly","https://jans.io/oauth/lock-config.write","https://jans.io/oauth/config/asset.readonly","https://jans.io/oauth/config/asset.write","https://jans.io/oauth/config/asset.admin","https://jans.io/oauth/lock/audit.readonly","https://jans.io/oauth/lock/audit.write","https://jans.io/oauth/lock/health.readonly","https://jans.io/oauth/lock/health.write","https://jans.io/oauth/lock/log.readonly","https://jans.io/oauth/lock/log.write","https://jans.io/oauth/lock/telemetry.readonly","https://jans.io/oauth/lock/telemetry.write","https://jans.io/oauth/config/token.readonly","https://jans.io/oauth/config/token.write","https://jans.io/oauth/config/token.delete","https://jans.io/oauth/config/agama-repo.readonly","https://jans.io/oauth/lock/read-all","https://jans.io/oauth/config/database.readonly","https://jans.io/oauth/config/ssa.readonly","https://jans.io/oauth/config/ssa.write","https://jans.io/oauth/config/uma.readonly","https://jans.io/oauth/config/uma.write","https://jans.io/oauth/config/uma.admin","https://jans.io/oauth/config/saml.delete","https://jans.io/oauth/config/asset.delete","https://jans.io/oauth/config/fido2-metrics.readonly"]}'::jsonb
)::text
WHERE "doc_id" = 'admin-ui';'''
    run(["sudo", "-u", "postgres", "psql", "-d", db_name, "-c", role_permission_mapping_sql], dry_run=ctx.dry_run)


def grant_adminUI_access(ctx: UpgradeContext) -> None:
    # Changes ["api-admin"] to ["admin"] in "jansAdminUIRole" column of users entries
    # to match recent changes to roles model
    # Ensures admin access is preserved for users that previously had it
    if ctx.discovery is None:
        raise UpgradeError("Discovery report is not initialized")

    db_name = ctx.discovery.install.persistence.db_name

    # Read-only lookup: always run, even under --dry-run, so we can report
    # (and, when not a dry run, act on) exactly which users are affected.
    select_sql = r'''SELECT "uid" FROM public."jansPerson" WHERE "jansAdminUIRole" ? 'api-admin';'''
    result = run(
        ["sudo", "-u", "postgres", "psql", "-d", db_name, "-t", "-A", "-c", select_sql],
        dry_run=False,
    )

    stdout = getattr(result, "stdout", result) or ""
    if isinstance(stdout, bytes):
        stdout = stdout.decode("utf-8")
    uids = [line.strip() for line in stdout.splitlines() if line.strip()]

    if not uids:
        log('No users found with legacy "api-admin" roles in jansAdminUIRole. It''s probably fine, but may result in lost access to admin UI post-upgrade if no user posses the new "admin" role after it')
        return

    log(f'Found {len(uids)} user(s) with legacy "api-admin" role in "jansAdminUIRole" column: {", ".join(uids)}')
    log('Will be updating them to use new "admin" role now instead..')

    for uid in uids:
        escaped_uid = uid.replace("'", "''")
        update_sql = (
            'UPDATE public."jansPerson" SET "jansAdminUIRole" = \'["admin"]\'::jsonb '
            f'WHERE "uid" = \'{escaped_uid}\';'
        )
        run(["sudo", "-u", "postgres", "psql", "-d", db_name, "-c", update_sql], dry_run=ctx.dry_run)


def update_casa_client_scopes(ctx: UpgradeContext) -> None:
    # Casa's OIDC client needs an additional scope in 6.0.0. Retrieves client's inum from casa's jansAppConf row
    # then adds an extra scope

    if ctx.discovery is None:
        raise UpgradeError("Discovery report is not initialized")
    if not ctx.discovery.services.get("jans-casa"):
        log("Casa is not installed on this host; skipping Casa client scope update")
        return

    db_name = ctx.discovery.install.persistence.db_name

    # Read-only lookups: always run, even under --dry-run, so we can report
    # exactly which client would be modified.
    log("Looking up Casa OIDC client's id/inum in jansAppConf..")
    client_lookup_sql = (
        'SELECT "jansConfApp"::jsonb -> \'oidc_config\' -> \'client\' ->> \'clientId\' '
        'FROM public."jansAppConf" WHERE "doc_id" = \'casa\';'
    )
    result = run(
        ["sudo", "-u", "postgres", "psql", "-X", "-d", db_name, "-t", "-A", "-c", client_lookup_sql],
        dry_run=False,
    )

    stdout = getattr(result, "stdout", result) or ""
    if isinstance(stdout, bytes):
        stdout = stdout.decode("utf-8")
    client_id = stdout.strip()

    # An empty result covers all three failure modes: no 'casa' row, no
    # clientId key, or a SQL NULL (rendered as an empty string by -t -A).
    if not client_id:
        msg = (
            "Could not determine Casa clientId from jansAppConf (doc_id='casa'); "
            "Casa client scopes were not updated"
        )
        log(f"WARNING: {msg}")
        ctx.warnings.append(msg)
        return

    escaped_client_id = client_id.replace("'", "''")
    log(f"Casa OIDC client id: {client_id}")

    # Resolve the scope URN to its DN, which is what jansClnt.jansScope stores.
    log(f'Finding out DN for scope "{CASA_EXTRA_CLIENT_SCOPE}"..')
    escaped_scope_urn = CASA_EXTRA_CLIENT_SCOPE.replace("'", "''")
    dn_lookup_sql = (
        f'SELECT "dn" FROM public."jansScope" WHERE "jansId" = \'{escaped_scope_urn}\';'
    )
    dn_result = run(
        ["sudo", "-u", "postgres", "psql", "-X", "-d", db_name, "-t", "-A", "-c", dn_lookup_sql],
        dry_run=False,
    )
    dn_stdout = getattr(dn_result, "stdout", dn_result) or ""
    if isinstance(dn_stdout, bytes):
        dn_stdout = dn_stdout.decode("utf-8")
    scope_dn = dn_stdout.strip()

    if not scope_dn:
        msg = (
            f'No scope found in jansScope with jansId "{CASA_EXTRA_CLIENT_SCOPE}"; '
            "Casa client scopes were not updated"
        )
        log(f"WARNING: {msg}")
        ctx.warnings.append(msg)
        return

    escaped_scope_dn = scope_dn.replace("'", "''")
    # Embedded in a JSON literal below, so quotes and backslashes need escaping too.
    json_scope_dn = json.dumps(scope_dn)
    log(f"DN for scope {CASA_EXTRA_CLIENT_SCOPE} is: {scope_dn}")

    # COALESCE to the literal 'null' so an existing row with a NULL jansScope
    # is distinguishable from a missing row.
    scope_lookup_sql = (
        'SELECT COALESCE("jansScope"::text, \'null\') '
        f'FROM public."jansClnt" WHERE "inum" = \'{escaped_client_id}\';'
    )
    scope_result = run(
        ["sudo", "-u", "postgres", "psql", "-X", "-d", db_name, "-t", "-A", "-c", scope_lookup_sql],
        dry_run=False,
    )
    scope_stdout = getattr(scope_result, "stdout", scope_result) or ""
    if isinstance(scope_stdout, bytes):
        scope_stdout = scope_stdout.decode("utf-8")
    raw_scopes = scope_stdout.strip()

    if not raw_scopes:
        msg = (
            f"No jansClnt row found for Casa client's inum {client_id}; "
            "Casa client scopes were not updated"
        )
        log(f"WARNING: {msg}")
        ctx.warnings.append(msg)
        return

    try:
        current_scopes = json.loads(raw_scopes)
    except json.JSONDecodeError:
        current_scopes = None

    if isinstance(current_scopes, list) and scope_dn in current_scopes:
        log(f'Casa client already has scope DN "{scope_dn}"; nothing to do')
        return
    if current_scopes is not None and not isinstance(current_scopes, list):
        msg = (
            f"jansScope for Casa client {client_id} is not a JSON array; "
            "Casa client scopes were not updated"
        )
        log(f"WARNING: {msg}")
        ctx.warnings.append(msg)
        return

    # Existing scopes are preserved; the guard clauses make the statement a no-op
    # if the scope is already present or the column holds something other than an array.
    log(f'Adding scope {CASA_EXTRA_CLIENT_SCOPE}\'s DN "{scope_dn}" to the list of Casa client\'s scopes..')
    update_sql = (
        'UPDATE public."jansClnt" '
        'SET "jansScope" = COALESCE("jansScope", \'[]\'::jsonb) '
        f'|| \'[{json_scope_dn}]\'::jsonb '
        f'WHERE "inum" = \'{escaped_client_id}\' '
        'AND jsonb_typeof(COALESCE("jansScope", \'[]\'::jsonb)) = \'array\' '
        f'AND NOT COALESCE("jansScope", \'[]\'::jsonb) ? \'{escaped_scope_dn}\';'
    )
    run(["sudo", "-u", "postgres", "psql", "-X", "-d", db_name, "-c", update_sql], dry_run=ctx.dry_run)


def migrate_database(ctx: UpgradeContext) -> None:
    section("Database migration")
    if ctx.skip_db:
        log("Skipping DB migration due to --skip-db")
        return
    if ctx.discovery is None:
        raise UpgradeError("Discovery report is not initialized")
    sql = 'ALTER TABLE public."adminUISession" ADD COLUMN IF NOT EXISTS "jansLastAccessTime" TIMESTAMP;'
    run(["sudo", "-u", "postgres", "psql", "-d", ctx.discovery.install.persistence.db_name, "-c", sql], dry_run=ctx.dry_run)

    # Update roles/scopes model and ensure admin access
    update_roles_model(ctx)
    grant_adminUI_access(ctx)
    update_casa_client_scopes(ctx)


def validate(ctx: UpgradeContext, artifact_plan: dict[str, list[tuple[Path, Path]]]) -> None:
    section("Validation")
    if ctx.dry_run:
        log("Dry-run validation: skipping post-change checks")
        return
    for _, dst in artifact_plan["wars"]:
        ensure_exists(dst)
    for _, dst in artifact_plan["config_api_plugins"]:
        ensure_exists(dst)
    for _, dst in artifact_plan["auth_custom_libs"]:
        ensure_exists(dst)
    if ctx.discovery and ctx.discovery.services.get("admin-ui"):
        ensure_exists(ADMIN_UI_DIR / "index.html")
        ensure_exists(ADMIN_UI_DIR / "env-config.js")
        ensure_exists(CONFIG_API_ADMINUI_POLICY_DIR / "policy-store.cjar")
        validate_policy_store_endpoint(ctx, CONFIG_API_ADMINUI_POLICY_DIR / "policy-store.cjar")
    ensure_exists(CONFIG_API_JAVA_SECURITY)
    statuses: dict[str, str] = {}
    for service in EXPECTED_SERVICES:
        if ctx.discovery and ctx.discovery.services.get(service, False):
            result = subprocess.run(["systemctl", "is-active", service], capture_output=True, text=True, check=False)
            statuses[service] = result.stdout.strip() or result.stderr.strip() or str(result.returncode)
    bad = {k: v for k, v in statuses.items() if v != "active"}
    if bad:
        raise UpgradeError(f"Service validation failed: {bad}")


def parse_args(argv: list[str]) -> UpgradeContext:
    p = argparse.ArgumentParser(description="Feature-aware Flex VM upgrade 5.16.0 -> 6.0.0")
    p.add_argument("--source-root", required=True, help="Path to staged 6.0.0 source artifacts")
    p.add_argument("--flex-fqdn", required=True, help="FQDN this Gluu Flex instance uses")
    p.add_argument("--backup-root", default="/root/flex-upgrade-backups")
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--skip-backup", action="store_true")
    p.add_argument("--skip-db", action="store_true")
    p.add_argument("--skip-restart", action="store_true")
    args = p.parse_args(argv)
    return UpgradeContext(
        source_root=Path(args.source_root),
        backup_root=Path(args.backup_root),
        flex_fqdn=args.flex_fqdn,
        dry_run=args.dry_run,
        skip_backup=args.skip_backup,
        skip_db=args.skip_db,
        skip_restart=args.skip_restart,
    )


def print_summary(ctx: UpgradeContext) -> None:
    payload = {
        "discovery": asdict(ctx.discovery) if ctx.discovery else {},
        "backup_dir": str(ctx.backup_dir) if ctx.backup_dir else None,
        "warnings": ctx.warnings,
    }
    print(json.dumps(payload, indent=2))


def main(argv: list[str]) -> int:
    ctx = parse_args(argv)
    try:
        require_root()
        ctx.discovery = discover()
        # override Flex's FQDN to not rely on auto-detection
        ctx.discovery.host.fqdn = ctx.flex_fqdn 
        section("Discovery result")
        print(json.dumps(asdict(ctx.discovery), indent=2))

        if ctx.discovery.services.get("jans-lock") or "jans-lock" in ctx.discovery.upgrade_plan.get("optional_components", []):
            raise UpgradeError("This upgrader generation does not support jans-lock-enabled hosts")
        if ctx.discovery.services.get("jans-kc") or "jans-kc" in ctx.discovery.upgrade_plan.get("optional_components", []):
            raise UpgradeError("This upgrader generation does not support jans-kc-enabled hosts")
        if ctx.discovery.install.persistence.mode != "local" or ctx.discovery.install.persistence.type not in ("pgsql", "sql"):
            raise UpgradeError("This upgrader generation currently supports only local PostgreSQL-backed hosts")

        artifact_plan = build_artifact_plan(ctx)
        create_backups(ctx, artifact_plan)
        stop_services(ctx)
        replace_wars(ctx, artifact_plan)
        replace_plugins_and_libs(ctx, artifact_plan)
        migrate_admin_ui(ctx)
        patch_server_ini(ctx)
        migrate_database(ctx)
        if not ctx.skip_restart:
            start_services(ctx)
        validate(ctx, artifact_plan)
        print_summary(ctx)
        log("Feature-aware upgrade completed successfully")
        return 0
    except UpgradeError as exc:
        log(f"ERROR: {exc}")
        if ctx.backup_dir:
            log(f"Backups: {ctx.backup_dir}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main(os.sys.argv[1:]))
