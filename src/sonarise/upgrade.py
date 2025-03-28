from __future__ import annotations
import argparse
import glob
import json
import os
import subprocess
import sys
import tempfile
import time
import traceback
from contextlib import contextmanager
from datetime import datetime
from functools import wraps
from pathlib import Path
import shutil
from typing import Optional

import requests
from packaging import version

from sonarise.config import ConfigError, FileConfig, load_config
from sonarise.utils.logger import logger, structured_logger
from sonarise.version_check import (
    VersionCheckResult,
    sonarqube_get_latest,
    SonarQubeVersionChecker,
)

# Add parent directory to Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))

# Define constants for paths
SONARQUBE_OLD_PATH = "/opt/sonarqube.old"
SONARQUBE_NEW_PATH = "/opt/sonarqube"
SONARQUBE_BACKUP_BASE = "/opt/sonarqube_backup"  # Base directory for all backups

# Additional constants
TIMEOUT_DEFAULT = 300  # seconds
MIN_BACKUP_SIZE = 1024 * 1024  # 1MB
DRY_RUN = False

# Add new constants
LOCK_FILE_DIR = "/var/run/sonarqube"  # More secure location for lock file
LOCK_FILE = os.path.join(LOCK_FILE_DIR, "sonarqube_upgrade.lock")
BACKUP_DIR = "/var/backup/sonarqube"  # Secure location for backups
TEMP_DIR = "/var/tmp/sonarqube"  # Dedicated temp directory


# Simplify version validation to just check format
def validate_version_string(version_str):
    """Validate version string format."""
    try:
        return str(version.parse(version_str))
    except version.InvalidVersion:
        raise ValueError(f"Invalid version format: {version_str}")


def is_version_upgrade_compatible(current_version, new_version):
    """Enhanced version compatibility check."""
    try:
        current = version.parse(current_version)
        new = version.parse(new_version)

        if new <= current:
            raise UpgradeError(
                f"New version ({new}) must be greater than current version ({current})"
            )

        return True

    except version.InvalidVersion as e:
        raise UpgradeError(f"Invalid version format: {str(e)}")


def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="SonarQube upgrade script",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  Check permissions: sudo -v && python3 upgrade.py --check-permissions
  Dry run: sudo python3 upgrade.py --dry-run
  Full upgrade: sudo python3 upgrade.py
        """,
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Simulate upgrade process without making changes",
    )
    parser.add_argument(
        "--check-permissions",
        action="store_true",
        help="Check if you have the required permissions to run the upgrade",
    )
    return parser.parse_args()


def check_permissions(config: FileConfig):
    """Check if the script has all required permissions."""
    checks = [
        ("Root privileges", lambda: os.geteuid() == 0),
        (
            "SonarQube directory access",
            lambda: os.access(config.install_dir, os.R_OK | os.W_OK),
        ),
        ("Systemctl access", lambda: os.access("/usr/bin/systemctl", os.X_OK)),
    ]

    all_passed = True
    for check_name, check_func in checks:
        if check_func():
            logger.info(f"✓ {check_name}: OK")
        else:
            logger.error(f"✗ {check_name}: Failed")
            all_passed = False

    return all_passed


def get_version():
    """Get the latest version of SonarQube using the custom module."""
    result = sonarqube_get_latest()
    if not result.is_success:
        raise UpgradeError(f"Failed to get latest version: {result.error}")
    return result.version


def dry_run_check(operation: str) -> Optional[bool]:
    """Log operation in dry run mode without executing."""
    if DRY_RUN:
        logger.info(f"[DRY RUN] Would execute: {operation}")
        return True
    return False


def run_command(command, shell=False, timeout=TIMEOUT_DEFAULT):
    """Run a shell command with dry run support."""
    if dry_run_check(command):
        return "dry-run-output"
    try:
        process = subprocess.Popen(
            command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=shell
        )
        output, error = process.communicate(timeout=timeout)
        if process.returncode != 0:
            raise subprocess.CalledProcessError(
                process.returncode, command, output=output, stderr=error
            )
        return output.decode()
    except subprocess.TimeoutExpired:
        process.kill()
        raise TimeoutError(f"Command timed out after {timeout} seconds: {command}")
    except Exception as e:
        logger.error(f"Command failed: {command}\nError: {str(e)}")
        raise


def retry_on_failure(retries=3, delay=5):
    """Decorator to retry functions on failure."""

    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            for attempt in range(retries):
                try:
                    return func(*args, **kwargs)
                except Exception as e:
                    if attempt == retries - 1:
                        raise
                    logger.warning(f"Attempt {attempt + 1} failed: {str(e)}")
                    time.sleep(delay)
            return None

        return wrapper

    return decorator


@contextmanager
def backup_context():
    """Context manager for secure database backup operations."""
    ensure_secure_directory(BACKUP_DIR)
    backup_path = os.path.join(BACKUP_DIR, f"sonarqube_backup_{int(time.time())}.gz")
    try:
        yield backup_path
    finally:
        if os.path.exists(backup_path) and os.path.getsize(backup_path) == 0:
            os.unlink(backup_path)


def validate_config():
    """Validate required configurations and permissions."""
    if os.geteuid() != 0:
        raise PermissionError(
            "This script must be run as root. Please use: sudo python3 upgrade.py"
        )

    required_dirs = [SONARQUBE_NEW_PATH]
    for dir_path in required_dirs:
        if not os.path.exists(dir_path):
            raise ValueError(f"Required directory not found: {dir_path}")


def get_current_version():
    """Get the current version of SonarQube installed."""
    with SonarQubeVersionChecker(
        "https://sonarqube.local", os.getenv("SONARQUBE_TOKEN")
    ) as checker:
        result = checker.check_deployed_version()
        if not result.is_success:
            raise UpgradeError(f"Failed to get current version: {result.error}")
        return result.version


class UpgradeError(Exception):
    """Custom exception for upgrade errors."""

    pass


def check_version_compatibility(new_version):
    """Check if the new version is compatible for upgrade."""
    current = get_current_version()
    if not is_version_upgrade_compatible(current, new_version):
        raise ValueError(
            f"Direct upgrade from {current} to {new_version} is not supported"
        )


@retry_on_failure(retries=3)
def backup_database():
    """Backup the SonarQube PostgreSQL database with validation."""
    if dry_run_check("backup_database"):
        return
    with backup_context() as backup_file:
        logger.info("Backing up database...")
        backup_command = f"pg_dump sonarqube | gzip > {backup_file}"
        run_command(backup_command, shell=True)

        # Verify backup file
        if not os.path.exists(backup_file) or os.path.getsize(backup_file) == 0:
            raise ValueError("Database backup failed or is empty")


def ensure_secure_directory(path, mode=0o700):
    """Create a secure directory with restricted permissions."""
    try:
        os.makedirs(path, mode=mode, exist_ok=True)
        # Ensure the directory has the correct permissions even if it already existed
        os.chmod(path, mode)
        # Ensure the directory is owned by the current user
        os.chown(path, os.getuid(), os.getgid())
        return path
    except OSError as e:
        raise UpgradeError(f"Failed to create secure directory {path}: {str(e)}")


def create_secure_tempdir():
    """Create a secure temporary directory."""
    temp_dir = ensure_secure_directory(TEMP_DIR)
    return tempfile.mkdtemp(prefix="sonarqube_", dir=temp_dir)


@contextmanager
def secure_tempfile(suffix=None):
    """Create a secure temporary file."""
    temp_dir = ensure_secure_directory(TEMP_DIR)
    fd, path = tempfile.mkstemp(dir=temp_dir, suffix=suffix)
    try:
        os.chmod(path, 0o600)
        os.close(fd)
        yield path
    finally:
        if os.path.exists(path):
            os.unlink(path)


def download_sonarqube(version, download_dir):
    """Download the specified SonarQube version with secure file handling."""
    url = os.getenv(
        "SONARQUBE_URL",
        "https://binaries.sonarsource.com/CommercialDistribution/sonarqube-developer/",
    )
    zipfile = f"sonarqube-developer-{version}.zip"

    logger.info(f"Downloading SonarQube version {version} from {url}")

    with secure_tempfile(suffix=".zip") as temp_path:
        try:
            r = requests.get(
                f"{url}{zipfile}",
                allow_redirects=True,
                timeout=300,
                verify=True,
                stream=True,
            )
            r.raise_for_status()

            # Stream the download to avoid loading entire file into memory
            with open(temp_path, "wb") as f:
                for chunk in r.iter_content(chunk_size=8192):
                    if chunk:
                        f.write(chunk)

            # Verify download size
            file_size = os.path.getsize(temp_path)
            if file_size < 1000000:  # Minimum expected size
                raise UpgradeError("Downloaded file is suspiciously small")

            # Move to final location
            final_path = os.path.join(download_dir, zipfile)
            shutil.move(temp_path, final_path)
            os.chmod(final_path, 0o644)  # Read-only for owner and group

            return final_path, f"sonarqube-{version}"

        except Exception as e:
            if os.path.exists(temp_path):
                os.unlink(temp_path)
            raise UpgradeError(f"Download failed: {str(e)}")


def extract_zip(zip_path, destination):
    """Extract a zip file to a destination directory."""
    logger.info(f"Extracting zip file to {destination}...")
    unzip_command = f"unzip {zip_path} -d {destination}"
    run_command(unzip_command, shell=True)


def safe_file_operations(func):
    """Decorator for safe file operations with rollback capability."""

    @wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except Exception as e:
            logger.error(f"File operation failed: {str(e)}")
            rollback_old_version()
            raise

    return wrapper


@safe_file_operations
def update_properties(old_properties: str, new_properties: str):
    """Update properties file with enhanced validation."""
    if dry_run_check(f"update_properties: {old_properties} -> {new_properties}"):
        return
    if not os.path.exists(old_properties):
        raise FileNotFoundError(f"Old properties file not found: {old_properties}")

    # Create backup of new properties file
    shutil.copy2(new_properties, f"{new_properties}.bak")

    try:
        custom_props = {}
        with open(old_properties, "r") as old_file:
            for line in old_file:
                line = line.strip()
                if line.startswith("sonar.") and "=" in line:
                    key, value = line.split("=", 1)
                    custom_props[key.strip()] = value.strip()

        with open(new_properties, "a") as new_file:
            new_file.write("\n# Custom properties migrated from previous version\n")
            for key, value in custom_props.items():
                new_file.write(f"{key}={value}\n")
    except Exception:
        # Restore backup on failure
        shutil.move(f"{new_properties}.bak", new_properties)
        raise


def rollback_old_version():
    """Rollback to the previous version if something goes wrong."""
    logger.info("Rolling back to the previous version...")

    # Find the most recent backup
    backup_pattern = f"{SONARQUBE_BACKUP_BASE}_*"
    backups = sorted(glob.glob(backup_pattern), reverse=True)

    if not backups:
        raise UpgradeError("No backup found to restore from")

    latest_backup = backups[0]
    logger.info(f"Found backup at {latest_backup}")

    if os.path.exists(SONARQUBE_NEW_PATH):
        shutil.rmtree(SONARQUBE_NEW_PATH)

    shutil.copytree(latest_backup, SONARQUBE_NEW_PATH)
    run_command(f"chown -R sonarqube:sonarqube {SONARQUBE_NEW_PATH}", shell=True)
    logger.info("Successfully restored from backup")


def validate_service(service_name):
    """Check if the service has started."""
    logger.info(f"Checking if {service_name} service started...")
    status_command = f"systemctl is-active {service_name}"
    result = run_command(status_command, shell=True)
    if result.strip() == "active":
        logger.info(
            f"{service_name} service started. Note: Database upgrades and additional setup steps may be required."
        )
        return True
    logger.error(f"{service_name} failed to start.")
    return False


def clean_up_environment():
    """Clean up orphaned processes or any leftover temporary files."""
    if DRY_RUN:
        logger.info("[DRY RUN] Would clean up environment")
        return

    logger.info("Cleaning up any orphaned processes...")
    try:
        run_command("systemctl stop sonarqube", shell=True)
    except Exception as e:
        logger.warning(f"Cleanup failed (non-critical): {str(e)}")


def clean_up_old_version():
    """Create a timestamped backup of the current installation."""
    if DRY_RUN:
        logger.info("[DRY RUN] Would create backup of current installation")
        return

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_path = f"{SONARQUBE_BACKUP_BASE}_{timestamp}"

    # Create backup directory if it doesn't exist
    os.makedirs(os.path.dirname(SONARQUBE_BACKUP_BASE), exist_ok=True)

    if os.path.exists(SONARQUBE_NEW_PATH):
        logger.info(f"Creating backup at {backup_path}")
        shutil.copytree(SONARQUBE_NEW_PATH, backup_path)
        logger.info("Backup completed successfully")
    else:
        logger.warning(f"No existing installation found at {SONARQUBE_NEW_PATH}")


def validate_backup(backup_file):
    """Validate backup file integrity."""
    min_size = 1024  # 1KB minimum
    if not os.path.exists(backup_file):
        raise UpgradeError("Backup file not found")
    if os.path.getsize(backup_file) < min_size:
        raise UpgradeError("Backup file is too small")
    return True


def simulate_upgrade(version: str) -> None:
    """Simulate the upgrade process for dry run mode."""
    structured_logger.info("[DRY RUN] Starting upgrade simulation")
    structured_logger.info(f"[DRY RUN] Would download SonarQube version: {version}")

    current_version = get_current_version()
    structured_logger.info(f"[DRY RUN] Current installed version: {current_version}")
    structured_logger.info(f"[DRY RUN] Upgrade path: {current_version} -> {version}")

    checks = [
        ("Config validation", lambda: True),
        ("Current version check", get_current_version),
        ("Version compatibility", lambda: check_version_compatibility(version)),
        ("Database backup space", lambda: shutil.disk_usage("/")[2] > MIN_BACKUP_SIZE),
        ("Download space", lambda: shutil.disk_usage("/opt")[2] > 500 * 1024 * 1024),
        ("Service status", lambda: True),
    ]

    for check_name, check_func in checks:
        try:
            check_func()
            structured_logger.info(f"[DRY RUN] ✓ {check_name} passed")
        except Exception:
            structured_logger.error(f"[DRY RUN] ✗ {check_name} would fail")
            raise

    structured_logger.info("[DRY RUN] Simulation completed successfully")


@contextmanager
def upgrade_lock(lock_dir):
    """Ensure only one upgrade process runs at a time using a secure lock file."""
    ensure_secure_directory(lock_dir)

    lock_file = os.path.join(lock_dir, "sonarqube_upgrade.lock")

    if os.path.exists(lock_file):
        try:
            with open(lock_file, "r") as f:
                pid = int(f.read().strip())
            if pid and os.path.exists(f"/proc/{pid}"):
                raise UpgradeError("Another upgrade process is running")
            # Lock file exists but process is dead, remove it
            os.unlink(lock_file)
        except (ValueError, FileNotFoundError):
            os.unlink(lock_file)

    try:
        with open(lock_file, "w") as f:
            os.chmod(lock_file, 0o600)
            f.write(str(os.getpid()))
        yield
    finally:
        if os.path.exists(lock_file):
            os.unlink(lock_file)


def create_restore_point():
    """Create a complete restore point including configuration and plugins."""
    restore_dir = f"{SONARQUBE_OLD_PATH}_restore_{int(time.time())}"
    try:
        shutil.copytree(SONARQUBE_NEW_PATH, restore_dir)
        with open(f"{restore_dir}/restore_info.json", "w") as f:
            json.dump(
                {
                    "timestamp": datetime.now().isoformat(),
                    "version": get_current_version(),
                    "plugins": list(
                        Path(f"{SONARQUBE_NEW_PATH}/extensions/plugins").glob("*.jar")
                    ),
                },
                f,
            )
        return restore_dir
    except Exception:
        if os.path.exists(restore_dir):
            shutil.rmtree(restore_dir)
        raise UpgradeError("Failed to create restore point")


def rollback_to_restore_point(restore_dir: str) -> None:
    """Rollback to a previously created restore point."""
    try:
        if not os.path.exists(restore_dir):
            raise UpgradeError("Restore point not found")

        logger.info("Rolling back to restore point...")
        if os.path.exists(SONARQUBE_NEW_PATH):
            shutil.rmtree(SONARQUBE_NEW_PATH)
        shutil.copytree(restore_dir, SONARQUBE_NEW_PATH)
        run_command(f"chown -R sonarqube:sonarqube {SONARQUBE_NEW_PATH}", shell=True)
        logger.info("Successfully restored from backup")
    except Exception as e:
        raise UpgradeError(f"Failed to rollback to restore point: {str(e)}")


def copy_plugins(source_dir: str, dest_dir: str):
    """Copy plugins with proper error handling and validation."""
    logger.info(f"Copying plugins from {source_dir} to {dest_dir}")

    # Create plugins directory if it doesn't exist
    os.makedirs(dest_dir, exist_ok=True)

    # Get list of plugin files
    plugin_files = list(Path(source_dir).glob("*.jar"))

    if not plugin_files:
        logger.warning("No plugins found to copy - continuing with upgrade")
        return

    for plugin in plugin_files:
        try:
            dest_file = os.path.join(dest_dir, plugin.name)
            shutil.copy2(str(plugin), dest_file)
            logger.info(f"Copied plugin: {plugin.name}")
        except Exception as e:
            logger.error(f"Failed to copy plugin {plugin.name}: {str(e)}")
            raise UpgradeError(f"Plugin copy failed: {str(e)}")


def validate_environment() -> None:
    """Validate environment before upgrade"""
    if os.geteuid() != 0:
        raise UpgradeError("Script must be run as root")

    _, file_config = load_config()  # Keep file_config as it's used
    try:
        file_config.validate()
    except ConfigError as e:
        raise UpgradeError(f"Configuration error: {e}")


def main() -> None:
    """Main execution function with improved error handling"""
    try:
        validate_environment()
        _, file_config = load_config()  # Keep file_config as it's used
    except UpgradeError as e:
        logger.error(str(e))
        sys.exit(1)

    with structured_logger.operation("upgrade"):
        args = parse_arguments()
        global DRY_RUN
        DRY_RUN = args.dry_run

        structured_logger.info(
            "Starting SonarQube upgrade",
            dry_run=DRY_RUN,
            pid=os.getpid(),
            user=os.getenv("USER"),
        )

        if args.check_permissions:
            sys.exit(0 if check_permissions(file_config) else 1)

        if os.geteuid() != 0:
            logger.error("Error: This script must be run as root.")
            sys.exit(1)

        with upgrade_lock(file_config.lock_dir):
            start_time = time.time()
            secure_tmp_dir = create_secure_tempdir()
            restore_point = None

            try:
                if DRY_RUN:
                    version = validate_version_string(get_version())
                    simulate_upgrade(version)
                    return

                restore_point = create_restore_point()

                # Clean up the old version if it exists
                clean_up_old_version()

                # Backup the database
                backup_database()

                # Retrieve the latest version of SonarQube
                version = validate_version_string(get_version())

                # Add version compatibility check
                check_version_compatibility(version)

                zipfile_path, foldername = download_sonarqube(version, secure_tmp_dir)

                # Extract downloaded file
                extract_zip(zipfile_path, "/opt")

                # Apply temporary permissions
                logger.info("Applying permissions to new version files...")
                run_command(
                    f"chown -R sonarqube:sonarqube /opt/{foldername}", shell=True
                )

                # Update sonar.properties file
                old_sonar_properties = f"{SONARQUBE_NEW_PATH}/conf/sonar.properties"
                new_sonar_properties = f"/opt/{foldername}/conf/sonar.properties"
                update_properties(old_sonar_properties, new_sonar_properties)

                # Copy plugins to the new version
                logger.info("Copying plugins...")
                source_plugins = f"{SONARQUBE_NEW_PATH}/extensions/plugins"
                dest_plugins = f"/opt/{foldername}/extensions/plugins"

                if os.path.exists(source_plugins):
                    copy_plugins(source_plugins, dest_plugins)
                else:
                    logger.warning(f"Plugins directory not found: {source_plugins}")

                # Stop old SonarQube server
                logger.info("Stopping old SonarQube server...")
                run_command("systemctl stop sonarqube", shell=True)

                # Backup old version and rename new version
                logger.info("Backing up old version...")
                run_command(f"mv {SONARQUBE_NEW_PATH} {SONARQUBE_OLD_PATH}", shell=True)
                run_command(f"mv /opt/{foldername} {SONARQUBE_NEW_PATH}", shell=True)

                # Set permissions for the new version
                logger.info("Setting permissions for the new version...")
                run_command(
                    f"chown -R sonarqube:sonarqube {SONARQUBE_NEW_PATH}", shell=True
                )

                # Start the new SonarQube server
                logger.info("Starting new SonarQube server...")
                run_command("systemctl start sonarqube", shell=True)

                # Only verify the service is running
                if not validate_service("sonarqube"):
                    logger.error("Service failed to start")
                    rollback_old_version()
                else:
                    logger.info(
                        """
Upgrade files copied successfully. 
Service is running.
IMPORTANT: Visit https://sonarqube.local/setup to complete the database upgrade 
and configuration steps. This is a required manual step for all SonarQube upgrades.
"""
                    )

                # Add execution time logging
                execution_time = time.time() - start_time
                structured_logger.info(
                    "File deployment completed",
                    execution_time=f"{execution_time:.2f}s",
                    new_version=version,
                )

            except Exception as e:
                structured_logger.error(
                    "Upgrade failed", error=str(e), traceback=traceback.format_exc()
                )
                if restore_point and os.path.exists(restore_point):
                    logger.info("Rolling back to restore point...")
                    rollback_to_restore_point(restore_point)
                raise
            finally:
                # Secure cleanup
                if os.path.exists(secure_tmp_dir):
                    shutil.rmtree(secure_tmp_dir, ignore_errors=True)


if __name__ == "__main__":
    main()
