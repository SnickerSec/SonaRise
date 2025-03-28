# SonaRise

Automated script for safely upgrading SonarQube Enterprise with backup, validation, and rollback capabilities.

## ⚠️ Important Database Upgrade Note

**After file deployment, you MUST complete the database upgrade process manually:**

1. Visit: `https://sonarqube.local/setup`
2. Follow the database upgrade wizard
3. Wait for the process to complete (may take several minutes)
4. Do not interrupt the upgrade process

This is a required step for all SonarQube upgrades.

## Features

- Automated backup and restore
- Version compatibility checking
- Safe rollback on failure
- Dry run simulation
- Permission validation
- Structured logging
- Plugin migration
- Configuration preservation
- Secure temporary file handling
- Process locking mechanism

## Security Features

- Secure temporary directory usage
- File permission restrictions (0o600 for sensitive files)
- Directory permission controls (0o700 for directories)
- Process-based lock files
- Safe cleanup procedures
- Dedicated backup locations
- Download streaming to prevent memory issues
- Secure API token handling
- Plugin validation and verification
- Environment validation checks

## Plugin Validation

The tool performs extensive plugin validation:

- File integrity checks
- Size verification (minimum 1KB)
- Extension validation (.jar only)
- Secure permissions (0o644)
- Progress tracking during copy
- Atomic operations with rollback
- Cleanup on failure

## Environment Validation

Pre-upgrade checks include:

- Minimum free space requirements:
  - Temp space: 100MB
  - Backup space: 500MB
- Required commands:
  - unzip
  - systemctl
  - pg_dump
- Directory permissions
- Configuration validation
- Service status

## Prerequisites

- Root/sudo access
- Python 3.8+
- PostgreSQL client tools
- Write access to:
  - `/var/run/sonarqube` (lock files)
  - `/var/backup/sonarqube` (backups)
  - `/var/tmp/sonarqube` (temporary files)
  - `/opt/sonarqube` (installation)

## Required Python packages:

```bash
requests
beautifulsoup4
packaging
```

## Installation

1. Clone the repository:

```bash
git clone https://github.com/cwillisf/sonarise.git
cd sonarise
```

2. Create and activate virtual environment:

```bash
python -m venv venv
source venv/bin/activate  # On Linux/Mac
# OR
.\venv\Scripts\activate   # On Windows
```

3. Install the package in development mode:

```bash
pip install -e .         # Install package
pip install -e .[dev]    # Install with development dependencies
```

4. Set required environment variables:

```bash
export SONARQUBE_URL="https://sonarqube.local"     # SonarQube instance URL
export SONARQUBE_TOKEN="your-token"                # API token
export SONARQUBE_VERIFY_SSL="true"                 # Optional: SSL verification
export SONARQUBE_CERT_PATH="/path/to/cert"         # Optional: Custom certificate
```

5. Create required directories with proper permissions:

```bash
# Create directories
sudo mkdir -p /var/run/sonarqube \
             /var/backup/sonarqube \
             /var/tmp/sonarqube \
             /var/log/sonarqube/upgrade

# Set ownership (replace USER with your username)
sudo chown -R $USER:$USER /var/run/sonarqube \
                         /var/backup/sonarqube \
                         /var/tmp/sonarqube \
                         /var/log/sonarqube/upgrade

# Set secure permissions
sudo chmod 700 /var/run/sonarqube \
              /var/backup/sonarqube \
              /var/tmp/sonarqube \
              /var/log/sonarqube/upgrade
```

## Usage

### Check Permissions

```bash
sudo -v && python3 upgrade.py --check-permissions
```

### Dry Run

```bash
sudo python3 upgrade.py --dry-run
```

### Full Upgrade

```bash
sudo python3 upgrade.py
```

## Directory Structure

```
/opt/
├── sonarqube/              # Current installation
├── sonarqube_backup_*      # Timestamped backups (YYYYMMDD_HHMMSS)
/var/run/sonarqube/         # Lock files
├── sonarqube_upgrade.lock
/var/backup/sonarqube/      # Database backups
├── sonarqube_backup_*.gz
/var/tmp/sonarqube/         # Temporary files
├── sonarqube_*             # Temporary directories
```

## Backup Strategy

### Installation Backups

- Automatic timestamped backups before each upgrade
- Format: `/opt/sonarqube_backup_YYYYMMDD_HHMMSS`
- Preserves complete installation including:
  - Configuration files
  - Plugins
  - Custom settings
  - File permissions

### Database Backups

- PostgreSQL dumps stored in `/var/backup/sonarqube/`
- Compressed with gzip
- Validated for minimum size and integrity
- Naming: `sonarqube_backup_[timestamp].gz`

### Rollback Process

The script automatically:

1. Locates the most recent timestamped backup
2. Restores the complete installation
3. Preserves all file permissions
4. Maintains configuration integrity

## Version Compatibility Rules

- Version downgrade is not supported
- The new version must be greater than the current version
- Basic version format validation
- No version restrictions beyond these rules

For detailed upgrade paths, see [SonarQube Update Center](https://docs.sonarqube.org/latest/setup/upgrade-notes/)

## Security Considerations

### File Permissions

- Temporary files: 0o600 (user read/write only)
- Directories: 0o700 (user full access only)
- Lock files: 0o600 (user read/write only)
- Downloaded files: 0o644 (user read/write, group/others read)

### Process Isolation

- Single upgrade process enforcement
- PID-based lock file validation
- Automatic dead lock cleanup

### Data Protection

- Secure temporary file handling
- Automatic cleanup of sensitive data
- Checksum verification of downloads
- Streaming download to prevent memory exhaustion
- Backup validation before upgrade

## Error Handling

The script includes comprehensive error handling for:

- Version compatibility
- Download integrity
- Backup validation
- Service health checks
- Permission issues
- Process locking
- Temporary file operations
- Directory access
- Network operations

## Logging

Logs are written to both console and file:

```
sonarqube_upgrade_YYYYMMDD_HHMMSS.log
```

## Rollback Process

In case of failure, the script automatically:

1. Stops the new instance
2. Cleans up temporary files
3. Restores the old version
4. Restarts the service
5. Validates health endpoints
6. Verifies service status

## Database Upgrade Process

### Pre-Upgrade Steps

1. Ensure sufficient database backup space
2. Verify database permissions
3. Check for active connections

### Post-File Deployment Steps

1. Wait for service to start
2. Visit `https://sonarqube.local/setup`
3. Follow the database upgrade wizard
4. Monitor logs: `tail -f /var/log/sonarqube/sonar.log`

### Common Database Issues

- Insufficient database permissions
- Low disk space
- Database connection timeouts
- Incompatible plugins

### Recovery Options

If database upgrade fails:

1. Stop SonarQube:

   ```bash
   sudo systemctl stop sonarqube
   ```

2. Restore database:

   ```bash
   gunzip -c /var/backup/sonarqube/sonarqube_backup_*.gz | psql sonarqube
   ```

3. Rollback to previous version:
   ```bash
   sudo mv /opt/sonarqube.old/* /opt/sonarqube/
   sudo systemctl start sonarqube
   ```

## Troubleshooting

### Common Issues

1. Permission denied:

   ```bash
   sudo chmod -R 700 /var/run/sonarqube /var/backup/sonarqube /var/tmp/sonarqube
   sudo chown -R $(whoami):$(whoami) /var/run/sonarqube /var/backup/sonarqube /var/tmp/sonarqube
   ```

2. Lock file exists:

   ```bash
   sudo rm /var/run/sonarqube/sonarqube_upgrade.lock
   ```

3. Insufficient space:

   ```bash
   df -h /var/backup/sonarqube /var/tmp/sonarqube /opt
   ```

4. Plugin validation failures:

   ```bash
   # Check plugin permissions
   ls -l /opt/sonarqube/extensions/plugins/*.jar

   # Verify plugin integrity
   find /opt/sonarqube/extensions/plugins -type f -name "*.jar" -size -1024c
   ```

5. Environment check failures:

   ```bash
   # Check available space
   df -h /tmp /var/backup/sonarqube

   # Verify required commands
   which unzip systemctl pg_dump
   ```

## SSL Certificate Configuration

To properly handle SSL verification, configure the following:

1. Using a custom certificate:

   ```bash
   export SONARQUBE_CERT_PATH="/path/to/certificate.pem"
   export SONARQUBE_VERIFY_SSL="true"
   ```

2. Using system certificates:

   ```bash
   export SONARQUBE_VERIFY_SSL="true"
   ```

3. Disable SSL verification (not recommended for production):
   ```bash
   export SONARQUBE_VERIFY_SSL="false"
   ```

For proper security, always verify SSL certificates in production environments.
