# Integration Examples

This document provides complete examples of integrating `op-secret-manager` with various systems.

---

## **Systemd User Service with Podman Quadlet**

This example shows how to use `op-secret-manager` to inject secrets into a containerized application running via Podman quadlet.

### **Map File**

Create entries in `/etc/op-secret-manager/mapfile`:

```text
# Using relative paths (recommended) - expanded to /run/user/<uid>/secrets/
myuser   op://vault/myapp/db_password   db_password
myuser   op://vault/myapp/api_key       api_key
```

### **Quadlet File**

Create `~/.config/containers/systemd/myapp.container`:

```ini
[Unit]
Description=My Application Container
After=network-online.target
Wants=network-online.target

[Container]
Image=docker.io/myapp:latest
Network=pasta

# Mount secrets directory into container (read-only, with SELinux label)
Volume=/run/user/%U/secrets:/run/secrets:ro,Z

# Application reads secrets from environment variables pointing to files
Environment=DB_PASSWORD_FILE=/run/secrets/db_password
Environment=API_KEY_FILE=/run/secrets/api_key

# Fetch secrets before starting container
ExecStartPre=/usr/local/bin/op-secret-manager

# Clean up secrets after container stops
ExecStopPost=/usr/local/bin/op-secret-manager --cleanup

[Service]
# Container will auto-restart
Restart=always

[Install]
WantedBy=default.target
```

### **Secret Lifecycle**

1. `ExecStartPre` runs `op-secret-manager` to fetch secrets and write them to `/run/user/1001/secrets/`
2. Container starts with `/run/user/1001/secrets/` mounted as `/run/secrets/` (read-only)
3. Application reads `$DB_PASSWORD_FILE` and `$API_KEY_FILE` to get secret paths
4. When container stops, `ExecStopPost` runs `op-secret-manager --cleanup` to delete secret files

### **Enable and Start**

```bash
systemctl --user daemon-reload
systemctl --user enable --now myapp.container
```

---

## **System Service Example**

For system-level services running as specific users (e.g., `postgres`):

### **Map File**

```text
postgres   op://production/database/password   db_password
postgres   op://production/database/cert       db_cert.pem
```

### **Service File**

Create `/etc/systemd/system/postgres-secrets.service`:

```ini
[Unit]
Description=PostgreSQL Secrets from 1Password
Before=postgresql.service

[Service]
Type=oneshot
User=postgres
ExecStart=/usr/local/bin/op-secret-manager
RemainAfterExit=yes

[Install]
WantedBy=postgresql.service
```

Modify `/etc/systemd/system/postgresql.service` to require secrets:

```ini
[Unit]
Requires=postgres-secrets.service
After=postgres-secrets.service
```

---

## **Cron Job Example**

For scheduled tasks that need secrets:

```bash
#!/bin/bash
# /usr/local/bin/backup-with-secrets.sh

# Fetch secrets
/usr/local/bin/op-secret-manager

# Run backup using secrets
pg_dump -h localhost \
  --password-file=/run/user/$(id -u)/secrets/db_password \
  mydb > /backups/mydb-$(date +%Y%m%d).sql

# Cleanup
/usr/local/bin/op-secret-manager --cleanup
```

Add to crontab:

```cron
0 2 * * * /usr/local/bin/backup-with-secrets.sh
```

---

## **Docker Compose Integration**

While Podman quadlets are recommended for systemd integration, Docker Compose can also work:

### **Map File**

```text
myuser   op://vault/app/db_password     db_password
myuser   op://vault/app/api_key         api_key
```

### **Wrapper Script**

Create `docker-compose-with-secrets.sh`:

```bash
#!/bin/bash
set -e

# Fetch secrets
/usr/local/bin/op-secret-manager

# Start containers
docker-compose up -d

# Trap cleanup on exit
trap '/usr/local/bin/op-secret-manager --cleanup' EXIT
```

### **Docker Compose File**

```yaml
version: '3.8'
services:
  app:
    image: myapp:latest
    volumes:
      - /run/user/${UID}/secrets:/run/secrets:ro
    environment:
      - DB_PASSWORD_FILE=/run/secrets/db_password
      - API_KEY_FILE=/run/secrets/api_key
```

---

## **Root User Example**

For services that must run as root:

### **Map File** 

Owned by `root:op` with mode 640:

```text
# Root entries
root      op://infrastructure/ssl/cert        ssl_cert.pem
root      op://infrastructure/ssl/key         ssl_key.pem

# Non-root entries
postgres  op://production/database/password   db_password
```

### **Setup**

```bash
# Ensure binary is SUID+SGID to op
sudo chown op:op /usr/local/bin/op-secret-manager
sudo chmod 6755 /usr/local/bin/op-secret-manager

# Ensure mapfile is root:op with mode 640
sudo chown root:op /etc/op-secret-manager/mapfile
sudo chmod 640 /etc/op-secret-manager/mapfile

# Run as root
sudo /usr/local/bin/op-secret-manager
```

Root's secrets are written to `/run/user/0/secrets/`.
