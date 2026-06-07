CREATE TABLE IF NOT EXISTS assets (
    asset_id TEXT PRIMARY KEY,
    hostname TEXT,
    os_name TEXT,
    os_version TEXT,
    os_arch TEXT,
    os_id TEXT,
    version_id TEXT,
    description TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS inventory_scans (
    id SERIAL PRIMARY KEY,
    asset_id TEXT REFERENCES assets(asset_id),
    scan_time TIMESTAMPTZ NOT NULL,
    package_count INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS packages (
    id SERIAL PRIMARY KEY,
    name TEXT NOT NULL,
    version TEXT NOT NULL,
    arch TEXT,
    description TEXT,
    purl TEXT,
    UNIQUE(name, version, arch)
);

CREATE TABLE IF NOT EXISTS installed_packages (
    scan_id INTEGER REFERENCES inventory_scans(id) ON DELETE CASCADE,
    package_id INTEGER REFERENCES packages(id) ON DELETE CASCADE,
    PRIMARY KEY (scan_id, package_id)
);

CREATE TABLE IF NOT EXISTS vulnerability_scans (
    id SERIAL PRIMARY KEY,
    asset_id TEXT REFERENCES assets(asset_id),
    scan_time TIMESTAMPTZ NOT NULL,
    vulnerabilities_count INTEGER NOT NULL DEFAULT 0,
    critical_count INTEGER NOT NULL DEFAULT 0,
    high_count INTEGER NOT NULL DEFAULT 0,
    medium_count INTEGER NOT NULL DEFAULT 0,
    low_count INTEGER NOT NULL DEFAULT 0,
    unknown_count INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS vulnerabilities (
    id SERIAL PRIMARY KEY,
    osv_id TEXT UNIQUE,
    severity TEXT,
    summary TEXT,
    details TEXT,
    published TEXT,
    modified TEXT
);

CREATE TABLE IF NOT EXISTS package_vulnerabilities (
    scan_id INTEGER REFERENCES vulnerability_scans(id) ON DELETE CASCADE,
    package_name TEXT,
    package_version TEXT,
    vulnerability_id INTEGER REFERENCES vulnerabilities(id),
    PRIMARY KEY (scan_id, package_name, package_version, vulnerability_id)
);
