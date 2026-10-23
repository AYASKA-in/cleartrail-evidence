
CREATE TABLE ct_schema (
	version INTEGER NOT NULL, 
	PRIMARY KEY (version)
)

;

CREATE TABLE ct_tenants (
	id VARCHAR(36) NOT NULL, 
	name VARCHAR(200) NOT NULL, 
	config TEXT NOT NULL, 
	aws_external_id VARCHAR(43) NOT NULL, 
	created_at BIGINT NOT NULL, 
	PRIMARY KEY (id), 
	UNIQUE (aws_external_id)
)

;

CREATE TABLE ct_audit (
	tenant_id VARCHAR(36) NOT NULL, 
	sequence INTEGER NOT NULL, 
	event TEXT NOT NULL, 
	previous_hash VARCHAR(64) NOT NULL, 
	event_hash VARCHAR(64) NOT NULL, 
	PRIMARY KEY (tenant_id, sequence), 
	FOREIGN KEY(tenant_id) REFERENCES ct_tenants (id)
)

;

CREATE TABLE ct_credentials (
	tenant_id VARCHAR(36) NOT NULL, 
	provider VARCHAR(16) NOT NULL, 
	envelope TEXT NOT NULL, 
	updated_at BIGINT NOT NULL, 
	PRIMARY KEY (tenant_id, provider), 
	FOREIGN KEY(tenant_id) REFERENCES ct_tenants (id)
)

;

CREATE TABLE ct_members (
	tenant_id VARCHAR(36) NOT NULL, 
	issuer VARCHAR(512) NOT NULL, 
	subject VARCHAR(255) NOT NULL, 
	role VARCHAR(16) NOT NULL, 
	PRIMARY KEY (tenant_id, issuer, subject), 
	CHECK (role IN ('admin', 'operator', 'auditor')), 
	FOREIGN KEY(tenant_id) REFERENCES ct_tenants (id)
)

;

CREATE TABLE ct_notes (
	tenant_id VARCHAR(36) NOT NULL, 
	control_id VARCHAR(40) NOT NULL, 
	document TEXT NOT NULL, 
	PRIMARY KEY (tenant_id, control_id), 
	FOREIGN KEY(tenant_id) REFERENCES ct_tenants (id)
)

;

CREATE TABLE ct_revisions (
	tenant_id VARCHAR(36) NOT NULL, 
	id VARCHAR(36) NOT NULL, 
	document TEXT NOT NULL, 
	PRIMARY KEY (tenant_id, id), 
	FOREIGN KEY(tenant_id) REFERENCES ct_tenants (id)
)

;

CREATE TABLE ct_runs (
	tenant_id VARCHAR(36) NOT NULL, 
	id VARCHAR(40) NOT NULL, 
	collected_at VARCHAR(40) NOT NULL, 
	document TEXT NOT NULL, 
	sha256 VARCHAR(64) NOT NULL, 
	summary TEXT NOT NULL, 
	PRIMARY KEY (tenant_id, id), 
	FOREIGN KEY(tenant_id) REFERENCES ct_tenants (id)
)

;

CREATE TABLE ct_sessions (
	token_hash VARCHAR(64) NOT NULL, 
	issuer VARCHAR(512) NOT NULL, 
	subject VARCHAR(255) NOT NULL, 
	active_tenant VARCHAR(36) NOT NULL, 
	csrf VARCHAR(43) NOT NULL, 
	expires_at BIGINT NOT NULL, 
	PRIMARY KEY (token_hash), 
	FOREIGN KEY(active_tenant) REFERENCES ct_tenants (id)
)

;
CREATE INDEX ct_session_expiry ON ct_sessions (expires_at);

CREATE TABLE ct_jobs (
	tenant_id VARCHAR(36) NOT NULL, 
	id VARCHAR(36) NOT NULL, 
	status VARCHAR(16) NOT NULL, 
	created_at BIGINT NOT NULL, 
	finished_at BIGINT, 
	lease_until BIGINT, 
	lease_token VARCHAR(64), 
	config TEXT NOT NULL, 
	attestations TEXT NOT NULL, 
	run_id VARCHAR(40), 
	error VARCHAR(64), 
	PRIMARY KEY (tenant_id, id), 
	CHECK (status IN ('queued', 'running', 'succeeded', 'failed')), 
	FOREIGN KEY(tenant_id, run_id) REFERENCES ct_runs (tenant_id, id), 
	FOREIGN KEY(tenant_id) REFERENCES ct_tenants (id)
)

;
CREATE INDEX ct_job_queue ON ct_jobs (status, created_at);
CREATE UNIQUE INDEX ct_one_active_job ON ct_jobs (tenant_id) WHERE status IN ('queued', 'running');
