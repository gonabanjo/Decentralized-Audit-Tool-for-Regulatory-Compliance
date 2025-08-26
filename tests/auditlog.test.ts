import { describe, expect, it, vi, beforeEach } from "vitest";

// Interfaces for type safety
interface ClarityResponse<T> {
  ok: boolean;
  value: T | number; // number for error codes
}

interface AuditLog {
  timestamp: number;
  auditor: string;
  company: string;
  standardReference: string;
  documentHashes: Uint8Array[];
  metadata: string;
  status: string;
  version: number;
  approvedBy: string | null;
  expiry: number | null;
}

interface AuditVersion {
  timestamp: number;
  updater: string;
  changes: string;
  previousHashes: Uint8Array[];
}

interface Collaborator {
  role: string;
  permissions: string[];
  addedAt: number;
}

interface AccessLicense {
  expiry: number;
  terms: string;
  active: boolean;
}

interface Category {
  category: string;
  tags: string[];
}

interface ContractState {
  paused: boolean;
  auditCounter: number;
  admin: string;
  auditLogs: Map<number, AuditLog>;
  auditVersions: Map<string, AuditVersion>; // Key: `${auditId}-${version}`
  auditCollaborators: Map<string, Collaborator>; // Key: `${auditId}-${collaborator}`
  authorizedAuditors: Map<string, boolean>; // Key: `${company}-${auditor}`
  auditAccessLicenses: Map<string, AccessLicense>; // Key: `${auditId}-${licensee}`
  auditCategories: Map<number, Category>;
  blockHeight: number; // Mock block height
}

// Mock contract implementation
class AuditLogMock {
  private state: ContractState = {
    paused: false,
    auditCounter: 0,
    admin: "deployer",
    auditLogs: new Map(),
    auditVersions: new Map(),
    auditCollaborators: new Map(),
    authorizedAuditors: new Map(),
    auditAccessLicenses: new Map(),
    auditCategories: new Map(),
    blockHeight: 1000,
  };

  private MAX_METADATA_LEN = 1000;
  private MAX_DOCUMENTS = 10;
  private ERR_UNAUTHORIZED = 100;
  private ERR_INVALID_AUDIT_ID = 101;
  private ERR_AUDIT_EXISTS = 102;
  private ERR_INVALID_HASH = 103;
  private ERR_PAUSED = 104;
  private ERR_INVALID_STATUS = 105;
  private ERR_METADATA_TOO_LONG = 106;
  private ERR_TOO_MANY_DOCUMENTS = 107;
  private ERR_ALREADY_APPROVED = 108;
  private ERR_INVALID_VERSION = 109;
  private ERR_NO_PERMISSION = 110;

  // Helper to simulate buff
  public buff(str: string): Uint8Array {
    return new TextEncoder().encode(str);
  }

  // Simulate block-height increment
  private incrementBlockHeight() {
    this.state.blockHeight += 1;
  }

  setAdmin(caller: string, newAdmin: string): ClarityResponse<boolean> {
    if (caller !== this.state.admin) {
      return { ok: false, value: this.ERR_UNAUTHORIZED };
    }
    this.state.admin = newAdmin;
    return { ok: true, value: true };
  }

  pauseContract(caller: string): ClarityResponse<boolean> {
    if (caller !== this.state.admin) {
      return { ok: false, value: this.ERR_UNAUTHORIZED };
    }
    this.state.paused = true;
    return { ok: true, value: true };
  }

  unpauseContract(caller: string): ClarityResponse<boolean> {
    if (caller !== this.state.admin) {
      return { ok: false, value: this.ERR_UNAUTHORIZED };
    }
    this.state.paused = false;
    return { ok: true, value: true };
  }

  addAuthorizedAuditor(caller: string, company: string, auditor: string): ClarityResponse<boolean> {
    if (caller !== this.state.admin && caller !== company) {
      return { ok: false, value: this.ERR_UNAUTHORIZED };
    }
    const key = `${company}-${auditor}`;
    this.state.authorizedAuditors.set(key, true);
    return { ok: true, value: true };
  }

  removeAuthorizedAuditor(caller: string, company: string, auditor: string): ClarityResponse<boolean> {
    if (caller !== this.state.admin && caller !== company) {
      return { ok: false, value: this.ERR_UNAUTHORIZED };
    }
    const key = `${company}-${auditor}`;
    this.state.authorizedAuditors.delete(key);
    return { ok: true, value: true };
  }

  logAudit(
    caller: string,
    company: string,
    standardReference: string,
    documentHashes: Uint8Array[],
    metadata: string,
    expiry: number | null
  ): ClarityResponse<number> {
    if (this.state.paused) {
      return { ok: false, value: this.ERR_PAUSED };
    }
    const authKey = `${company}-${caller}`;
    if (!this.state.authorizedAuditors.get(authKey)) {
      return { ok: false, value: this.ERR_UNAUTHORIZED };
    }
    if (metadata.length > this.MAX_METADATA_LEN) {
      return { ok: false, value: this.ERR_METADATA_TOO_LONG };
    }
    if (documentHashes.length > this.MAX_DOCUMENTS) {
      return { ok: false, value: this.ERR_TOO_MANY_DOCUMENTS };
    }
    this.incrementBlockHeight();
    const auditId = ++this.state.auditCounter;
    this.state.auditLogs.set(auditId, {
      timestamp: this.state.blockHeight,
      auditor: caller,
      company,
      standardReference,
      documentHashes,
      metadata,
      status: "pending",
      version: 1,
      approvedBy: null,
      expiry,
    });
    return { ok: true, value: auditId };
  }

  updateAuditVersion(
    caller: string,
    auditId: number,
    changes: string,
    newDocumentHashes: Uint8Array[]
  ): ClarityResponse<number> {
    if (this.state.paused) {
      return { ok: false, value: this.ERR_PAUSED };
    }
    const audit = this.state.auditLogs.get(auditId);
    if (!audit) {
      return { ok: false, value: this.ERR_INVALID_AUDIT_ID };
    }
    const collabKey = `${auditId}-${caller}`;
    const collab = this.state.auditCollaborators.get(collabKey);
    const hasUpdatePerm = collab?.permissions.includes("update") ?? false;
    if (audit.auditor !== caller && !hasUpdatePerm) {
      return { ok: false, value: this.ERR_NO_PERMISSION };
    }
    this.incrementBlockHeight();
    const newVersion = audit.version + 1;
    const versionKey = `${auditId}-${newVersion}`;
    this.state.auditVersions.set(versionKey, {
      timestamp: this.state.blockHeight,
      updater: caller,
      changes,
      previousHashes: audit.documentHashes,
    });
    audit.version = newVersion;
    audit.documentHashes = newDocumentHashes;
    audit.status = "updated";
    this.state.auditLogs.set(auditId, audit);
    return { ok: true, value: newVersion };
  }

  approveAudit(caller: string, auditId: number, approver: string): ClarityResponse<boolean> {
    if (this.state.paused) {
      return { ok: false, value: this.ERR_PAUSED };
    }
    const audit = this.state.auditLogs.get(auditId);
    if (!audit) {
      return { ok: false, value: this.ERR_INVALID_AUDIT_ID };
    }
    if (audit.approvedBy !== null) {
      return { ok: false, value: this.ERR_ALREADY_APPROVED };
    }
    if (caller !== this.state.admin) {
      return { ok: false, value: this.ERR_UNAUTHORIZED };
    }
    audit.status = "approved";
    audit.approvedBy = approver;
    this.state.auditLogs.set(auditId, audit);
    return { ok: true, value: true };
  }

  updateAuditStatus(caller: string, auditId: number, newStatus: string): ClarityResponse<boolean> {
    if (this.state.paused) {
      return { ok: false, value: this.ERR_PAUSED };
    }
    const audit = this.state.auditLogs.get(auditId);
    if (!audit) {
      return { ok: false, value: this.ERR_INVALID_AUDIT_ID };
    }
    const collabKey = `${auditId}-${caller}`;
    const collab = this.state.auditCollaborators.get(collabKey);
    const hasStatusPerm = collab?.permissions.includes("update-status") ?? false;
    if (audit.auditor !== caller && !hasStatusPerm) {
      return { ok: false, value: this.ERR_NO_PERMISSION };
    }
    audit.status = newStatus;
    this.state.auditLogs.set(auditId, audit);
    return { ok: true, value: true };
  }

  addCollaborator(
    caller: string,
    auditId: number,
    collaborator: string,
    role: string,
    permissions: string[]
  ): ClarityResponse<boolean> {
    const audit = this.state.auditLogs.get(auditId);
    if (!audit) {
      return { ok: false, value: this.ERR_INVALID_AUDIT_ID };
    }
    if (audit.auditor !== caller) {
      return { ok: false, value: this.ERR_UNAUTHORIZED };
    }
    const key = `${auditId}-${collaborator}`;
    this.state.auditCollaborators.set(key, { role, permissions, addedAt: this.state.blockHeight });
    return { ok: true, value: true };
  }

  grantAccessLicense(
    caller: string,
    auditId: number,
    licensee: string,
    duration: number,
    terms: string
  ): ClarityResponse<boolean> {
    const audit = this.state.auditLogs.get(auditId);
    if (!audit) {
      return { ok: false, value: this.ERR_INVALID_AUDIT_ID };
    }
    if (audit.company !== caller) {
      return { ok: false, value: this.ERR_UNAUTHORIZED };
    }
    const key = `${auditId}-${licensee}`;
    this.state.auditAccessLicenses.set(key, {
      expiry: this.state.blockHeight + duration,
      terms,
      active: true,
    });
    return { ok: true, value: true };
  }

  addAuditCategory(
    caller: string,
    auditId: number,
    category: string,
    tags: string[]
  ): ClarityResponse<boolean> {
    const audit = this.state.auditLogs.get(auditId);
    if (!audit) {
      return { ok: false, value: this.ERR_INVALID_AUDIT_ID };
    }
    if (audit.auditor !== caller) {
      return { ok: false, value: this.ERR_UNAUTHORIZED };
    }
    this.state.auditCategories.set(auditId, { category, tags });
    return { ok: true, value: true };
  }

  getAuditDetails(auditId: number): ClarityResponse<AuditLog | null> {
    return { ok: true, value: this.state.auditLogs.get(auditId) ?? null };
  }

  getAuditVersion(auditId: number, version: number): ClarityResponse<AuditVersion | null> {
    const key = `${auditId}-${version}`;
    return { ok: true, value: this.state.auditVersions.get(key) ?? null };
  }

  verifyAuditHash(auditId: number, hash: Uint8Array): ClarityResponse<boolean> {
    const audit = this.state.auditLogs.get(auditId);
    if (!audit) {
      return { ok: false, value: this.ERR_INVALID_AUDIT_ID };
    }
    const found = audit.documentHashes.some((h) => h.every((byte, i) => byte === hash[i]));
    return { ok: true, value: found };
  }

  hasAccess(auditId: number, caller: string): ClarityResponse<boolean> {
    const key = `${auditId}-${caller}`;
    const license = this.state.auditAccessLicenses.get(key);
    if (!license) {
      return { ok: true, value: false };
    }
    return { ok: true, value: license.active && this.state.blockHeight < license.expiry };
  }

  getAuditCollaborator(auditId: number, collaborator: string): ClarityResponse<Collaborator | null> {
    const key = `${auditId}-${collaborator}`;
    return { ok: true, value: this.state.auditCollaborators.get(key) ?? null };
  }

  getAuditCategory(auditId: number): ClarityResponse<Category | null> {
    return { ok: true, value: this.state.auditCategories.get(auditId) ?? null };
  }

  isContractPaused(): ClarityResponse<boolean> {
    return { ok: true, value: this.state.paused };
  }

  getAuditCounter(): ClarityResponse<number> {
    return { ok: true, value: this.state.auditCounter };
  }
}

// Test setup
const accounts = {
  deployer: "deployer",
  company: "company_1",
  auditor: "auditor_1",
  regulator: "regulator_1",
  collaborator: "collaborator_1",
  licensee: "licensee_1",
};

describe("AuditLog Contract", () => {
  let contract: AuditLogMock;

  beforeEach(() => {
    contract = new AuditLogMock();
    vi.resetAllMocks();
  });

  it("should initialize with correct defaults", () => {
    expect(contract.isContractPaused()).toEqual({ ok: true, value: false });
    expect(contract.getAuditCounter()).toEqual({ ok: true, value: 0 });
  });

  it("should allow admin to add authorized auditor", () => {
    const result = contract.addAuthorizedAuditor(accounts.deployer, accounts.company, accounts.auditor);
    expect(result).toEqual({ ok: true, value: true });
  });

  it("should prevent non-admin/non-company from adding auditor", () => {
    const result = contract.addAuthorizedAuditor(accounts.collaborator, accounts.company, accounts.auditor);
    expect(result).toEqual({ ok: false, value: 100 });
  });

  it("should allow authorized auditor to log audit", () => {
    contract.addAuthorizedAuditor(accounts.deployer, accounts.company, accounts.auditor);
    const hashes = [contract.buff("hash1"), contract.buff("hash2")];
    const result = contract.logAudit(
      accounts.auditor,
      accounts.company,
      "FDA-21CFR",
      hashes,
      "Audit metadata",
      10000
    );
    expect(result).toEqual({ ok: true, value: 1 });
    const details = contract.getAuditDetails(1);
    expect(details).toEqual({
      ok: true,
      value: expect.objectContaining({
        auditor: accounts.auditor,
        company: accounts.company,
        status: "pending",
        version: 1,
      }),
    });
  });

  it("should prevent unauthorized from logging audit", () => {
    const hashes = [contract.buff("hash1")];
    const result = contract.logAudit(
      accounts.auditor,
      accounts.company,
      "FDA-21CFR",
      hashes,
      "Unauthorized",
      null
    );
    expect(result).toEqual({ ok: false, value: 100 });
  });

  it("should reject metadata too long", () => {
    contract.addAuthorizedAuditor(accounts.deployer, accounts.company, accounts.auditor);
    const hashes = [contract.buff("hash1")];
    const longMetadata = "a".repeat(1001);
    const result = contract.logAudit(
      accounts.auditor,
      accounts.company,
      "FDA-21CFR",
      hashes,
      longMetadata,
      null
    );
    expect(result).toEqual({ ok: false, value: 106 });
  });

  it("should reject too many documents", () => {
    contract.addAuthorizedAuditor(accounts.deployer, accounts.company, accounts.auditor);
    const hashes = Array(11).fill(contract.buff("hash"));
    const result = contract.logAudit(
      accounts.auditor,
      accounts.company,
      "FDA-21CFR",
      hashes,
      "Too many",
      null
    );
    expect(result).toEqual({ ok: false, value: 107 });
  });

  it("should allow auditor to update version", () => {
    contract.addAuthorizedAuditor(accounts.deployer, accounts.company, accounts.auditor);
    const hashes = [contract.buff("hash1")];
    contract.logAudit(accounts.auditor, accounts.company, "FDA-21CFR", hashes, "Initial", null);
    const newHashes = [contract.buff("newhash")];
    const result = contract.updateAuditVersion(accounts.auditor, 1, "Changes made", newHashes);
    expect(result).toEqual({ ok: true, value: 2 });
    const version = contract.getAuditVersion(1, 2);
    expect(version).toEqual({
      ok: true,
      value: expect.objectContaining({ changes: "Changes made" }),
    });
    const details = contract.getAuditDetails(1);
    expect(details).toEqual({
      ok: true,
      value: expect.objectContaining({ version: 2, status: "updated" }),
    });
  });

  it("should prevent unauthorized from updating version", () => {
    contract.addAuthorizedAuditor(accounts.deployer, accounts.company, accounts.auditor);
    const hashes = [contract.buff("hash1")];
    contract.logAudit(accounts.auditor, accounts.company, "FDA-21CFR", hashes, "Initial", null);
    const newHashes = [contract.buff("newhash")];
    const result = contract.updateAuditVersion(accounts.collaborator, 1, "Unauthorized", newHashes);
    expect(result).toEqual({ ok: false, value: 110 });
  });

  it("should allow admin to approve audit", () => {
    contract.addAuthorizedAuditor(accounts.deployer, accounts.company, accounts.auditor);
    const hashes = [contract.buff("hash1")];
    contract.logAudit(accounts.auditor, accounts.company, "FDA-21CFR", hashes, "To approve", null);
    const result = contract.approveAudit(accounts.deployer, 1, accounts.regulator);
    expect(result).toEqual({ ok: true, value: true });
    const details = contract.getAuditDetails(1);
    expect(details).toEqual({
      ok: true,
      value: expect.objectContaining({ status: "approved", approvedBy: accounts.regulator }),
    });
  });

  it("should prevent double approval", () => {
    contract.addAuthorizedAuditor(accounts.deployer, accounts.company, accounts.auditor);
    const hashes = [contract.buff("hash1")];
    contract.logAudit(accounts.auditor, accounts.company, "FDA-21CFR", hashes, "Approved", null);
    contract.approveAudit(accounts.deployer, 1, accounts.regulator);
    const result = contract.approveAudit(accounts.deployer, 1, accounts.regulator);
    expect(result).toEqual({ ok: false, value: 108 });
  });

  it("should allow adding collaborator", () => {
    contract.addAuthorizedAuditor(accounts.deployer, accounts.company, accounts.auditor);
    const hashes = [contract.buff("hash1")];
    contract.logAudit(accounts.auditor, accounts.company, "FDA-21CFR", hashes, "Collab", null);
    const result = contract.addCollaborator(
      accounts.auditor,
      1,
      accounts.collaborator,
      "reviewer",
      ["update", "update-status"]
    );
    expect(result).toEqual({ ok: true, value: true });
    const collab = contract.getAuditCollaborator(1, accounts.collaborator);
    expect(collab).toEqual({
      ok: true,
      value: expect.objectContaining({ role: "reviewer" }),
    });
  });

  it("should allow collaborator with permission to update status", () => {
    contract.addAuthorizedAuditor(accounts.deployer, accounts.company, accounts.auditor);
    const hashes = [contract.buff("hash1")];
    contract.logAudit(accounts.auditor, accounts.company, "FDA-21CFR", hashes, "Status", null);
    contract.addCollaborator(
      accounts.auditor,
      1,
      accounts.collaborator,
      "editor",
      ["update-status"]
    );
    const result = contract.updateAuditStatus(accounts.collaborator, 1, "reviewed");
    expect(result).toEqual({ ok: true, value: true });
    const details = contract.getAuditDetails(1);
    expect(details).toEqual({
      ok: true,
      value: expect.objectContaining({ status: "reviewed" }),
    });
  });

  it("should grant access license", () => {
    contract.addAuthorizedAuditor(accounts.deployer, accounts.company, accounts.auditor);
    const hashes = [contract.buff("hash1")];
    contract.logAudit(accounts.auditor, accounts.company, "FDA-21CFR", hashes, "License", null);
    const result = contract.grantAccessLicense(
      accounts.company,
      1,
      accounts.licensee,
      100,
      "View only"
    );
    expect(result).toEqual({ ok: true, value: true });
    const access = contract.hasAccess(1, accounts.licensee);
    expect(access).toEqual({ ok: true, value: true });
  });

  it("should add audit category", () => {
    contract.addAuthorizedAuditor(accounts.deployer, accounts.company, accounts.auditor);
    const hashes = [contract.buff("hash1")];
    contract.logAudit(accounts.auditor, accounts.company, "FDA-21CFR", hashes, "Category", null);
    const result = contract.addAuditCategory(
      accounts.auditor,
      1,
      "manufacturing",
      ["GMP", "FDA"]
    );
    expect(result).toEqual({ ok: true, value: true });
    const cat = contract.getAuditCategory(1);
    expect(cat).toEqual({
      ok: true,
      value: expect.objectContaining({ category: "manufacturing" }),
    });
  });

  it("should verify audit hash", () => {
    contract.addAuthorizedAuditor(accounts.deployer, accounts.company, accounts.auditor);
    const hash1 = contract.buff("hash1");
    const hashes = [hash1, contract.buff("hash2")];
    contract.logAudit(accounts.auditor, accounts.company, "FDA-21CFR", hashes, "Verify", null);
    const result = contract.verifyAuditHash(1, hash1);
    expect(result).toEqual({ ok: true, value: true });
    const wrongHash = contract.buff("wrong");
    const wrongResult = contract.verifyAuditHash(1, wrongHash);
    expect(wrongResult).toEqual({ ok: true, value: false });
  });

  it("should pause and prevent operations", () => {
    const pauseResult = contract.pauseContract(accounts.deployer);
    expect(pauseResult).toEqual({ ok: true, value: true });
    expect(contract.isContractPaused()).toEqual({ ok: true, value: true });

    const hashes = [contract.buff("hash1")];
    const logDuringPause = contract.logAudit(
      accounts.auditor,
      accounts.company,
      "FDA-21CFR",
      hashes,
      "Paused",
      null
    );
    expect(logDuringPause).toEqual({ ok: false, value: 104 });

    const unpauseResult = contract.unpauseContract(accounts.deployer);
    expect(unpauseResult).toEqual({ ok: true, value: true });
    expect(contract.isContractPaused()).toEqual({ ok: true, value: false });
  });
});