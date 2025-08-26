;; AuditLog Smart Contract
;; This contract serves as the core for recording tamper-proof audit logs for regulatory compliance in the pharmaceutical industry.
;; It supports international drug standards, ensuring immutable timestamps, document hashes, and metadata.
;; Features include role-based access, audit versioning, multi-document support, status tracking, and collaborator management.

;; Constants
(define-constant ERR_UNAUTHORIZED (err u100))
(define-constant ERR_INVALID_AUDIT_ID (err u101))
(define-constant ERR_AUDIT_EXISTS (err u102))
(define-constant ERR_INVALID_HASH (err u103))
(define-constant ERR_PAUSED (err u104))
(define-constant ERR_INVALID_STATUS (err u105))
(define-constant ERR_METADATA_TOO_LONG (err u106))
(define-constant ERR_TOO_MANY_DOCUMENTS (err u107))
(define-constant ERR_ALREADY_APPROVED (err u108))
(define-constant ERR_INVALID_VERSION (err u109))
(define-constant ERR_NO_PERMISSION (err u110))
(define-constant MAX_METADATA_LEN u1000)
(define-constant MAX_DOCUMENTS u10)
(define-constant CONTRACT_OWNER tx-sender)

;; Data Variables
(define-data-var contract-paused bool false)
(define-data-var audit-counter uint u0)
(define-data-var admin principal tx-sender)

;; Data Maps
(define-map audit-logs
  { audit-id: uint }
  {
    timestamp: uint,
    auditor: principal,
    company: principal,
    standard-reference: (string-ascii 50),  ;; e.g., "FDA-21CFR", linked to StandardRegistry
    document-hashes: (list 10 (buff 32)),  ;; Multiple document hashes for evidence
    metadata: (string-utf8 1000),
    status: (string-ascii 20),  ;; e.g., "pending", "approved", "rejected"
    version: uint,
    approved-by: (optional principal),  ;; Regulator approval
    expiry: (optional uint)  ;; Optional validity period
  }
)

(define-map audit-versions
  { audit-id: uint, version: uint }
  {
    timestamp: uint,
    updater: principal,
    changes: (string-utf8 500),
    previous-hashes: (list 10 (buff 32))
  }
)

(define-map audit-collaborators
  { audit-id: uint, collaborator: principal }
  {
    role: (string-ascii 50),  ;; e.g., "reviewer", "contributor"
    permissions: (list 5 (string-ascii 20)),  ;; e.g., "update", "approve"
    added-at: uint
  }
)

(define-map authorized-auditors
  { company: principal, auditor: principal }
  bool
)

(define-map audit-access-licenses
  { audit-id: uint, licensee: principal }
  {
    expiry: uint,
    terms: (string-utf8 200),
    active: bool
  }
)

(define-map audit-categories
  { audit-id: uint }
  {
    category: (string-ascii 50),  ;; e.g., "manufacturing", "clinical-trials"
    tags: (list 10 (string-ascii 20))
  }
)

;; Private Functions
(define-private (is-admin (caller principal))
  (is-eq caller (var-get admin))
)

(define-private (is-authorized-auditor (company principal) (auditor principal))
  (default-to false (map-get? authorized-auditors { company: company, auditor: auditor }))
)

(define-private (has-permission (audit-id uint) (caller principal) (permission (string-ascii 20)))
  (let ((collab (map-get? audit-collaborators { audit-id: audit-id, collaborator: caller })))
    (if (is-some collab)
      (is-some (index-of? (get permissions (unwrap-panic collab)) permission))
      false
    )
  )
)

(define-private (increment-audit-counter)
  (let ((current (var-get audit-counter)))
    (var-set audit-counter (+ current u1))
    (+ current u1)
  )
)

;; Public Functions

;; Admin Functions
(define-public (set-admin (new-admin principal))
  (if (is-admin tx-sender)
    (begin
      (var-set admin new-admin)
      (ok true)
    )
    ERR_UNAUTHORIZED
  )
)

(define-public (pause-contract)
  (if (is-admin tx-sender)
    (begin
      (var-set contract-paused true)
      (ok true)
    )
    ERR_UNAUTHORIZED
  )
)

(define-public (unpause-contract)
  (if (is-admin tx-sender)
    (begin
      (var-set contract-paused false)
      (ok true)
    )
    ERR_UNAUTHORIZED
  )
)

(define-public (add-authorized-auditor (company principal) (auditor principal))
  (if (or (is-admin tx-sender) (is-eq tx-sender company))
    (begin
      (map-set authorized-auditors { company: company, auditor: auditor } true)
      (ok true)
    )
    ERR_UNAUTHORIZED
  )
)

(define-public (remove-authorized-auditor (company principal) (auditor principal))
  (if (or (is-admin tx-sender) (is-eq tx-sender company))
    (begin
      (map-delete authorized-auditors { company: company, auditor: auditor })
      (ok true)
    )
    ERR_UNAUTHORIZED
  )
)

;; Audit Logging
(define-public (log-audit 
  (company principal)
  (standard-reference (string-ascii 50))
  (document-hashes (list 10 (buff 32)))
  (metadata (string-utf8 1000))
  (expiry (optional uint))
  )
  (if (var-get contract-paused)
    ERR_PAUSED
    (if (is-authorized-auditor company tx-sender)
      (if (> (len metadata) MAX_METADATA_LEN)
        ERR_METADATA_TOO_LONG
        (if (> (len document-hashes) MAX_DOCUMENTS)
          ERR_TOO_MANY_DOCUMENTS
          (let ((audit-id (increment-audit-counter)))
            (map-set audit-logs
              { audit-id: audit-id }
              {
                timestamp: block-height,
                auditor: tx-sender,
                company: company,
                standard-reference: standard-reference,
                document-hashes: document-hashes,
                metadata: metadata,
                status: "pending",
                version: u1,
                approved-by: none,
                expiry: expiry
              }
            )
            (print { event: "audit-logged", audit-id: audit-id, company: company })
            (ok audit-id)
          )
        )
      )
      ERR_UNAUTHORIZED
    )
  )
)

;; Update Audit Version
(define-public (update-audit-version 
  (audit-id uint)
  (changes (string-utf8 500))
  (new-document-hashes (list 10 (buff 32)))
  )
  (match (map-get? audit-logs { audit-id: audit-id })
    audit
    (if (var-get contract-paused)
      ERR_PAUSED
      (if (or (is-eq (get auditor audit) tx-sender) (has-permission audit-id tx-sender "update"))
        (let ((new-version (+ (get version audit) u1)))
          (map-set audit-versions
            { audit-id: audit-id, version: new-version }
            {
              timestamp: block-height,
              updater: tx-sender,
              changes: changes,
              previous-hashes: (get document-hashes audit)
            }
          )
          (map-set audit-logs
            { audit-id: audit-id }
            (merge audit {
              version: new-version,
              document-hashes: new-document-hashes,
              status: "updated"
            })
          )
          (print { event: "audit-updated", audit-id: audit-id, version: new-version })
          (ok new-version)
        )
        ERR_NO_PERMISSION
      )
    )
    ERR_INVALID_AUDIT_ID
  )
)

;; Approve Audit (e.g., by regulator)
(define-public (approve-audit (audit-id uint) (approver principal))
  (match (map-get? audit-logs { audit-id: audit-id })
    audit
    (if (var-get contract-paused)
      ERR_PAUSED
      (if (is-none (get approved-by audit))
        (if (is-admin tx-sender)  ;; Assuming regulators are admins or extend roles
          (begin
            (map-set audit-logs
              { audit-id: audit-id }
              (merge audit {
                status: "approved",
                approved-by: (some approver)
              })
            )
            (print { event: "audit-approved", audit-id: audit-id, approver: approver })
            (ok true)
          )
          ERR_UNAUTHORIZED
        )
        ERR_ALREADY_APPROVED
      )
    )
    ERR_INVALID_AUDIT_ID
  )
)

;; Update Status
(define-public (update-audit-status (audit-id uint) (new-status (string-ascii 20)))
  (match (map-get? audit-logs { audit-id: audit-id })
    audit
    (if (var-get contract-paused)
      ERR_PAUSED
      (if (or (is-eq (get auditor audit) tx-sender) (has-permission audit-id tx-sender "update-status"))
        (begin
          (map-set audit-logs
            { audit-id: audit-id }
            (merge audit { status: new-status })
          )
          (ok true)
        )
        ERR_NO_PERMISSION
      )
    )
    ERR_INVALID_AUDIT_ID
  )
)

;; Add Collaborator
(define-public (add-collaborator 
  (audit-id uint)
  (collaborator principal)
  (role (string-ascii 50))
  (permissions (list 5 (string-ascii 20)))
  )
  (match (map-get? audit-logs { audit-id: audit-id })
    audit
    (if (is-eq (get auditor audit) tx-sender)
      (begin
        (map-set audit-collaborators
          { audit-id: audit-id, collaborator: collaborator }
          {
            role: role,
            permissions: permissions,
            added-at: block-height
          }
        )
        (ok true)
      )
      ERR_UNAUTHORIZED
    )
    ERR_INVALID_AUDIT_ID
  )
)

;; Grant Access License
(define-public (grant-access-license 
  (audit-id uint)
  (licensee principal)
  (duration uint)
  (terms (string-utf8 200))
  )
  (match (map-get? audit-logs { audit-id: audit-id })
    audit
    (if (is-eq (get company audit) tx-sender)
      (begin
        (map-set audit-access-licenses
          { audit-id: audit-id, licensee: licensee }
          {
            expiry: (+ block-height duration),
            terms: terms,
            active: true
          }
        )
        (ok true)
      )
      ERR_UNAUTHORIZED
    )
    ERR_INVALID_AUDIT_ID
  )
)

;; Add Category
(define-public (add-audit-category 
  (audit-id uint)
  (category (string-ascii 50))
  (tags (list 10 (string-ascii 20)))
  )
  (match (map-get? audit-logs { audit-id: audit-id })
    audit
    (if (is-eq (get auditor audit) tx-sender)
      (begin
        (map-set audit-categories
          { audit-id: audit-id }
          {
            category: category,
            tags: tags
          }
        )
        (ok true)
      )
      ERR_UNAUTHORIZED
    )
    ERR_INVALID_AUDIT_ID
  )
)

;; Read-Only Functions
(define-read-only (get-audit-details (audit-id uint))
  (map-get? audit-logs { audit-id: audit-id })
)

(define-read-only (get-audit-version (audit-id uint) (version uint))
  (map-get? audit-versions { audit-id: audit-id, version: version })
)

(define-read-only (verify-audit-hash (audit-id uint) (hash (buff 32)))
  (match (map-get? audit-logs { audit-id: audit-id })
    audit
    (ok (is-some (index-of? (get document-hashes audit) hash)))
    ERR_INVALID_AUDIT_ID
  )
)

(define-read-only (has-access (audit-id uint) (caller principal))
  (match (map-get? audit-access-licenses { audit-id: audit-id, licensee: caller })
    license
    (and (get active license) (< block-height (get expiry license)))
    false
  )
)

(define-read-only (get-audit-collaborator (audit-id uint) (collaborator principal))
  (map-get? audit-collaborators { audit-id: audit-id, collaborator: collaborator })
)

(define-read-only (get-audit-category (audit-id uint))
  (map-get? audit-categories { audit-id: audit-id })
)

(define-read-only (is-contract-paused)
  (var-get contract-paused)
)

(define-read-only (get-audit-counter)
  (var-get audit-counter)
)