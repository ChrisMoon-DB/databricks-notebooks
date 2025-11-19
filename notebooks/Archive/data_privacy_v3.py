# Databricks notebook source
# MAGIC %md
# MAGIC # Data Privacy and Security in Databricks
# MAGIC
# MAGIC This notebook demonstrates data privacy and security features in Databricks Unity Catalog.
# MAGIC
# MAGIC ## Topics:
# MAGIC 1. **RBAC** - Role-Based Access Control
# MAGIC 2. **Views** - Dynamic, Restricted, and Materialized
# MAGIC 3. **Data Hashing** - Irreversible anonymization
# MAGIC 4. **Data Masking** - Format-preserving obfuscation
# MAGIC 5. **Row Filtering** - Scope access by attributes
# MAGIC 6. **Tokenization** - Reversible token replacement
# MAGIC 7. **ABAC** - Attribute-Based Access Control
# MAGIC 8. **Encryption** - Protect data at rest and in transit

# COMMAND ----------

# MAGIC %md
# MAGIC ## Configuration
# MAGIC
# MAGIC Set your demo preferences:

# COMMAND ----------

# Demo Configuration - Using TEMPORARY objects only (auto-cleanup on session end)
print(f"✓ Configuration loaded")
print(f"  → Using TEMPORARY tables, views, and functions")
print(f"  → Auto-cleanup when session ends")

# COMMAND ----------

# Import required libraries
from pyspark.sql.functions import *
from pyspark.sql.types import *

print("✓ Libraries loaded")

# COMMAND ----------

# ============================================================================
# ENVIRONMENT SETUP
# ============================================================================

print("Setting up demo environment...")
print(f"→ Creating temporary tables and views")

# HR employee_info temp view
spark.sql("""
    CREATE OR REPLACE TEMP VIEW employee_info AS
    SELECT * FROM VALUES
        (1, 'David Wells', 100000.00, '123-45-6789'),
        (2, 'Chris Moon', 120000.00, '234-56-7890'),
        (3, 'Jane Doe', 95000.00, '345-67-8901'),
        (4, 'John Smith', 110000.00, '456-78-9012')
    AS t(id, name, salary, ssn)
""")

# Customers customer_info temp view
spark.sql("""
    CREATE OR REPLACE TEMP VIEW customer_info AS
    SELECT * FROM VALUES
        (1, 'david.wells@databricks.com', 'David Wells', '2025-01-01'),
        (2, 'chris.moon@databricks.com', 'Chris Moon', '2025-02-01'),
        (3, 'jane.doe@example.com', 'Jane Doe', '2025-03-15'),
        (4, 'john.smith@example.com', 'John Smith', '2025-04-20')
    AS t(id, email, name, created_at)
""")

# Retail customers temp view
spark.sql("""
    CREATE OR REPLACE TEMP VIEW customers AS
    SELECT * FROM VALUES
        (1, '123-45-6789', 'Alice Smith', 'US'),
        (2, '234-56-7890', 'Maria Silva', 'EU'),
        (3, '456-78-9012', 'Akira Tanaka', 'APAC'),
        (4, '567-89-0123', 'Bob Johnson', 'US'),
        (5, '678-90-1234', 'Emma Brown', 'EU')
    AS t(id, ssn, name, region)
""")

print("\n" + "="*60)
print("✓ Setup Complete!")
print("="*60)
print("→ All temporary tables created and populated")
print("→ Ready for demonstrations")

# COMMAND ----------

# MAGIC %md
# MAGIC ---
# MAGIC
# MAGIC ## 4. Data Masking
# MAGIC
# MAGIC **What is Data Masking?**
# MAGIC Replaces sensitive values with obfuscated versions while maintaining format and structure.
# MAGIC
# MAGIC **Use Cases:**
# MAGIC - Display masked SSNs (XXX-XX-6789) instead of raw values
# MAGIC - Preserve formats for analytics while hiding true values
# MAGIC - Automate masking by user/group with Unity Catalog
# MAGIC
# MAGIC **Key Functions:** `IS_ACCOUNT_GROUP_MEMBER()`, `IS_MEMBER()`, `mask()`
# MAGIC
# MAGIC **Important:** Fine-grained controls require serverless compute

# COMMAND ----------

# Create temporary masking function based on group membership
spark.sql("""CREATE OR REPLACE TEMPORARY FUNCTION mask_ssn(ssn STRING)
RETURNS STRING
RETURN CASE
    WHEN IS_ACCOUNT_GROUP_MEMBER('admin') THEN ssn
    ELSE '***-**-****'
END""")

# Create temporary view with masked SSN
spark.sql("""CREATE OR REPLACE TEMP VIEW v_customers_masked AS
SELECT id, mask_ssn(ssn) AS ssn, name, region
FROM customers""")

print("Original Data:")
display(spark.sql("SELECT * FROM customers LIMIT 3"))

print("\nMasked Data (SSN hidden based on permissions):")
display(spark.sql("SELECT * FROM v_customers_masked LIMIT 3"))

print("\n✓ SSN masked based on group membership")
print("✓ Admins see full SSN, others see masked")
print("✓ Format preserved for analytics")
print("\n⚠️  Update 'admin' to your admin group name")

# COMMAND ----------

# MAGIC %md
# MAGIC ---
# MAGIC
# MAGIC ## 5. Row-Level Filtering
# MAGIC
# MAGIC **What is Row Filtering?**
# MAGIC Controls which records users can view by applying row-level conditions, enforced transparently at query time.
# MAGIC
# MAGIC **Use Cases:**
# MAGIC - GDPR: Restrict EU data to EU employees only
# MAGIC - Multi-tenancy: Each customer sees only their data
# MAGIC - Financial segmentation: Business units see only their accounts
# MAGIC - Data sharing: Curated datasets for external partners
# MAGIC
# MAGIC **Benefits:** Transparent enforcement • Combines with column masks • No data duplication

# COMMAND ----------

# Create temporary row filter function based on region
spark.sql(f"""CREATE OR REPLACE TEMPORARY FUNCTION filter_by_region(region STRING)
RETURNS BOOLEAN
RETURN CASE
    -- Add the current user for demo purposes, in production you would use the groups as shown below.
    WHEN CURRENT_USER() = '{dbutils.notebook.entry_point.getDbutils().notebook().getContext().userName().get()}' AND region = 'US' THEN TRUE
    WHEN IS_MEMBER('Team_US') AND region = 'US' THEN TRUE
    WHEN IS_MEMBER('Team_EU') AND region = 'EU' THEN TRUE
    WHEN IS_MEMBER('Team_APAC') AND region = 'APAC' THEN TRUE
    WHEN IS_ACCOUNT_GROUP_MEMBER('admin') THEN TRUE
    ELSE FALSE
END""")

# Create temporary view with row filtering
spark.sql("""CREATE OR REPLACE TEMP VIEW v_customers_filtered AS
SELECT id, ssn, name, region
FROM customers
WHERE filter_by_region(region)""")

print("All Data (5 rows):")
display(spark.sql("SELECT * FROM customers ORDER BY id"))

print("\nFiltered Data (based on user's region):")
display(spark.sql("SELECT * FROM v_customers_filtered ORDER BY id"))

print("\n✓ Team_US: US records only")
print("✓ Team_EU: EU records only")
print("✓ Team_APAC: APAC records only")
print("✓ Admins: All records")
print("\n⚠️  Update Team_US, Team_EU, Team_APAC to your group names")

# COMMAND ----------

# MAGIC %md
# MAGIC ---
# MAGIC
# MAGIC ## 6. Data Tokenization
# MAGIC
# MAGIC **What is Tokenization?**
# MAGIC Substitutes sensitive values with random tokens that map back via secure vaults. Unlike hashing, tokenization is **reversible**.
# MAGIC
# MAGIC **Use Cases:**
# MAGIC - PCI-DSS: Replace credit cards with compliant tokens
# MAGIC - Testing: Provide realistic but protected test data
# MAGIC - Analytics: Enable analysis without exposing PII
# MAGIC - Fraud detection: Reversible for authorized investigation
# MAGIC
# MAGIC **Production Integration:** VGS, Basis Theory, TokenEx
# MAGIC
# MAGIC **Trade-offs:** ✓ Reversible • ⚠️ Requires external service • ⚠️ Performance overhead

# COMMAND ----------

# Create temporary tokenization functions
spark.sql("""CREATE OR REPLACE TEMPORARY FUNCTION tokenize(value STRING)
RETURNS STRING
RETURN CONCAT('TOK-', substr(sha2(value, 256), 1, 32))""")

spark.sql(f"""CREATE OR REPLACE TEMPORARY FUNCTION detokenize(token STRING, original STRING, region STRING)
RETURNS STRING
RETURN CASE
    WHEN CURRENT_USER() = '{dbutils.notebook.entry_point.getDbutils().notebook().getContext().userName().get()}' AND region = 'US' THEN original
    WHEN IS_ACCOUNT_GROUP_MEMBER('CAN_SEE')  THEN original
    ELSE token
END""")

# Create tokenized data as temporary view
spark.sql("""CREATE OR REPLACE TEMP VIEW customers_tokenized AS
SELECT id, tokenize(ssn) AS ssn_token, ssn AS ssn_original, name, region
FROM customers""")

# Create temporary view with conditional detokenization
spark.sql("""CREATE OR REPLACE TEMP VIEW v_customers_tokenized AS
SELECT id, detokenize(ssn_token, ssn_original, region) AS ssn, name, region
FROM customers_tokenized""")

print("Tokenized Storage:")
display(spark.sql("SELECT id, ssn_token, name, region FROM customers_tokenized LIMIT 3"))

print("\nConditional Detokenization:")
display(spark.sql("SELECT * FROM v_customers_tokenized LIMIT 3"))

print("\n✓ Non-admins see tokens only")
print("✓ Admins see original values")
print("\n🔗 Production: VGS • Basis Theory • TokenEx")

# COMMAND ----------

# MAGIC %md
# MAGIC ---
# MAGIC
# MAGIC ## 7. Attribute-Based Access Control (ABAC)
# MAGIC
# MAGIC **What is ABAC?**
# MAGIC Policy-driven access control based on object attributes (tags). Permissions set and enforced dynamically as data evolves.
# MAGIC
# MAGIC **Use Cases:**
# MAGIC - Auto-deny access to columns tagged 'sensitivity=PII'
# MAGIC - Monitor and protect credit card data automatically
# MAGIC - Apply policies to new tables/columns with matching tags
# MAGIC
# MAGIC **Key Features:** Tag-based policies • Dynamic enforcement • Centralized governance
# MAGIC
# MAGIC **Status:** Currently in **Beta** (October 2025)
# MAGIC
# MAGIC [ABAC Documentation](https://docs.databricks.com/security/attribute-based-access-control.html)

# COMMAND ----------

# ABAC Conceptual Workflow (requires Beta workspace configuration)

print("ABAC Workflow (Conceptual)")
print("="*70)

print("Step 1: Tag column as PII")
print("  ALTER TABLE hr.employee_info")
print("  ALTER COLUMN ssn SET TAGS ('sensitivity' = 'PII');\n")

print("Step 2: Create policy to mask PII")
print("  CREATE POLICY mask_pii ON SCHEMA hr")
print("  COLUMN MASK (ssn) USING '***-**-****'")
print("  TO all_accounts EXCEPT hr_admins;\n")

print("Step 3: Apply policy")
print("  ALTER TABLE hr.employee_info")
print("  ALTER COLUMN ssn SET MASK POLICY mask_pii;\n")

print("="*70)

# Simulate with temporary view
spark.sql("""CREATE OR REPLACE TEMP VIEW v_employee_info_abac AS
SELECT id, name, salary,
    CASE 
    WHEN CURRENT_USER() = '{dbutils.notebook.entry_point.getDbutils().notebook().getContext().userName().get()}' AND region = 'US' THEN original
    WHEN IS_ACCOUNT_GROUP_MEMBER('hr_admin') THEN ssn ELSE '***-**-****' END AS ssn
FROM employee_info""")

print("Simulated ABAC Behavior:")
display(spark.sql("SELECT * FROM v_employee_info_abac"))

print("\n✓ Policy auto-masks columns tagged as PII")
print("✓ Applies to all tables in schema")
print("✓ Exceptions for specific groups")

# COMMAND ----------

# MAGIC %md
# MAGIC ---
# MAGIC
# MAGIC ## 8. Data Encryption
# MAGIC
# MAGIC **What is Encryption?**
# MAGIC Protects data at rest and in transit by converting to encoded format readable only with decryption keys.
# MAGIC
# MAGIC **Databricks Encryption Options:**
# MAGIC
# MAGIC 1. **AES Functions** - Column-level encryption (`AES_ENCRYPT`, `AES_DECRYPT`)
# MAGIC 2. **Server-side** - Automatic cloud storage encryption (S3, Azure Blob, GCS)
# MAGIC 3. **Format-Preserving** - Encrypt while maintaining format
# MAGIC 4. **Envelope Encryption** - Multi-layer DEK/KEK approach
# MAGIC 5. **Multi-key Protection** - Customer + Databricks managed keys
# MAGIC
# MAGIC **See `data_encryption.ipynb` for detailed encryption demonstrations**

# COMMAND ----------

# AES-128 Encryption Demo
encryption_key = "MySecureKey12345"  # ⚠️ Use Azure Key Vault/AWS KMS/GCP KMS in production

# Create encrypted data as temporary view
spark.sql(f"""CREATE OR REPLACE TEMP VIEW employee_info_encrypted AS
SELECT id, name, salary, base64(aes_encrypt(ssn, '{encryption_key}', 'ECB', 'PKCS')) AS ssn_encrypted
FROM employee_info""")

print("Encrypted Data:")
display(spark.sql("SELECT * FROM employee_info_encrypted"))

# Create temporary view with conditional decryption
spark.sql(f"""CREATE OR REPLACE TEMP VIEW v_employee_info_decrypted AS
SELECT id, name, salary,
    CASE
        WHEN IS_ACCOUNT_GROUP_MEMBER('hr_admin')
        THEN aes_decrypt(unbase64(ssn_encrypted), '{encryption_key}', 'ECB', 'PKCS')
        ELSE '***-**-****'
    END AS ssn
FROM employee_info_encrypted""")

print("\nConditionally Decrypted:")
display(spark.sql("SELECT * FROM v_employee_info_decrypted"))

print("\n✓ HR admins see decrypted values")
print("✓ Others see masked values")
print("\n🔒 Best Practices:")
print("   • Use customer-managed keys (CMK)")
print("   • Rotate keys regularly")
print("   • Store keys in vault services (Key Vault, KMS)")
print("   • Enable TLS/SSL for data in transit")

# COMMAND ----------

# MAGIC %md
# MAGIC ---
# MAGIC
# MAGIC ## Summary: Privacy Features Comparison
# MAGIC
# MAGIC | Feature | Use Case | Reversible | Performance | Complexity |
# MAGIC |---------|----------|------------|-------------|------------|
# MAGIC | **RBAC** | Role-based permissions | N/A | Low | Low |
# MAGIC | **Views** | Controlled exposure | N/A | Low-Med | Low |
# MAGIC | **Hashing** | Anonymization | No | Low | Low |
# MAGIC | **Masking** | Format-preserving obfuscation | Optional | Low-Med | Medium |
# MAGIC | **Row Filtering** | Regional/attribute access | N/A | Medium | Medium |
# MAGIC | **Tokenization** | Reversible PII protection | Yes | Med-High | High |
# MAGIC | **ABAC** | Policy-driven control | N/A | Medium | Med-High |
# MAGIC | **Encryption** | At-rest/transit protection | Yes | Low-Med | Medium |
# MAGIC
# MAGIC ---
# MAGIC
# MAGIC ## Key Takeaways
# MAGIC
# MAGIC ✓ **Defense in Depth** - Combine techniques for comprehensive protection
# MAGIC ✓ **Unity Catalog** - Centralized governance for all privacy controls
# MAGIC ✓ **Serverless Compute** - Required for fine-grained controls
# MAGIC ✓ **Audit & Compliance** - All controls logged and auditable
# MAGIC ✓ **Performance** - Consider impact when implementing complex policies
# MAGIC
# MAGIC ---
# MAGIC
# MAGIC ## Resources
# MAGIC
# MAGIC - [Unity Catalog](https://docs.databricks.com/data-governance/unity-catalog/index.html)
# MAGIC - [Row & Column Filters](https://docs.databricks.com/security/privacy/row-and-column-filters.html)
# MAGIC - [ABAC](https://docs.databricks.com/security/attribute-based-access-control.html)
# MAGIC - [Encryption](https://docs.databricks.com/security/encryption/index.html)
# MAGIC
# MAGIC ---
# MAGIC
# MAGIC ## Environment Configuration Notes
# MAGIC
# MAGIC **Update these values for your Databricks environment:**
# MAGIC
# MAGIC **Group Names:**
# MAGIC - `admin` → Your admin group
# MAGIC - `hr_admin` / `hr_viewer_group` → Your HR groups
# MAGIC - `Team_US` / `Team_EU` / `Team_APAC` → Your regional groups
# MAGIC
# MAGIC **Encryption:**
# MAGIC - Replace hardcoded keys with Azure Key Vault / AWS KMS / GCP KMS references

# COMMAND ----------

# MAGIC %md
# MAGIC ---
# MAGIC
# MAGIC ## Cleanup
# MAGIC
# MAGIC **Note:** All tables, views, and functions in this notebook are temporary and will be automatically cleaned up when your Spark session ends.
# MAGIC
# MAGIC No manual cleanup is required! 🎉

# COMMAND ----------

print("✓ Using temporary tables, views, and functions")
print("✓ No manual cleanup needed!")
print("✓ All objects will be automatically removed when session ends")
