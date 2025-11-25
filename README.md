# Databricks Data Privacy Notebooks

This repository contains Databricks notebooks demonstrating data privacy and security features available in Unity Catalog.

## Contents

### Data Privacy Demonstrations

The `notebooks/data-privacy/` directory contains comprehensive demonstrations of:

1. **Role-Based Access Control (RBAC)** - Grant permissions based on user roles
2. **Views** - Dynamic, Restricted, and Materialized views for controlled data access
3. **Data Hashing** - Irreversible masking using hash functions
4. **Data Masking** - Format-preserving obfuscation of sensitive data
5. **Row-Level Filtering** - Scope data access by user attributes or regions
6. **Data Tokenization** - Reversible token replacement for PII
7. **Attribute-Based Access Control (ABAC)** - Policy-driven access using metadata tags
8. **Data Encryption** - Protect data at rest and in transit

### Files

- `notebooks/data-privacy/data_privacy.ipynb` - Main demonstration notebook
- `notebooks/data-privacy/setup_environment.ipynb` - Environment setup (called automatically)
- `notebooks/data-privacy/data_encryption.ipynb` - Detailed encryption examples
- `notebooks/data-privacy/utilities.py` - Helper functions for privacy operations

## Getting Started

### Prerequisites

- Databricks workspace with Unity Catalog enabled
- Appropriate permissions to create schemas, tables, and functions
- Python 3.8+ (for local development)

### Running the Notebooks

1. Import the notebooks into your Databricks workspace
2. Attach to a cluster (Serverless recommended for fine-grained access controls)
3. Configure your preferences in the Configuration cell:
   - `USE_TEMP_TABLES = True` (recommended for demos - auto-cleanup)
   - `USE_TEMP_TABLES = False` (for persistent environments)
4. Run the cells sequentially to see each privacy feature demonstrated

### Setup

The notebooks automatically create:
- Sample schemas (hr, customers, retail, governance) - only if using permanent tables
- Sample tables with test data (temporary or permanent based on config)
- User-defined functions for masking, filtering, and tokenization
- Views demonstrating various privacy techniques

**Key Features:**
- **Temporary Tables Mode** - No manual cleanup required (default)
- **Modular Setup** - Environment setup in separate notebook, called via `%run`
- **Clean Demo Experience** - Setup code hidden from main demonstrations
- **Environment Agnostic** - Clear placeholders for group names and configurations

## Key Features

### Defense in Depth
Combine multiple privacy techniques for comprehensive data protection.

### Unity Catalog Integration
All privacy controls are managed through Unity Catalog for centralized governance.

### Audit & Compliance
All access controls are logged and auditable for regulatory compliance.

## Documentation

- [Unity Catalog Documentation](https://docs.databricks.com/en/data-governance/unity-catalog/index.html)
- [Row and Column Filters](https://docs.databricks.com/en/security/privacy/row-and-column-filters.html)
- [ABAC Documentation](https://docs.databricks.com/en/security/attribute-based-access-control.html)
- [Data Encryption in Databricks](https://docs.databricks.com/en/security/encryption/index.html)

## Support

For questions or issues, please refer to the [Databricks Documentation](https://docs.databricks.com) or contact your Databricks representative.

## License

Copyright © Databricks. All rights reserved.

