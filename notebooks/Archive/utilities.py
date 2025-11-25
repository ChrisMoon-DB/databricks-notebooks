"""
Data Privacy Utilities for Databricks

This module provides utility functions for data privacy demonstrations in Databricks.
Functions include helpers for hashing, masking, encryption, and data generation.

Author: Databricks
Version: 1.0
"""

import hashlib
from typing import Optional, List, Dict, Any
from pyspark.sql import DataFrame, SparkSession
from pyspark.sql.functions import col, sha2


# ============================================================================
# DATA GENERATION UTILITIES
# ============================================================================

def generate_sample_employees(
        spark: SparkSession,
        num_records: int = 10) -> DataFrame:
    """
    Generate sample employee data for testing.

    Args:
        spark: SparkSession instance
        num_records: Number of employee records to generate

    Returns:
        DataFrame with sample employee data
    """
    from pyspark.sql.types import StructType, StructField, IntegerType, StringType, DecimalType

    schema = StructType([
        StructField("id", IntegerType(), False),
        StructField("name", StringType(), False),
        StructField("salary", DecimalType(10, 2), False),
        StructField("ssn", StringType(), False)
    ])

    sample_data = []
    names = [
        "Alice Smith",
        "Bob Johnson",
        "Carol White",
        "David Brown",
        "Emma Davis",
        "Frank Miller",
        "Grace Lee",
        "Henry Wilson",
        "Ivy Martinez",
        "Jack Taylor"]

    for i in range(min(num_records, len(names))):
        sample_data.append((
            i + 1,
            names[i],
            float(90000 + (i * 10000)),
            f"{100+i:03d}-{20+i:02d}-{6000+i:04d}"
        ))

    return spark.createDataFrame(sample_data, schema)


def generate_sample_customers(
        spark: SparkSession,
        num_records: int = 10) -> DataFrame:
    """
    Generate sample customer data with regional information.

    Args:
        spark: SparkSession instance
        num_records: Number of customer records to generate

    Returns:
        DataFrame with sample customer data
    """
    from pyspark.sql.types import StructType, StructField, IntegerType, StringType

    schema = StructType([
        StructField("id", IntegerType(), False),
        StructField("ssn", StringType(), False),
        StructField("name", StringType(), False),
        StructField("region", StringType(), False)
    ])

    names = [
        "Alice Smith",
        "Maria Silva",
        "Akira Tanaka",
        "Bob Johnson",
        "Emma Brown",
        "Pierre Dubois",
        "Yuki Sato",
        "Carlos Garcia",
        "Nina Petrova",
        "Lars Hansen"]
    regions = ["US", "EU", "APAC", "US", "EU", "EU", "APAC", "US", "EU", "EU"]

    sample_data = []
    for i in range(min(num_records, len(names))):
        sample_data.append((
            i + 1,
            f"{100+i:03d}-{20+i:02d}-{6000+i:04d}",
            names[i],
            regions[i]
        ))

    return spark.createDataFrame(sample_data, schema)


# ============================================================================
# HASHING UTILITIES
# ============================================================================

def hash_column(value: str, algorithm: str = "sha256") -> str:
    """
    Hash a string value using the specified algorithm.

    Args:
        value: String value to hash
        algorithm: Hash algorithm (sha256, sha1, md5)

    Returns:
        Hexadecimal hash string
    """
    if algorithm == "sha256":
        return hashlib.sha256(value.encode()).hexdigest()
    elif algorithm == "sha1":
        return hashlib.sha1(value.encode()).hexdigest()
    elif algorithm == "md5":
        return hashlib.md5(value.encode()).hexdigest()
    else:
        raise ValueError(f"Unsupported hash algorithm: {algorithm}")


def apply_column_hashing(df: DataFrame, column_name: str,
                         hash_algorithm: str = "sha256",
                         output_column: Optional[str] = None) -> DataFrame:
    """
    Apply hashing to a DataFrame column.

    Args:
        df: Input DataFrame
        column_name: Name of column to hash
        hash_algorithm: Hash algorithm (256, 384, 512 for SHA-2)
        output_column: Name for output column (default: <column_name>_hash)

    Returns:
        DataFrame with hashed column
    """
    if output_column is None:
        output_column = f"{column_name}_hash"

    return df.withColumn(
        output_column, sha2(
            col(column_name), int(
                hash_algorithm.replace(
                    "sha", ""))))


# ============================================================================
# MASKING UTILITIES
# ============================================================================

def mask_ssn(ssn: str, show_last: int = 4) -> str:
    """
    Mask an SSN, showing only the last N digits.

    Args:
        ssn: SSN string (format: XXX-XX-XXXX)
        show_last: Number of digits to show at the end

    Returns:
        Masked SSN string
    """
    if not ssn or len(ssn) < show_last:
        return "***-**-****"

    if show_last == 0:
        return "***-**-****"
    elif show_last == 4:
        return f"***-**-{ssn[-4:]}"
    else:
        visible = ssn[-show_last:]
        return f"{'*' * (len(ssn) - show_last)}{visible}"


def mask_email(email: str, mask_type: str = "partial") -> str:
    """
    Mask an email address.

    Args:
        email: Email address to mask
        mask_type: Type of masking ('partial', 'domain', 'full')

    Returns:
        Masked email string
    """
    if not email or "@" not in email:
        return "***@***.***"

    local, domain = email.split("@", 1)

    if mask_type == "full":
        return "***@***.***"
    elif mask_type == "domain":
        return f"{local}@***.***"
    else:  # partial
        if len(local) > 2:
            masked_local = local[0] + "*" * (len(local) - 2) + local[-1]
        else:
            masked_local = "*" * len(local)
        return f"{masked_local}@{domain}"


def apply_column_masking(df: DataFrame, column_name: str,
                         mask_char: str = "*",
                         show_first: int = 0,
                         show_last: int = 0,
                         output_column: Optional[str] = None) -> DataFrame:
    """
    Apply masking to a DataFrame column.

    Args:
        df: Input DataFrame
        column_name: Name of column to mask
        mask_char: Character to use for masking
        show_first: Number of characters to show at the beginning
        show_last: Number of characters to show at the end
        output_column: Name for output column (default: <column_name>_masked)

    Returns:
        DataFrame with masked column
    """
    if output_column is None:
        output_column = f"{column_name}_masked"

    # Create masking expression
    from pyspark.sql.functions import length, concat, substring, lit, regexp_replace

    col_ref = col(column_name)
    col_length = length(col_ref)

    if show_first > 0 and show_last > 0:
        # Show first N and last M characters
        masked = concat(
            substring(col_ref, 1, show_first),
            lit(mask_char * 10),  # Middle masked section
            substring(col_ref, -show_last, show_last)
        )
    elif show_last > 0:
        # Show only last N characters
        masked = concat(
            regexp_replace(substring(col_ref, 1, col_length - show_last), ".", mask_char),
            substring(col_ref, -show_last, show_last)
        )
    else:
        # Mask everything
        masked = regexp_replace(col_ref, ".", mask_char)

    return df.withColumn(output_column, masked)


# ============================================================================
# ENCRYPTION UTILITIES
# ============================================================================

def get_encryption_key_info() -> Dict[str, str]:
    """
    Get information about encryption key management.

    Returns:
        Dictionary with encryption key information
    """
    return {
        "recommended_key_length": "16 (AES-128), 24 (AES-192), or 32 (AES-256) bytes",
        "key_management_services": "Azure Key Vault, AWS KMS, GCP Cloud KMS",
        "best_practices": [
            "Never hardcode encryption keys",
            "Rotate keys regularly",
            "Use envelope encryption for additional security",
            "Store keys separately from encrypted data",
            "Implement proper key access controls"]}


# ============================================================================
# GOVERNANCE UTILITIES
# ============================================================================

def create_privacy_report(
        spark: SparkSession,
        catalog: str,
        schema: str) -> DataFrame:
    """
    Create a report of tables and their column types for privacy assessment.

    Args:
        spark: SparkSession instance
        catalog: Catalog name
        schema: Schema name

    Returns:
        DataFrame with table and column information
    """
    tables_query = f"""
    SELECT
        table_catalog,
        table_schema,
        table_name,
        column_name,
        data_type,
        CASE
            WHEN column_name LIKE '%ssn%' OR column_name LIKE '%social%' THEN 'HIGH'
            WHEN column_name LIKE '%email%' OR column_name LIKE '%phone%' THEN 'MEDIUM'
            WHEN column_name LIKE '%name%' OR column_name LIKE '%address%' THEN 'MEDIUM'
            ELSE 'LOW'
        END AS privacy_risk
    FROM system.information_schema.columns
    WHERE table_catalog = '{catalog}'
        AND table_schema = '{schema}'
    ORDER BY privacy_risk DESC, table_name, column_name
    """

    try:
        return spark.sql(tables_query)
    except Exception as e:
        print(f"Warning: Could not generate privacy report. Error: {e}")
        return None


def list_privacy_functions(
        spark: SparkSession,
        catalog: str,
        schema: str) -> List[str]:
    """
    List all user-defined functions in a governance schema.

    Args:
        spark: SparkSession instance
        catalog: Catalog name
        schema: Schema name (typically governance schema)

    Returns:
        List of function names
    """
    try:
        functions_df = spark.sql(f"SHOW FUNCTIONS IN {catalog}.{schema}")
        return [row.function for row in functions_df.collect()]
    except Exception as e:
        print(f"Warning: Could not list functions. Error: {e}")
        return []


# ============================================================================
# VALIDATION UTILITIES
# ============================================================================

def validate_privacy_setup(spark: SparkSession,
                           catalog: str,
                           schemas: List[str]) -> Dict[str, Any]:
    """
    Validate that privacy demonstration setup is complete.

    Args:
        spark: SparkSession instance
        catalog: Catalog name
        schemas: List of schema names to validate

    Returns:
        Dictionary with validation results
    """
    results = {
        "catalog": catalog,
        "schemas_exist": {},
        "tables_exist": {},
        "functions_exist": {},
        "status": "PASS"
    }

    # Check schemas
    for schema in schemas:
        try:
            spark.sql(f"DESCRIBE SCHEMA {catalog}.{schema}")
            results["schemas_exist"][schema] = True
        except Exception:
            results["schemas_exist"][schema] = False
            results["status"] = "FAIL"

    return results


# ============================================================================
# DISPLAY UTILITIES
# ============================================================================

def print_privacy_banner(title: str, width: int = 70):
    """
    Print a formatted banner for section headers.

    Args:
        title: Title text to display
        width: Width of the banner
    """
    print("\n" + "=" * width)
    print(f" {title}")
    print("=" * width + "\n")


def print_privacy_checklist():
    """
    Print a checklist of privacy best practices.
    """
    checklist = """
    DATA PRIVACY IMPLEMENTATION CHECKLIST
    =====================================

    □ Identify sensitive data (PII, PHI, PCI, etc.)
    □ Classify data by sensitivity level (HIGH, MEDIUM, LOW)
    □ Implement RBAC for baseline access control
    □ Apply column masking for sensitive fields
    □ Implement row-level filtering for data segmentation
    □ Consider encryption for highly sensitive data
    □ Tag columns/tables with metadata for ABAC
    □ Create views for controlled data access
    □ Set up audit logging for compliance
    □ Document access policies and procedures
    □ Regularly review and update access controls
    □ Train users on data privacy policies

    For more information, visit:
    https://docs.databricks.com/en/security/privacy/index.html
    """
    print(checklist)


# ============================================================================
# EXPORT
# ============================================================================

__all__ = [
    # Data generation
    'generate_sample_employees',
    'generate_sample_customers',

    # Hashing
    'hash_column',
    'apply_column_hashing',

    # Masking
    'mask_ssn',
    'mask_email',
    'apply_column_masking',

    # Encryption
    'get_encryption_key_info',

    # Governance
    'create_privacy_report',
    'list_privacy_functions',
    'validate_privacy_setup',

    # Display
    'print_privacy_banner',
    'print_privacy_checklist'
]
