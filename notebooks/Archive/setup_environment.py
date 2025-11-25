# Databricks notebook source
# MAGIC %md
# MAGIC # Data Privacy Demo - Environment Setup
# MAGIC
# MAGIC This script sets up the demo environment. It is called automatically by the main demo notebook.

# COMMAND ----------

# ============================================================================
# ENVIRONMENT SETUP
# ============================================================================
# This script is called via %run from the main demo notebook
# Configuration is passed from the calling notebook

from pyspark.sql.functions import *
from pyspark.sql.types import *

print("Setting up demo environment...")
print(f"→ Mode: {'Temporary tables' if USE_TEMP_TABLES else 'Permanent tables'}")

# Helper function
def get_table_type():
    return "TEMPORARY" if USE_TEMP_TABLES else ""

# Create schemas (only for permanent tables)
if not USE_TEMP_TABLES:
    for schema in [HR_SCHEMA, CUSTOMERS_SCHEMA, RETAIL_SCHEMA, GOVERNANCE_SCHEMA]:
        spark.sql(f"CREATE SCHEMA IF NOT EXISTS {CATALOG}.{schema}")
    print("✓ Schemas created")

# HR employee_info table
spark.sql(f"""CREATE OR REPLACE {get_table_type()} TABLE {CATALOG}.{HR_SCHEMA}.employee_info (
    id INT, name STRING, salary DECIMAL(10, 2), ssn STRING)""")
spark.sql(f"""INSERT INTO {CATALOG}.{HR_SCHEMA}.employee_info VALUES
    (1, 'David Wells', 100000.00, '123-45-6789'),
    (2, 'Chris Moon', 120000.00, '234-56-7890'),
    (3, 'Jane Doe', 95000.00, '345-67-8901'),
    (4, 'John Smith', 110000.00, '456-78-9012')""")

# Customers customer_info table
spark.sql(f"""CREATE OR REPLACE {get_table_type()} TABLE {CATALOG}.{CUSTOMERS_SCHEMA}.customer_info (
    id INT, email STRING, name STRING, created_at DATE)""")
spark.sql(f"""INSERT INTO {CATALOG}.{CUSTOMERS_SCHEMA}.customer_info VALUES
    (1, 'david.wells@databricks.com', 'David Wells', '2025-01-01'),
    (2, 'chris.moon@databricks.com', 'Chris Moon', '2025-02-01'),
    (3, 'jane.doe@example.com', 'Jane Doe', '2025-03-15'),
    (4, 'john.smith@example.com', 'John Smith', '2025-04-20')""")

# Retail customers table
spark.sql(f"""CREATE OR REPLACE {get_table_type()} TABLE {CATALOG}.{RETAIL_SCHEMA}.customers (
    id INT, ssn STRING, name STRING, region STRING)""")
spark.sql(f"""INSERT INTO {CATALOG}.{RETAIL_SCHEMA}.customers VALUES
    (1, '123-45-6789', 'Alice Smith', 'US'),
    (2, '234-56-7890', 'Maria Silva', 'EU'),
    (3, '456-78-9012', 'Akira Tanaka', 'APAC'),
    (4, '567-89-0123', 'Bob Johnson', 'US'),
    (5, '678-90-1234', 'Emma Brown', 'EU')""")

print("\n" + "="*60)
print("✓ Setup Complete!")
print("="*60)
print("→ All tables created and populated")
print("→ Ready for demonstrations")

