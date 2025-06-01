#!/usr/bin/env python3

import argparse
import yaml
import json
import jsonschema
import logging
import os
import sys

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def setup_argparse():
    """
    Sets up the argument parser for the command-line interface.
    """
    parser = argparse.ArgumentParser(description="Analyzes service account configurations and validates them against security baselines.")
    parser.add_argument("config_file", help="Path to the configuration file (YAML or JSON).")
    parser.add_argument("schema_file", help="Path to the schema file (JSON) defining security baselines.")
    parser.add_argument("-l", "--log_level", choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'], default='INFO', help="Set the logging level.")
    parser.add_argument("-o", "--output_file", help="Path to the output file for the report (optional).")
    return parser.parse_args()

def load_config(config_file):
    """
    Loads configuration data from a YAML or JSON file.

    Args:
        config_file (str): Path to the configuration file.

    Returns:
        dict: Configuration data as a dictionary.

    Raises:
        FileNotFoundError: If the configuration file does not exist.
        ValueError: If the file format is invalid or loading fails.
    """
    try:
        with open(config_file, 'r') as f:
            if config_file.endswith('.yaml') or config_file.endswith('.yml'):
                try:
                    config_data = yaml.safe_load(f)
                except yaml.YAMLError as e:
                    raise ValueError(f"Error loading YAML file: {e}")
            elif config_file.endswith('.json'):
                try:
                    config_data = json.load(f)
                except json.JSONDecodeError as e:
                    raise ValueError(f"Error loading JSON file: {e}")
            else:
                raise ValueError("Unsupported file format.  Must be YAML or JSON.")
        return config_data
    except FileNotFoundError:
        raise FileNotFoundError(f"Configuration file not found: {config_file}")
    except Exception as e:
        raise ValueError(f"Error loading configuration file: {e}")


def load_schema(schema_file):
    """
    Loads a JSON schema from a file.

    Args:
        schema_file (str): Path to the schema file.

    Returns:
        dict: Schema data as a dictionary.

    Raises:
        FileNotFoundError: If the schema file does not exist.
        ValueError: If the file is not valid JSON or loading fails.
    """
    try:
        with open(schema_file, 'r') as f:
            try:
                schema_data = json.load(f)
                return schema_data
            except json.JSONDecodeError as e:
                raise ValueError(f"Error loading JSON schema: {e}")
    except FileNotFoundError:
        raise FileNotFoundError(f"Schema file not found: {schema_file}")
    except Exception as e:
        raise ValueError(f"Error loading schema file: {e}")

def validate_config(config_data, schema_data):
    """
    Validates the configuration data against the provided schema.

    Args:
        config_data (dict): Configuration data to validate.
        schema_data (dict): JSON schema to validate against.

    Returns:
        list: A list of validation errors (if any).  Empty list if validation passes.
        Each error is a dictionary containing 'message' and 'path'.

    Raises:
        jsonschema.exceptions.ValidationError: If the configuration does not match the schema.
    """
    try:
        jsonschema.validate(instance=config_data, schema=schema_data)
        return []  # No errors
    except jsonschema.exceptions.ValidationError as e:
        errors = []
        error_path = ".".join(map(str, e.path))  # Format the path as a string.

        error_info = {
            "message": e.message,
            "path": error_path
        }
        errors.append(error_info)

        return errors
    except jsonschema.exceptions.SchemaError as e:
        raise ValueError(f"Invalid schema: {e}")
    except Exception as e:
        raise Exception(f"Unexpected validation error: {e}")



def generate_report(validation_errors):
    """
    Generates a report based on the validation errors.

    Args:
        validation_errors (list): A list of validation error dictionaries.

    Returns:
        str: A formatted report string.
    """
    if not validation_errors:
        return "Configuration validation successful. No issues found."

    report = "Configuration validation failed:\n"
    for error in validation_errors:
        report += f"  - Path: {error['path']}\n"
        report += f"    Message: {error['message']}\n"
    return report

def main():
    """
    Main function to orchestrate the configuration validation process.
    """
    try:
        args = setup_argparse()

        # Set log level based on argument
        logging.getLogger().setLevel(args.log_level.upper())

        logging.info("Starting chv-ServiceAccountPrivilegeChecker...")

        config_data = load_config(args.config_file)
        logging.info(f"Configuration file loaded: {args.config_file}")

        schema_data = load_schema(args.schema_file)
        logging.info(f"Schema file loaded: {args.schema_file}")

        validation_errors = validate_config(config_data, schema_data)
        logging.info("Configuration validation completed.")

        report = generate_report(validation_errors)

        if args.output_file:
            try:
                with open(args.output_file, 'w') as f:
                    f.write(report)
                logging.info(f"Report saved to: {args.output_file}")
            except Exception as e:
                logging.error(f"Error writing report to file: {e}")
        else:
            print(report)

        if validation_errors:
            sys.exit(1)  # Exit with an error code if validation failed

        logging.info("chv-ServiceAccountPrivilegeChecker completed successfully.")


    except FileNotFoundError as e:
        logging.error(e)
        sys.exit(1)
    except ValueError as e:
        logging.error(e)
        sys.exit(1)
    except jsonschema.exceptions.ValidationError as e:
        logging.error(f"Schema validation error: {e}")
        sys.exit(1)
    except Exception as e:
        logging.exception(f"An unexpected error occurred: {e}")
        sys.exit(1)

if __name__ == "__main__":
    # Example Usage:
    # Create example configuration and schema files for testing.

    # Create a sample config.yaml
    config_data = {
        "service_accounts": [
            {
                "name": "web_server",
                "permissions": ["read", "write", "execute"]
            },
            {
                "name": "database_server",
                "permissions": ["read", "write", "admin"]
            }
        ]
    }

    with open("config.yaml", "w") as f:
        yaml.dump(config_data, f)

    # Create a sample schema.json
    schema_data = {
        "type": "object",
        "properties": {
            "service_accounts": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "name": {"type": "string"},
                        "permissions": {
                            "type": "array",
                            "items": {"type": "string"},
                            "uniqueItems": True
                        }
                    },
                    "required": ["name", "permissions"]
                }
            }
        },
        "required": ["service_accounts"]
    }

    with open("schema.json", "w") as f:
        json.dump(schema_data, f, indent=4)

    # Now run the script from the command line:
    # python main.py config.yaml schema.json

    main()