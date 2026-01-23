"""Field validation engine for dynamic application forms.

Validates form data against field_validation_rules defined in credential
type configurations. Supports:
- String validation: min_length, max_length, pattern (regex)
- Numeric validation: min_value, max_value
- Enum validation: allowed_values
- Conditional validation: required_if, depends_on
"""

import re
from typing import Any, Optional
from datetime import datetime, date


class ValidationError(Exception):
    """Validation error with field name and message."""
    
    def __init__(self, field: str, message: str):
        self.field = field
        self.message = message
        super().__init__(f"{field}: {message}")


class FieldValidator:
    """Validates individual field values against rules."""
    
    def __init__(self, field_name: str, rules: dict[str, Any]):
        """Initialize validator.
        
        Args:
            field_name: Name of the field being validated
            rules: Validation rules dictionary
        """
        self.field_name = field_name
        self.rules = rules
    
    def validate(self, value: Any, all_data: dict[str, Any]) -> list[str]:
        """Validate a field value.
        
        Args:
            value: The field value to validate
            all_data: All form data (for conditional validation)
        
        Returns:
            List of error messages (empty if valid)
        """
        errors = []
        
        # Check if field is required
        if self.rules.get("required", False):
            if value is None or value == "" or (isinstance(value, list) and len(value) == 0):
                errors.append(f"{self.field_name} is required")
                return errors  # Stop further validation if required field is empty
        
        # Check conditional requirement
        if "required_if" in self.rules:
            if self._check_required_if(all_data):
                if value is None or value == "":
                    errors.append(f"{self.field_name} is required when {self.rules['required_if']}")
                    return errors
        
        # Check dependencies
        if "depends_on" in self.rules:
            depends_on = self.rules["depends_on"]
            if not isinstance(depends_on, list):
                depends_on = [depends_on]
            
            for dep_field in depends_on:
                if dep_field not in all_data or not all_data[dep_field]:
                    errors.append(f"{self.field_name} requires {dep_field} to be filled")
                    return errors
        
        # Skip other validations if value is empty and not required
        if value is None or value == "":
            return errors
        
        # String validations
        if isinstance(value, str):
            if "min_length" in self.rules:
                if len(value) < self.rules["min_length"]:
                    errors.append(
                        f"{self.field_name} must be at least {self.rules['min_length']} characters"
                    )
            
            if "max_length" in self.rules:
                if len(value) > self.rules["max_length"]:
                    errors.append(
                        f"{self.field_name} must not exceed {self.rules['max_length']} characters"
                    )
            
            if "pattern" in self.rules:
                pattern = self.rules["pattern"]
                if not re.match(pattern, value):
                    pattern_desc = self.rules.get("pattern_description", "required format")
                    errors.append(f"{self.field_name} must match {pattern_desc}")
        
        # Numeric validations
        if isinstance(value, (int, float)):
            if "min_value" in self.rules:
                if value < self.rules["min_value"]:
                    errors.append(
                        f"{self.field_name} must be at least {self.rules['min_value']}"
                    )
            
            if "max_value" in self.rules:
                if value > self.rules["max_value"]:
                    errors.append(
                        f"{self.field_name} must not exceed {self.rules['max_value']}"
                    )
        
        # Enum validation
        if "allowed_values" in self.rules:
            allowed = self.rules["allowed_values"]
            if value not in allowed:
                errors.append(
                    f"{self.field_name} must be one of: {', '.join(map(str, allowed))}"
                )
        
        # Date validations
        if "date_after" in self.rules:
            if isinstance(value, str):
                try:
                    value_date = datetime.fromisoformat(value.replace('Z', '+00:00')).date()
                except:
                    errors.append(f"{self.field_name} must be a valid date")
                    return errors
            elif isinstance(value, datetime):
                value_date = value.date()
            elif isinstance(value, date):
                value_date = value
            else:
                errors.append(f"{self.field_name} must be a date")
                return errors
            
            after_field = self.rules["date_after"]
            if after_field in all_data:
                after_value = all_data[after_field]
                if isinstance(after_value, str):
                    try:
                        after_date = datetime.fromisoformat(after_value.replace('Z', '+00:00')).date()
                        if value_date <= after_date:
                            errors.append(f"{self.field_name} must be after {after_field}")
                    except:
                        pass
        
        if "date_before" in self.rules:
            if isinstance(value, str):
                try:
                    value_date = datetime.fromisoformat(value.replace('Z', '+00:00')).date()
                except:
                    errors.append(f"{self.field_name} must be a valid date")
                    return errors
            elif isinstance(value, datetime):
                value_date = value.date()
            elif isinstance(value, date):
                value_date = value
            else:
                errors.append(f"{self.field_name} must be a date")
                return errors
            
            before_field = self.rules["date_before"]
            if before_field in all_data:
                before_value = all_data[before_field]
                if isinstance(before_value, str):
                    try:
                        before_date = datetime.fromisoformat(before_value.replace('Z', '+00:00')).date()
                        if value_date >= before_date:
                            errors.append(f"{self.field_name} must be before {before_field}")
                    except:
                        pass
        
        # Custom validation function (if provided as string - eval not recommended in production)
        if "custom_validator" in self.rules:
            custom_func = self.rules["custom_validator"]
            if callable(custom_func):
                try:
                    result = custom_func(value, all_data)
                    if result is not True:
                        errors.append(result or f"{self.field_name} failed custom validation")
                except Exception as e:
                    errors.append(f"{self.field_name} validation error: {str(e)}")
        
        return errors
    
    def _check_required_if(self, all_data: dict[str, Any]) -> bool:
        """Check if field is required based on condition.
        
        Args:
            all_data: All form data
        
        Returns:
            True if field is required based on condition
        """
        required_if = self.rules["required_if"]
        
        # Simple field presence check
        if isinstance(required_if, str):
            return required_if in all_data and all_data[required_if]
        
        # Dictionary with field: value condition
        if isinstance(required_if, dict):
            for field, expected_value in required_if.items():
                if field in all_data and all_data[field] == expected_value:
                    return True
        
        return False


class FormValidator:
    """Validates entire form against field validation rules."""
    
    def __init__(self, field_validation_rules: dict[str, dict[str, Any]]):
        """Initialize form validator.
        
        Args:
            field_validation_rules: Dictionary mapping field names to validation rules
        """
        self.field_validation_rules = field_validation_rules
        self.validators = {
            field: FieldValidator(field, rules)
            for field, rules in field_validation_rules.items()
        }
    
    def validate(self, form_data: dict[str, Any]) -> dict[str, list[str]]:
        """Validate all form data.
        
        Args:
            form_data: Dictionary of field names to values
        
        Returns:
            Dictionary mapping field names to lists of error messages
            Empty dict if all valid
        """
        errors = {}
        
        for field_name, validator in self.validators.items():
            value = form_data.get(field_name)
            field_errors = validator.validate(value, form_data)
            
            if field_errors:
                errors[field_name] = field_errors
        
        return errors
    
    def is_valid(self, form_data: dict[str, Any]) -> bool:
        """Check if form data is valid.
        
        Args:
            form_data: Dictionary of field names to values
        
        Returns:
            True if valid, False otherwise
        """
        return len(self.validate(form_data)) == 0
    
    def validate_partial(
        self,
        form_data: dict[str, Any],
        fields: list[str]
    ) -> dict[str, list[str]]:
        """Validate only specified fields.
        
        Useful for multi-step forms where you validate one step at a time.
        
        Args:
            form_data: Dictionary of field names to values
            fields: List of field names to validate
        
        Returns:
            Dictionary mapping field names to lists of error messages
        """
        errors = {}
        
        for field_name in fields:
            if field_name in self.validators:
                validator = self.validators[field_name]
                value = form_data.get(field_name)
                field_errors = validator.validate(value, form_data)
                
                if field_errors:
                    errors[field_name] = field_errors
        
        return errors


def validate_application_data(
    application_data: dict[str, Any],
    field_validation_rules: dict[str, dict[str, Any]]
) -> tuple[bool, dict[str, list[str]]]:
    """Validate application data against field rules.
    
    Convenience function for one-off validation.
    
    Args:
        application_data: Form/application data
        field_validation_rules: Validation rules
    
    Returns:
        Tuple of (is_valid, errors_dict)
    """
    validator = FormValidator(field_validation_rules)
    errors = validator.validate(application_data)
    return len(errors) == 0, errors
