"""msgspec-based validation models with enhanced features"""

import re
from typing import Any, TypeVar

import msgspec

Struct = msgspec.Struct
ValidationError = msgspec.ValidationError

T = TypeVar("T", bound="BaseModel")


class ConstraintValidator:
    """Validator for common constraints"""

    @staticmethod
    def validate_email(value: str) -> bool:
        """Validate email format"""
        pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
        return bool(re.match(pattern, value))

    @staticmethod
    def validate_url(value: str) -> bool:
        """Validate URL format"""
        pattern = r"^https?://[^\s/$.?#].[^\s]*$"
        return bool(re.match(pattern, value))

    @staticmethod
    def validate_phone(value: str) -> bool:
        """Validate phone number (basic)"""
        pattern = r"^\+?1?\d{9,15}$"
        cleaned = re.sub(r"[\s\-\(\)]", "", value)
        return bool(re.match(pattern, cleaned))

    @staticmethod
    def validate_length(value: str, min_len: int | None = None, max_len: int | None = None) -> bool:
        """Validate string length"""
        length = len(value)
        if min_len is not None and length < min_len:
            return False
        if max_len is not None and length > max_len:
            return False
        return True

    @staticmethod
    def validate_range(
        value: int | float, min_val: int | float | None = None, max_val: int | float | None = None
    ) -> bool:
        """Validate numeric range"""
        if min_val is not None and value < min_val:
            return False
        if max_val is not None and value > max_val:
            return False
        return True

    @staticmethod
    def validate_pattern(value: str, pattern: str) -> bool:
        """Validate against regex pattern"""
        return bool(re.match(pattern, value))


class FieldMetadata:
    """Metadata for struct fields"""

    __slots__ = (
        "min_length",
        "max_length",
        "pattern",
        "min_value",
        "max_value",
        "format",
        "description",
    )

    def __init__(
        self,
        min_length: int | None = None,
        max_length: int | None = None,
        pattern: str | None = None,
        min_value: int | float | None = None,
        max_value: int | float | None = None,
        format: str | None = None,
        description: str | None = None,
    ) -> None:
        self.min_length = min_length
        self.max_length = max_length
        self.pattern = pattern
        self.min_value = min_value
        self.max_value = max_value
        self.format = format
        self.description = description


def field(
    default: Any = msgspec.NODEFAULT,
    *,
    default_factory: Any = msgspec.NODEFAULT,
    name: str | None = None,
    metadata: FieldMetadata | None = None,
) -> Any:
    """Field definition for Struct with metadata support"""
    kwargs: dict[str, Any] = {}

    if default is not msgspec.NODEFAULT:
        kwargs["default"] = default
    if default_factory is not msgspec.NODEFAULT:
        kwargs["default_factory"] = default_factory
    if name is not None:
        kwargs["name"] = name

    return msgspec.field(**kwargs)


class BaseModel(msgspec.Struct):
    """Base model with validation hooks"""

    def __post_init__(self) -> None:
        """Called after initialization for custom validation"""
        self.validate()

    def validate(self) -> None:
        """Override this method for custom validation logic"""
        pass

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary"""
        return {field: getattr(self, field) for field in self.__struct_fields__}

    def json(self) -> bytes:
        """Serialize to JSON bytes"""
        return msgspec.json.encode(self)

    def json_str(self) -> str:
        """Serialize to JSON string"""
        return self.json().decode("utf-8")

    @classmethod
    def from_dict(cls: type[T], data: dict[str, Any]) -> T:
        """Create instance from dictionary"""
        return msgspec.convert(data, type=cls)

    @classmethod
    def from_json(cls: type[T], data: bytes | str) -> T:
        """Create instance from JSON"""
        if isinstance(data, str):
            data = data.encode("utf-8")
        return msgspec.json.decode(data, type=cls)

    def copy(self: T, **changes: Any) -> T:
        """Create a copy with changes"""
        current = self.to_dict()
        current.update(changes)
        return self.from_dict(current)

