"""One authoritative location for detection defaults and configurable thresholds."""

from dataclasses import asdict, dataclass

RULE_VERSION = "1.0.0"


@dataclass(frozen=True)
class RuleConfig:
    failure_threshold: int = 5
    failure_window_minutes: int = 5
    success_window_minutes: int = 10
    task_window_minutes: int = 15

    def __post_init__(self):
        for name, value in asdict(self).items():
            if type(value) is not int or not 1 <= value <= 1440:
                raise ValueError(f"{name} must be an integer from 1 to 1440")
        if self.failure_threshold < 2:
            raise ValueError("failure_threshold must be at least 2")


DEFAULT_CONFIG = RuleConfig()
