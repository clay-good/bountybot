import os
import yaml
import logging
from pathlib import Path
from typing import Dict, Any, Optional
from dotenv import load_dotenv

logger = logging.getLogger(__name__)


class ConfigLoader:
    """
    Loads and merges configuration from multiple sources:
    1. Command-line arguments (highest priority)
    2. Environment variables
    3. Custom config file
    4. User config (~/.bountybot/config.yaml)
    5. Default config (lowest priority)
    """
    
    def __init__(self):
        self.config: Dict[str, Any] = {}
        load_dotenv()
    
    def load(self, custom_config_path: Optional[str] = None, cli_overrides: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Load configuration from all sources and merge them.
        
        Args:
            custom_config_path: Path to custom config file
            cli_overrides: Dictionary of CLI argument overrides
            
        Returns:
            Merged configuration dictionary
        """
        # Start with default config
        default_config_path = Path(__file__).parent.parent / "config" / "default.yaml"
        self.config = self._load_yaml_file(default_config_path)
        
        # Load user config if exists
        user_config_path = Path.home() / ".bountybot" / "config.yaml"
        if user_config_path.exists():
            user_config = self._load_yaml_file(user_config_path)
            self.config = self._deep_merge(self.config, user_config)
        
        # Load custom config if provided
        if custom_config_path:
            custom_config = self._load_yaml_file(Path(custom_config_path))
            self.config = self._deep_merge(self.config, custom_config)
        
        # Apply environment variables
        self._apply_env_vars()
        
        # Apply CLI overrides (highest priority)
        if cli_overrides:
            self.config = self._deep_merge(self.config, cli_overrides)
        
        # Expand environment variables in config values
        self.config = self._expand_env_vars(self.config)
        
        logger.info("Configuration loaded successfully")
        return self.config
    
    def _load_yaml_file(self, path: Path) -> Dict[str, Any]:
        """Load YAML configuration file."""
        try:
            with open(path, 'r') as f:
                config = yaml.safe_load(f)
                return config or {}
        except FileNotFoundError:
            logger.warning(f"Config file not found: {path}")
            return {}
        except yaml.YAMLError as e:
            logger.error(f"Error parsing YAML file {path}: {e}")
            return {}
    
    def _deep_merge(self, base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
        """
        Deep merge two dictionaries, with override taking precedence.
        """
        result = base.copy()
        for key, value in override.items():
            if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                result[key] = self._deep_merge(result[key], value)
            else:
                result[key] = value
        return result
    
    def _apply_env_vars(self):
        """Apply environment variables with BOUNTYBOT_ prefix."""
        env_mappings = {
            'BOUNTYBOT_CONFIG_PATH': ('config_path',),
            'BOUNTYBOT_LOG_LEVEL': ('logging', 'level'),
            'BOUNTYBOT_CACHE_DIR': ('cache_dir',),
            'BOUNTYBOT_PARALLEL_TASKS': ('validation', 'parallel_tasks'),
            'BOUNTYBOT_MAX_COST_PER_RUN': ('cost_management', 'max_cost_per_validation'),
            'BOUNTYBOT_DAILY_BUDGET': ('cost_management', 'max_daily_cost'),
        }
        
        for env_var, config_path in env_mappings.items():
            value = os.getenv(env_var)
            if value:
                self._set_nested_value(self.config, config_path, value)
    
    def _set_nested_value(self, config: Dict[str, Any], path: tuple, value: Any):
        """Set a nested dictionary value using a path tuple."""
        current = config
        for key in path[:-1]:
            if key not in current:
                current[key] = {}
            current = current[key]
        
        # Try to convert to appropriate type
        final_key = path[-1]
        if isinstance(current.get(final_key), int):
            try:
                value = int(value)
            except ValueError:
                pass
        elif isinstance(current.get(final_key), float):
            try:
                value = float(value)
            except ValueError:
                pass
        elif isinstance(current.get(final_key), bool):
            value = value.lower() in ('true', '1', 'yes')
        
        current[final_key] = value
    
    def _expand_env_vars(self, config: Any) -> Any:
        """
        Recursively expand environment variables in config values.
        Supports ${VAR_NAME} syntax.
        """
        if isinstance(config, dict):
            return {k: self._expand_env_vars(v) for k, v in config.items()}
        elif isinstance(config, list):
            return [self._expand_env_vars(item) for item in config]
        elif isinstance(config, str):
            # Expand ${VAR_NAME} patterns
            import re
            pattern = r'\$\{([^}]+)\}'
            
            def replace_env_var(match):
                var_name = match.group(1)
                return os.getenv(var_name, match.group(0))
            
            return re.sub(pattern, replace_env_var, config)
        else:
            return config
    
    def validate_config(self) -> bool:
        """
        Validate that required configuration values are present.
        
        Returns:
            True if configuration is valid, False otherwise
        """
        required_fields = [
            ('api', 'default_provider'),
            ('api', 'providers'),
            ('validation', 'parallel_tasks'),
            ('output', 'formats'),
        ]
        
        for field_path in required_fields:
            current = self.config
            for key in field_path:
                if key not in current:
                    logger.error(f"Missing required config field: {'.'.join(field_path)}")
                    return False
                current = current[key]
        
        # Validate API key for default provider
        default_provider = self.config['api']['default_provider']
        provider_config = self.config['api']['providers'].get(default_provider, {})
        api_key = provider_config.get('api_key', '')
        
        if not api_key or api_key.startswith('${'):
            logger.error(f"API key not configured for provider: {default_provider}")
            return False
        
        return True
    
    def get(self, *path, default=None) -> Any:
        """
        Get a configuration value using a path.
        
        Example:
            config.get('api', 'default_provider')
        """
        current = self.config
        for key in path:
            if isinstance(current, dict) and key in current:
                current = current[key]
            else:
                return default
        return current

