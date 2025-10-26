"""
Model Registry Manager

Manages model versions, deployment, and lifecycle.
"""

from datetime import datetime
from typing import Dict, List, Optional
import logging
import json

from .models import (
    ModelRegistry,
    ModelVersion,
    ModelType,
    ExperimentMetrics
)

logger = logging.getLogger(__name__)


class ModelRegistryManager:
    """
    Model registry for version management and deployment.
    
    Features:
    - Model versioning with semantic versioning
    - Champion/challenger tracking
    - Production deployment management
    - Model comparison and selection
    - Automated rollback
    - Model lineage tracking
    """
    
    def __init__(self):
        """Initialize model registry manager."""
        self.logger = logging.getLogger(__name__)
        self.registries: Dict[str, ModelRegistry] = {}
    
    def create_registry(
        self,
        model_name: str,
        model_type: ModelType
    ) -> ModelRegistry:
        """
        Create new model registry.
        
        Args:
            model_name: Name of the model
            model_type: Type of model
            
        Returns:
            Created registry
        """
        self.logger.info(f"Creating registry for model: {model_name}")
        
        registry = ModelRegistry(
            model_name=model_name,
            model_type=model_type
        )
        
        self.registries[model_name] = registry
        
        return registry
    
    def register_model(
        self,
        model_name: str,
        version: str,
        model_type: ModelType,
        experiment_id: str,
        model_path: str,
        metrics: Optional[ExperimentMetrics] = None,
        description: str = "",
        tags: Optional[List[str]] = None,
        metadata: Optional[Dict] = None
    ) -> ModelVersion:
        """
        Register new model version.
        
        Args:
            model_name: Name of the model
            version: Version string (e.g., "1.0.0")
            model_type: Type of model
            experiment_id: ID of training experiment
            model_path: Path to saved model
            metrics: Model metrics
            description: Version description
            tags: Version tags
            metadata: Additional metadata
            
        Returns:
            Registered model version
        """
        self.logger.info(f"Registering model: {model_name} v{version}")
        
        # Get or create registry
        if model_name not in self.registries:
            self.create_registry(model_name, model_type)
        
        registry = self.registries[model_name]
        
        # Create model version
        model_version = ModelVersion(
            model_name=model_name,
            version=version,
            model_type=model_type,
            experiment_id=experiment_id,
            model_path=model_path,
            metrics=metrics,
            description=description,
            tags=tags or [],
            metadata=metadata or {}
        )
        
        # Add to registry
        registry.versions.append(model_version)
        registry.updated_at = datetime.utcnow()
        
        self.logger.info(f"Registered model version: {model_version.version_id}")
        
        return model_version
    
    def promote_to_champion(
        self,
        model_name: str,
        version_id: str
    ) -> ModelVersion:
        """
        Promote model version to champion.
        
        Args:
            model_name: Name of the model
            version_id: Version ID to promote
            
        Returns:
            Promoted model version
        """
        self.logger.info(f"Promoting model to champion: {model_name} version {version_id}")
        
        registry = self.registries.get(model_name)
        if not registry:
            raise ValueError(f"Registry not found: {model_name}")
        
        # Find version
        version = None
        for v in registry.versions:
            if v.version_id == version_id:
                version = v
                break
        
        if not version:
            raise ValueError(f"Version not found: {version_id}")
        
        # Update champion flags
        for v in registry.versions:
            v.is_champion = (v.version_id == version_id)
        
        registry.champion_version_id = version_id
        registry.updated_at = datetime.utcnow()
        
        self.logger.info(f"Champion updated: {version.version}")
        
        return version
    
    def deploy_to_production(
        self,
        model_name: str,
        version_id: str
    ) -> ModelVersion:
        """
        Deploy model version to production.
        
        Args:
            model_name: Name of the model
            version_id: Version ID to deploy
            
        Returns:
            Deployed model version
        """
        self.logger.info(f"Deploying to production: {model_name} version {version_id}")
        
        registry = self.registries.get(model_name)
        if not registry:
            raise ValueError(f"Registry not found: {model_name}")
        
        # Find version
        version = None
        for v in registry.versions:
            if v.version_id == version_id:
                version = v
                break
        
        if not version:
            raise ValueError(f"Version not found: {version_id}")
        
        # Update production flags
        for v in registry.versions:
            v.is_production = (v.version_id == version_id)
        
        version.deployed_at = datetime.utcnow()
        registry.production_version_id = version_id
        registry.updated_at = datetime.utcnow()
        
        self.logger.info(f"Deployed to production: {version.version}")
        
        return version
    
    def rollback_production(
        self,
        model_name: str,
        target_version_id: Optional[str] = None
    ) -> ModelVersion:
        """
        Rollback production to previous version.
        
        Args:
            model_name: Name of the model
            target_version_id: Specific version to rollback to (or previous if None)
            
        Returns:
            Rolled back model version
        """
        self.logger.info(f"Rolling back production: {model_name}")
        
        registry = self.registries.get(model_name)
        if not registry:
            raise ValueError(f"Registry not found: {model_name}")
        
        # Get current production version
        current_prod = registry.get_production()
        if not current_prod:
            raise ValueError("No production version to rollback from")
        
        # Find target version
        if target_version_id:
            target = None
            for v in registry.versions:
                if v.version_id == target_version_id:
                    target = v
                    break
            if not target:
                raise ValueError(f"Target version not found: {target_version_id}")
        else:
            # Find previous production version
            prod_versions = [v for v in registry.versions if v.deployed_at is not None]
            prod_versions.sort(key=lambda v: v.deployed_at)
            
            if len(prod_versions) < 2:
                raise ValueError("No previous version to rollback to")
            
            target = prod_versions[-2]
        
        # Deploy target version
        return self.deploy_to_production(model_name, target.version_id)
    
    def compare_versions(
        self,
        model_name: str,
        version_id_a: str,
        version_id_b: str
    ) -> Dict[str, any]:
        """
        Compare two model versions.
        
        Args:
            model_name: Name of the model
            version_id_a: First version ID
            version_id_b: Second version ID
            
        Returns:
            Comparison results
        """
        registry = self.registries.get(model_name)
        if not registry:
            raise ValueError(f"Registry not found: {model_name}")
        
        # Find versions
        version_a = None
        version_b = None
        for v in registry.versions:
            if v.version_id == version_id_a:
                version_a = v
            if v.version_id == version_id_b:
                version_b = v
        
        if not version_a or not version_b:
            raise ValueError("One or both versions not found")
        
        # Compare metrics
        comparison = {
            'version_a': {
                'version': version_a.version,
                'accuracy': version_a.metrics.accuracy if version_a.metrics else 0.0,
                'created_at': version_a.created_at.isoformat()
            },
            'version_b': {
                'version': version_b.version,
                'accuracy': version_b.metrics.accuracy if version_b.metrics else 0.0,
                'created_at': version_b.created_at.isoformat()
            },
            'winner': None,
            'improvement': 0.0
        }
        
        if version_a.metrics and version_b.metrics:
            acc_a = version_a.metrics.accuracy
            acc_b = version_b.metrics.accuracy
            
            if acc_b > acc_a:
                comparison['winner'] = 'B'
                comparison['improvement'] = (acc_b - acc_a) / acc_a * 100
            elif acc_a > acc_b:
                comparison['winner'] = 'A'
                comparison['improvement'] = (acc_a - acc_b) / acc_b * 100
        
        return comparison
    
    def get_model_lineage(
        self,
        model_name: str,
        version_id: str
    ) -> List[ModelVersion]:
        """
        Get lineage of model version (parent models in transfer learning).
        
        Args:
            model_name: Name of the model
            version_id: Version ID
            
        Returns:
            List of parent model versions
        """
        registry = self.registries.get(model_name)
        if not registry:
            return []
        
        lineage = []
        current_id = version_id
        
        # Trace back through parent models
        while current_id:
            version = None
            for v in registry.versions:
                if v.version_id == current_id:
                    version = v
                    break
            
            if not version:
                break
            
            lineage.append(version)
            
            # Get parent from metadata
            current_id = version.metadata.get('parent_version_id')
        
        return lineage
    
    def list_versions(
        self,
        model_name: str,
        include_deprecated: bool = False
    ) -> List[ModelVersion]:
        """
        List all versions of a model.
        
        Args:
            model_name: Name of the model
            include_deprecated: Whether to include deprecated versions
            
        Returns:
            List of model versions
        """
        registry = self.registries.get(model_name)
        if not registry:
            return []
        
        versions = registry.versions
        
        if not include_deprecated:
            versions = [v for v in versions if v.deprecated_at is None]
        
        # Sort by creation date (newest first)
        versions.sort(key=lambda v: v.created_at, reverse=True)
        
        return versions
    
    def deprecate_version(
        self,
        model_name: str,
        version_id: str
    ) -> ModelVersion:
        """
        Deprecate a model version.
        
        Args:
            model_name: Name of the model
            version_id: Version ID to deprecate
            
        Returns:
            Deprecated model version
        """
        self.logger.info(f"Deprecating version: {model_name} version {version_id}")
        
        registry = self.registries.get(model_name)
        if not registry:
            raise ValueError(f"Registry not found: {model_name}")
        
        # Find version
        version = None
        for v in registry.versions:
            if v.version_id == version_id:
                version = v
                break
        
        if not version:
            raise ValueError(f"Version not found: {version_id}")
        
        # Cannot deprecate production version
        if version.is_production:
            raise ValueError("Cannot deprecate production version")
        
        version.deprecated_at = datetime.utcnow()
        registry.updated_at = datetime.utcnow()
        
        return version

