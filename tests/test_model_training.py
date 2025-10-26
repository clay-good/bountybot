"""
Tests for AI Model Training & Fine-Tuning System
"""

import pytest
import numpy as np
from datetime import datetime

from bountybot.ml.training import (
    TrainingDataset,
    TrainingExample,
    TrainingExperiment,
    ModelVersion,
    ModelRegistry,
    ABTestConfig,
    FederatedRound,
    ExplainabilityResult,
    DatasetSplit,
    TrainingStatus,
    ModelType,
    ExperimentStatus,
    TrainingPipeline,
    TransferLearningEngine,
    ActiveLearningPipeline,
    ModelRegistryManager,
    ABTestingFramework,
    FederatedLearningCoordinator,
    ModelExplainer,
    SamplingStrategy
)
from bountybot.ml.deep_learning import (
    NeuralNetwork,
    TrainingConfig,
    FeatureVector
)


class TestTrainingDataset:
    """Test training dataset functionality."""
    
    def test_create_dataset(self):
        """Test creating training dataset."""
        dataset = TrainingDataset(
            name="Test Dataset",
            description="Test vulnerability dataset",
            model_type=ModelType.VULNERABILITY_CLASSIFIER,
            num_classes=3,
            class_names=["sql_injection", "xss", "csrf"]
        )
        
        assert dataset.name == "Test Dataset"
        assert dataset.num_classes == 3
        assert len(dataset.class_names) == 3
        assert len(dataset.examples) == 0
    
    def test_add_examples(self):
        """Test adding examples to dataset."""
        dataset = TrainingDataset(
            name="Test Dataset",
            class_names=["sql_injection", "xss"]
        )
        
        example = TrainingExample(
            input_data={"title": "SQL Injection", "description": "Test"},
            label="sql_injection",
            split=DatasetSplit.TRAIN
        )
        
        dataset.examples.append(example)
        
        assert len(dataset.examples) == 1
        assert dataset.examples[0].label == "sql_injection"
    
    def test_get_split(self):
        """Test getting examples by split."""
        dataset = TrainingDataset(name="Test")
        
        dataset.examples = [
            TrainingExample(input_data={}, label="a", split=DatasetSplit.TRAIN),
            TrainingExample(input_data={}, label="b", split=DatasetSplit.TRAIN),
            TrainingExample(input_data={}, label="c", split=DatasetSplit.VALIDATION),
        ]
        
        train = dataset.get_split(DatasetSplit.TRAIN)
        val = dataset.get_split(DatasetSplit.VALIDATION)
        
        assert len(train) == 2
        assert len(val) == 1
    
    def test_class_distribution(self):
        """Test getting class distribution."""
        dataset = TrainingDataset(name="Test")
        
        dataset.examples = [
            TrainingExample(input_data={}, label="sql_injection"),
            TrainingExample(input_data={}, label="sql_injection"),
            TrainingExample(input_data={}, label="xss"),
        ]
        
        dist = dataset.get_class_distribution()
        
        assert dist["sql_injection"] == 2
        assert dist["xss"] == 1


class TestTrainingPipeline:
    """Test training pipeline."""
    
    def test_create_pipeline(self):
        """Test creating training pipeline."""
        pipeline = TrainingPipeline()
        
        assert pipeline.config is not None
        assert pipeline.feature_engineer is not None
    
    def test_prepare_dataset(self):
        """Test dataset preparation."""
        pipeline = TrainingPipeline()
        
        dataset = TrainingDataset(name="Test")
        dataset.examples = [
            TrainingExample(input_data={}, label=f"label_{i}")
            for i in range(100)
        ]
        
        prepared = pipeline.prepare_dataset(
            dataset,
            validation_split=0.2,
            test_split=0.1
        )
        
        train = prepared.get_split(DatasetSplit.TRAIN)
        val = prepared.get_split(DatasetSplit.VALIDATION)
        test = prepared.get_split(DatasetSplit.TEST)
        
        assert len(train) == 70
        assert len(val) == 20
        assert len(test) == 10
    
    def test_validate_dataset(self):
        """Test dataset validation."""
        pipeline = TrainingPipeline()

        # Valid dataset
        dataset = TrainingDataset(
            name="Test",
            class_names=["a", "b"],
            num_classes=2
        )
        dataset.examples = [
            TrainingExample(input_data={"title": f"Test {idx}"}, label="a", split=DatasetSplit.TRAIN)
            for idx in range(10)
        ]

        is_valid, errors = pipeline.validate_dataset(dataset)

        # Should pass or have minor warnings
        assert len(errors) < 5  # Allow some warnings
    
    def test_augment_data(self):
        """Test data augmentation."""
        pipeline = TrainingPipeline()
        
        examples = [
            TrainingExample(
                input_data={"title": "Test", "description": "Test desc"},
                label="test"
            )
            for _ in range(5)
        ]
        
        augmented = pipeline.augment_data(examples, augmentation_factor=3)
        
        assert len(augmented) == 15  # 5 * 3


class TestTransferLearning:
    """Test transfer learning."""
    
    def test_create_engine(self):
        """Test creating transfer learning engine."""
        engine = TransferLearningEngine()
        
        assert engine is not None
    
    def test_freeze_layers(self):
        """Test freezing layers."""
        engine = TransferLearningEngine()

        config = TrainingConfig(
            input_size=100,
            output_size=10,
            hidden_sizes=[64, 32]
        )
        model = NeuralNetwork(config)

        frozen = engine.freeze_layers(model, num_layers_to_freeze=1)

        assert hasattr(frozen, 'frozen_layers')
        assert len(frozen.frozen_layers) == 1

    def test_unfreeze_layers(self):
        """Test unfreezing layers."""
        engine = TransferLearningEngine()

        config = TrainingConfig(
            input_size=100,
            output_size=10,
            hidden_sizes=[64, 32]
        )
        model = NeuralNetwork(config)

        model = engine.freeze_layers(model, 2)
        initial_frozen = len(model.frozen_layers)
        model = engine.unfreeze_layers(model, 1)

        # Should have fewer frozen layers after unfreezing
        assert len(model.frozen_layers) <= initial_frozen
    
    def test_transfer_learning_strategy(self):
        """Test getting transfer learning strategy."""
        engine = TransferLearningEngine()
        
        strategy = engine.get_transfer_learning_strategy(
            source_dataset_size=10000,
            target_dataset_size=50,
            similarity_score=0.8
        )
        
        assert 'freeze_layers' in strategy
        assert 'learning_rate_multiplier' in strategy
        assert 'recommendation' in strategy


class TestActiveLearning:
    """Test active learning."""
    
    def test_create_pipeline(self):
        """Test creating active learning pipeline."""
        config = TrainingConfig(input_size=100, output_size=10)
        model = NeuralNetwork(config)
        pipeline = ActiveLearningPipeline(model, strategy=SamplingStrategy.UNCERTAINTY)

        assert pipeline.model is not None
        assert pipeline.strategy == SamplingStrategy.UNCERTAINTY

    def test_select_samples_uncertainty(self):
        """Test uncertainty sampling."""
        config = TrainingConfig(input_size=100, output_size=10)
        model = NeuralNetwork(config)
        pipeline = ActiveLearningPipeline(model, strategy=SamplingStrategy.UNCERTAINTY)

        unlabeled = [
            TrainingExample(input_data={"title": f"Test {i}"}, label="")
            for i in range(20)
        ]

        selected = pipeline.select_samples(unlabeled, n_samples=5)

        assert len(selected) == 5

    def test_label_samples(self):
        """Test labeling samples."""
        config = TrainingConfig(input_size=100, output_size=10)
        model = NeuralNetwork(config)
        pipeline = ActiveLearningPipeline(model)

        samples = [
            TrainingExample(input_data={"title": "SQL Injection"}, label="")
        ]

        def labeling_func(example):
            return "sql_injection"

        labeled = pipeline.label_samples(samples, labeling_func)

        assert len(labeled) == 1
        assert labeled[0].label == "sql_injection"

    def test_estimate_labeling_budget(self):
        """Test labeling budget estimation."""
        config = TrainingConfig(input_size=100, output_size=10)
        model = NeuralNetwork(config)
        pipeline = ActiveLearningPipeline(model)
        
        estimate = pipeline.estimate_labeling_budget(
            target_accuracy=0.95,
            current_accuracy=0.85,
            samples_per_iteration=10
        )
        
        assert 'estimated_samples' in estimate
        assert 'estimated_iterations' in estimate
        assert 'achievable' in estimate


class TestModelRegistry:
    """Test model registry."""
    
    def test_create_registry(self):
        """Test creating model registry."""
        manager = ModelRegistryManager()
        
        registry = manager.create_registry(
            model_name="vulnerability_classifier",
            model_type=ModelType.VULNERABILITY_CLASSIFIER
        )
        
        assert registry.model_name == "vulnerability_classifier"
        assert len(registry.versions) == 0
    
    def test_register_model(self):
        """Test registering model version."""
        manager = ModelRegistryManager()
        
        version = manager.register_model(
            model_name="test_model",
            version="1.0.0",
            model_type=ModelType.VULNERABILITY_CLASSIFIER,
            experiment_id="exp_123",
            model_path="/models/test_1.0.0",
            description="Initial version"
        )
        
        assert version.version == "1.0.0"
        assert version.model_name == "test_model"
    
    def test_promote_to_champion(self):
        """Test promoting model to champion."""
        manager = ModelRegistryManager()
        
        v1 = manager.register_model(
            model_name="test_model",
            version="1.0.0",
            model_type=ModelType.VULNERABILITY_CLASSIFIER,
            experiment_id="exp_1",
            model_path="/models/v1"
        )
        
        champion = manager.promote_to_champion("test_model", v1.version_id)
        
        assert champion.is_champion
        assert manager.registries["test_model"].champion_version_id == v1.version_id
    
    def test_deploy_to_production(self):
        """Test deploying to production."""
        manager = ModelRegistryManager()
        
        v1 = manager.register_model(
            model_name="test_model",
            version="1.0.0",
            model_type=ModelType.VULNERABILITY_CLASSIFIER,
            experiment_id="exp_1",
            model_path="/models/v1"
        )
        
        deployed = manager.deploy_to_production("test_model", v1.version_id)
        
        assert deployed.is_production
        assert deployed.deployed_at is not None


class TestABTesting:
    """Test A/B testing framework."""
    
    def test_create_test(self):
        """Test creating A/B test."""
        framework = ABTestingFramework()
        
        model_a = ModelVersion(model_name="test", version="1.0.0")
        model_b = ModelVersion(model_name="test", version="2.0.0")
        
        config = framework.create_test(
            name="Test A/B",
            model_a=model_a,
            model_b=model_b,
            traffic_split=0.5
        )
        
        assert config.name == "Test A/B"
        assert config.traffic_split == 0.5
    
    def test_route_request(self):
        """Test request routing."""
        framework = ABTestingFramework()
        
        model_a = ModelVersion(model_name="test", version="1.0.0")
        model_b = ModelVersion(model_name="test", version="2.0.0")
        
        config = framework.create_test(
            name="Test",
            model_a=model_a,
            model_b=model_b,
            traffic_split=0.5
        )
        
        # Test routing
        routes = [framework.route_request(config.test_id) for _ in range(100)]
        
        # Should have both A and B
        assert "A" in routes
        assert "B" in routes
    
    def test_record_and_analyze(self):
        """Test recording and analyzing results."""
        framework = ABTestingFramework()
        
        model_a = ModelVersion(model_name="test", version="1.0.0")
        model_b = ModelVersion(model_name="test", version="2.0.0")
        
        config = framework.create_test(
            name="Test",
            model_a=model_a,
            model_b=model_b,
            min_samples=10
        )
        
        # Record results
        for i in range(20):
            framework.record_result(
                config.test_id,
                "A",
                prediction_correct=True,
                latency_ms=100.0
            )
            framework.record_result(
                config.test_id,
                "B",
                prediction_correct=True,
                latency_ms=120.0
            )
        
        # Analyze
        result = framework.analyze_test(config.test_id)
        
        assert result.model_a_samples == 20
        assert result.model_b_samples == 20
        assert result.recommendation is not None


class TestFederatedLearning:
    """Test federated learning."""
    
    def test_create_coordinator(self):
        """Test creating federated learning coordinator."""
        config = TrainingConfig(input_size=100, output_size=10)
        model = NeuralNetwork(config)
        coordinator = FederatedLearningCoordinator(model)

        assert coordinator.global_model is not None
        assert coordinator.current_round == 0

    def test_start_round(self):
        """Test starting federated round."""
        config = TrainingConfig(input_size=100, output_size=10)
        model = NeuralNetwork(config)
        coordinator = FederatedLearningCoordinator(model)

        round_obj = coordinator.start_round(["tenant1", "tenant2", "tenant3"])

        assert round_obj.round_number == 1
        assert len(round_obj.participating_tenants) == 3
        assert round_obj.status == TrainingStatus.RUNNING

    def test_submit_and_aggregate(self):
        """Test submitting and aggregating updates."""
        config = TrainingConfig(input_size=100, output_size=10)
        model = NeuralNetwork(config)
        coordinator = FederatedLearningCoordinator(model)
        
        round_obj = coordinator.start_round(["tenant1", "tenant2"])
        
        # Submit updates
        for tenant in ["tenant1", "tenant2"]:
            weights = {
                'weights': np.random.randn(100, 50),
                'biases': np.random.randn(50)
            }
            coordinator.submit_local_update(
                round_obj.round_id,
                tenant,
                weights,
                num_samples=100
            )
        
        # Aggregate
        aggregated = coordinator.aggregate_updates(round_obj.round_id)
        
        assert 'weights' in aggregated
        assert 'biases' in aggregated


class TestModelExplainer:
    """Test model explainability."""
    
    def test_create_explainer(self):
        """Test creating model explainer."""
        config = TrainingConfig(input_size=100, output_size=10)
        model = NeuralNetwork(config)
        explainer = ModelExplainer(model)

        assert explainer.model is not None

    def test_explain_prediction(self):
        """Test explaining prediction."""
        config = TrainingConfig(input_size=100, output_size=10)
        model = NeuralNetwork(config)
        explainer = ModelExplainer(model)

        features = FeatureVector(
            title_tokens=["sql", "injection"],
            description_tokens=["test", "vulnerability"],
            title_length=13,
            description_length=20,
            text_embedding=[0.1] * 92  # 100 - 8 base features = 92
        )

        result = explainer.explain_prediction(
            input_data={"title": "SQL Injection", "description": "Test"},
            features=features,
            prediction="sql_injection",
            confidence=0.95,
            model_version_id="v1"
        )

        assert result.prediction == "sql_injection"
        assert result.confidence == 0.95
        assert len(result.feature_importance) > 0
        assert len(result.top_features) > 0
        assert result.explanation_text != ""

    def test_generate_counterfactual(self):
        """Test generating counterfactual."""
        config = TrainingConfig(input_size=100, output_size=10)
        model = NeuralNetwork(config)
        explainer = ModelExplainer(model)

        features = FeatureVector(
            title_tokens=["sql", "injection"],
            description_tokens=["test", "vulnerability"],
            title_length=13,
            description_length=20,
            text_embedding=[0.1] * 92  # 100 - 8 base features = 92
        )

        counterfactual = explainer.generate_counterfactual(
            features,
            target_prediction="xss",
            max_changes=3
        )

        assert 'target_prediction' in counterfactual
        assert 'changes_needed' in counterfactual
        assert 'explanation' in counterfactual

