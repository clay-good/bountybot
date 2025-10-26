#!/usr/bin/env python3
"""
Demo: BountyBot v2.18.0 - AI Model Fine-Tuning & Custom Training Pipeline

This demo showcases the advanced ML training capabilities including:
- Custom model training
- Transfer learning
- Active learning
- Model versioning & A/B testing
- Federated learning
- Model explainability
"""

import numpy as np
from datetime import datetime

from bountybot.ml.training import (
    TrainingDataset,
    TrainingExample,
    TrainingExperiment,
    ModelVersion,
    DatasetSplit,
    ModelType,
    TrainingPipeline,
    TransferLearningEngine,
    ActiveLearningPipeline,
    SamplingStrategy,
    ModelRegistryManager,
    ABTestingFramework,
    FederatedLearningCoordinator,
    ModelExplainer
)
from bountybot.ml.deep_learning import (
    NeuralNetwork,
    TrainingConfig,
    FeatureVector
)


def print_section(title: str):
    """Print section header."""
    print(f"\n{'='*80}")
    print(f"  {title}")
    print(f"{'='*80}\n")


def demo_custom_training():
    """Demo custom model training."""
    print_section("1. Custom Model Training")
    
    # Create training dataset
    dataset = TrainingDataset(
        name="Vulnerability Classification Dataset",
        description="Custom dataset for SQL injection detection",
        model_type=ModelType.VULNERABILITY_CLASSIFIER,
        num_classes=3,
        class_names=["sql_injection", "xss", "csrf"]
    )
    
    # Add training examples
    for i in range(100):
        example = TrainingExample(
            input_data={
                "title": f"Vulnerability Report {i}",
                "description": f"Test vulnerability description {i}"
            },
            label=dataset.class_names[i % 3]
        )
        dataset.examples.append(example)
    
    print(f"✓ Created dataset: {dataset.name}")
    print(f"  - Examples: {len(dataset.examples)}")
    print(f"  - Classes: {dataset.num_classes}")
    
    # Initialize training pipeline
    pipeline = TrainingPipeline()
    
    # Prepare dataset with splits
    prepared = pipeline.prepare_dataset(
        dataset,
        validation_split=0.2,
        test_split=0.1
    )
    
    train_size = len(prepared.get_split(DatasetSplit.TRAIN))
    val_size = len(prepared.get_split(DatasetSplit.VALIDATION))
    test_size = len(prepared.get_split(DatasetSplit.TEST))
    
    print(f"\n✓ Prepared dataset splits:")
    print(f"  - Train: {train_size} examples")
    print(f"  - Validation: {val_size} examples")
    print(f"  - Test: {test_size} examples")
    
    # Validate dataset
    is_valid, errors = pipeline.validate_dataset(prepared)
    print(f"\n✓ Dataset validation: {'PASSED' if is_valid else 'FAILED'}")
    if errors:
        print(f"  - Warnings: {len(errors)}")


def demo_transfer_learning():
    """Demo transfer learning."""
    print_section("2. Transfer Learning & Fine-Tuning")
    
    # Create base model
    config = TrainingConfig(
        input_size=128,
        hidden_sizes=[256, 128, 64],
        output_size=20
    )
    base_model = NeuralNetwork(config)
    
    print(f"✓ Created base model:")
    print(f"  - Input size: {config.input_size}")
    print(f"  - Hidden layers: {config.hidden_sizes}")
    print(f"  - Output size: {config.output_size}")
    print(f"  - Parameters: {base_model.get_num_parameters():,}")
    
    # Initialize transfer learning engine
    engine = TransferLearningEngine()
    
    # Freeze bottom layers
    frozen_model = engine.freeze_layers(base_model, num_layers_to_freeze=2)
    print(f"\n✓ Froze bottom 2 layers for transfer learning")
    print(f"  - Frozen layers: {len(frozen_model.frozen_layers)}")
    
    # Get transfer learning strategy
    strategy = engine.get_transfer_learning_strategy(
        source_dataset_size=10000,
        target_dataset_size=100,
        similarity_score=0.7
    )
    
    print(f"\n✓ Transfer learning strategy:")
    print(f"  - Freeze layers: {strategy['freeze_layers']}")
    print(f"  - Learning rate multiplier: {strategy['learning_rate_multiplier']}")
    print(f"  - Recommendation: {strategy['recommendation']}")


def demo_active_learning():
    """Demo active learning."""
    print_section("3. Active Learning Pipeline")
    
    # Create model
    config = TrainingConfig(input_size=128, output_size=10)
    model = NeuralNetwork(config)
    
    # Initialize active learning pipeline
    pipeline = ActiveLearningPipeline(
        model,
        strategy=SamplingStrategy.UNCERTAINTY
    )
    
    print(f"✓ Created active learning pipeline:")
    print(f"  - Strategy: {pipeline.strategy.value}")
    
    # Create unlabeled pool
    unlabeled = [
        TrainingExample(
            input_data={"title": f"Unlabeled Report {i}"},
            label=""
        )
        for i in range(50)
    ]
    
    print(f"  - Unlabeled pool: {len(unlabeled)} examples")
    
    # Select most informative samples
    selected = pipeline.select_samples(unlabeled, n_samples=10)
    
    print(f"\n✓ Selected {len(selected)} most informative samples for labeling")
    
    # Estimate labeling budget
    estimate = pipeline.estimate_labeling_budget(
        target_accuracy=0.95,
        current_accuracy=0.80,
        samples_per_iteration=10
    )
    
    print(f"\n✓ Labeling budget estimate:")
    print(f"  - Estimated samples needed: {estimate['estimated_samples']}")
    print(f"  - Estimated iterations: {estimate['estimated_iterations']}")
    print(f"  - Target achievable: {estimate['achievable']}")


def demo_model_registry():
    """Demo model versioning and registry."""
    print_section("4. Model Versioning & Registry")
    
    # Create model registry manager
    manager = ModelRegistryManager()
    
    # Create registry
    registry = manager.create_registry(
        model_name="vulnerability_classifier",
        model_type=ModelType.VULNERABILITY_CLASSIFIER
    )
    
    print(f"✓ Created model registry: {registry.model_name}")
    
    # Register model versions
    v1 = manager.register_model(
        model_name="vulnerability_classifier",
        version="1.0.0",
        model_type=ModelType.VULNERABILITY_CLASSIFIER,
        experiment_id="exp_001",
        model_path="/models/v1.0.0",
        description="Initial baseline model"
    )
    
    v2 = manager.register_model(
        model_name="vulnerability_classifier",
        version="2.0.0",
        model_type=ModelType.VULNERABILITY_CLASSIFIER,
        experiment_id="exp_002",
        model_path="/models/v2.0.0",
        description="Improved model with transfer learning"
    )
    
    print(f"\n✓ Registered model versions:")
    print(f"  - v1.0.0: {v1.version_id[:8]}...")
    print(f"  - v2.0.0: {v2.version_id[:8]}...")
    
    # Promote to champion
    champion = manager.promote_to_champion("vulnerability_classifier", v2.version_id)
    print(f"\n✓ Promoted v2.0.0 to champion model")
    
    # Deploy to production
    deployed = manager.deploy_to_production("vulnerability_classifier", v2.version_id)
    print(f"✓ Deployed v2.0.0 to production")
    print(f"  - Deployed at: {deployed.deployed_at.strftime('%Y-%m-%d %H:%M:%S')}")


def demo_ab_testing():
    """Demo A/B testing."""
    print_section("5. A/B Testing Framework")
    
    # Create A/B testing framework
    framework = ABTestingFramework()
    
    # Create model versions
    model_a = ModelVersion(model_name="classifier", version="1.0.0")
    model_b = ModelVersion(model_name="classifier", version="2.0.0")
    
    # Create A/B test
    test = framework.create_test(
        name="Classifier v1 vs v2",
        model_a=model_a,
        model_b=model_b,
        traffic_split=0.5,
        min_samples=100
    )
    
    print(f"✓ Created A/B test: {test.name}")
    print(f"  - Test ID: {test.test_id[:8]}...")
    print(f"  - Traffic split: {test.traffic_split*100:.0f}% to model B")
    print(f"  - Min samples: {test.min_samples}")
    
    # Simulate traffic
    print(f"\n✓ Simulating traffic...")
    for i in range(200):
        variant = framework.route_request(test.test_id)
        # Simulate results (model B is slightly better)
        correct = np.random.random() < (0.85 if variant == "A" else 0.90)
        latency = np.random.normal(100 if variant == "A" else 110, 10)
        
        framework.record_result(
            test.test_id,
            variant,
            prediction_correct=correct,
            latency_ms=latency
        )
    
    # Analyze results
    result = framework.analyze_test(test.test_id)
    
    print(f"\n✓ A/B test results:")
    print(f"  - Model A: {result.model_a_samples} samples, {result.model_a_accuracy:.1%} accuracy")
    print(f"  - Model B: {result.model_b_samples} samples, {result.model_b_accuracy:.1%} accuracy")
    print(f"  - Statistical significance: {result.statistical_significance}")
    print(f"  - Winner: {result.winner if result.winner else 'No clear winner'}")
    print(f"  - Recommendation: {result.recommendation}")


def demo_federated_learning():
    """Demo federated learning."""
    print_section("6. Federated Learning")
    
    # Create global model
    config = TrainingConfig(input_size=128, output_size=10)
    global_model = NeuralNetwork(config)
    
    # Create federated learning coordinator
    coordinator = FederatedLearningCoordinator(global_model)
    
    print(f"✓ Created federated learning coordinator")
    print(f"  - Global model parameters: {global_model.get_num_parameters():,}")
    
    # Start federated round
    tenants = ["tenant_1", "tenant_2", "tenant_3", "tenant_4", "tenant_5"]
    round_obj = coordinator.start_round(tenants)
    
    print(f"\n✓ Started federated round {round_obj.round_number}")
    print(f"  - Participating tenants: {len(round_obj.participating_tenants)}")
    
    # Simulate local training and updates
    print(f"\n✓ Simulating local training...")
    for tenant in tenants:
        # Simulate local model weights
        weights = {
            'weights': np.random.randn(100, 50),
            'biases': np.random.randn(50)
        }
        
        coordinator.submit_local_update(
            round_obj.round_id,
            tenant,
            weights,
            num_samples=np.random.randint(50, 200)
        )
        print(f"  - Received update from {tenant}")
    
    # Complete round
    completed = coordinator.complete_round(round_obj.round_id)
    
    print(f"\n✓ Completed federated round {completed.round_number}")
    print(f"  - Updates received: {len(completed.tenant_updates)}")
    print(f"  - Status: {completed.status.value}")


def demo_explainability():
    """Demo model explainability."""
    print_section("7. Model Explainability")
    
    # Create model
    config = TrainingConfig(input_size=128, output_size=10)
    model = NeuralNetwork(config)
    
    # Create explainer
    explainer = ModelExplainer(model)
    
    print(f"✓ Created model explainer")
    
    # Create feature vector
    features = FeatureVector(
        title_tokens=["sql", "injection", "vulnerability"],
        description_tokens=["database", "query", "attack"],
        title_length=25,
        description_length=150,
        num_urls=2,
        num_code_blocks=1,
        has_poc=True,
        has_exploit=False,
        text_embedding=[0.1] * 120
    )
    
    # Explain prediction
    result = explainer.explain_prediction(
        input_data={
            "title": "SQL Injection Vulnerability",
            "description": "Database query attack vector"
        },
        features=features,
        prediction="sql_injection",
        confidence=0.95,
        model_version_id="v1.0.0"
    )
    
    print(f"\n✓ Prediction explanation:")
    print(f"  - Prediction: {result.prediction}")
    print(f"  - Confidence: {result.confidence:.1%}")
    print(f"  - Top features:")
    for feature, importance in result.top_features[:5]:
        print(f"    • {feature}: {importance:.3f}")
    
    print(f"\n{result.explanation_text}")


def main():
    """Run all demos."""
    print("\n" + "="*80)
    print("  BountyBot v2.18.0 - AI Model Fine-Tuning & Custom Training Pipeline")
    print("  Demo Script")
    print("="*80)
    
    try:
        demo_custom_training()
        demo_transfer_learning()
        demo_active_learning()
        demo_model_registry()
        demo_ab_testing()
        demo_federated_learning()
        demo_explainability()
        
        print_section("Demo Complete!")
        print("✅ All features demonstrated successfully!")
        print("\nBountyBot v2.18.0 provides enterprise-grade ML training capabilities:")
        print("  • Custom model training with data validation")
        print("  • Transfer learning for domain adaptation")
        print("  • Active learning for efficient labeling")
        print("  • Model versioning and registry")
        print("  • A/B testing for safe deployment")
        print("  • Federated learning for privacy-preserving training")
        print("  • Model explainability for interpretability")
        print("\n" + "="*80 + "\n")
        
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()

