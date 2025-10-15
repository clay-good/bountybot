try:
    from .metrics_collector import (
        MetricsCollector,
        ReportMetrics,
        ResearcherMetrics,
        SystemMetrics
    )

    from .trend_analyzer import (
        TrendAnalyzer,
        TrendData,
        TrendType
    )

    __all__ = [
        'MetricsCollector',
        'ReportMetrics',
        'ResearcherMetrics',
        'SystemMetrics',
        'TrendAnalyzer',
        'TrendData',
        'TrendType'
    ]
except ImportError as e:
    # Graceful degradation if analytics dependencies are missing
    import logging
    logging.warning(f"Analytics module not fully available: {e}")
    __all__ = []

