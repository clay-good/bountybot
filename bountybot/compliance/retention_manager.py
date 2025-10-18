"""
Data Retention Manager

Manages data retention policies and enforcement.
"""

import logging
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
from .models import DataRetentionPolicy, DataClassification

logger = logging.getLogger(__name__)


class RetentionManager:
    """Manages data retention policies."""
    
    def __init__(self):
        """Initialize retention manager."""
        self.policies: Dict[str, DataRetentionPolicy] = {}
        self.retention_actions: List[Dict[str, Any]] = []
    
    def add_policy(self, policy: DataRetentionPolicy):
        """
        Add retention policy.
        
        Args:
            policy: Retention policy to add
        """
        self.policies[policy.policy_id] = policy
        logger.info(f"Added retention policy: {policy.name}")
    
    def get_policy(self, policy_id: str) -> Optional[DataRetentionPolicy]:
        """Get retention policy by ID."""
        return self.policies.get(policy_id)
    
    def get_applicable_policy(
        self,
        data_type: str,
        data_classification: Optional[DataClassification] = None
    ) -> Optional[DataRetentionPolicy]:
        """
        Get applicable retention policy for data.
        
        Args:
            data_type: Type of data
            data_classification: Data classification level
            
        Returns:
            Applicable policy or None
        """
        for policy in self.policies.values():
            if not policy.is_active:
                continue
            
            # Check data type match
            if data_type in policy.data_types:
                return policy
            
            # Check classification match
            if data_classification and policy.data_classification == data_classification:
                return policy
        
        return None
    
    def check_retention(
        self,
        data_id: str,
        data_type: str,
        created_at: datetime,
        data_classification: Optional[DataClassification] = None
    ) -> Dict[str, Any]:
        """
        Check if data should be retained or deleted.
        
        Args:
            data_id: Data identifier
            data_type: Type of data
            created_at: When data was created
            data_classification: Data classification level
            
        Returns:
            Dictionary with retention decision
        """
        policy = self.get_applicable_policy(data_type, data_classification)
        
        if not policy:
            return {
                'action': 'retain',
                'reason': 'No applicable retention policy',
                'policy_id': None
            }
        
        age_days = (datetime.utcnow() - created_at).days
        
        # Check if should be archived
        if policy.archive_after_days and age_days >= policy.archive_after_days:
            return {
                'action': 'archive',
                'reason': f'Data age ({age_days} days) exceeds archive threshold ({policy.archive_after_days} days)',
                'policy_id': policy.policy_id,
                'policy_name': policy.name,
                'age_days': age_days
            }
        
        # Check if should be deleted
        if age_days >= policy.retention_period_days:
            if policy.auto_delete:
                return {
                    'action': 'delete',
                    'reason': f'Data age ({age_days} days) exceeds retention period ({policy.retention_period_days} days)',
                    'policy_id': policy.policy_id,
                    'policy_name': policy.name,
                    'deletion_method': policy.deletion_method,
                    'age_days': age_days,
                    'auto_delete': True
                }
            else:
                return {
                    'action': 'review',
                    'reason': f'Data age ({age_days} days) exceeds retention period ({policy.retention_period_days} days) - manual review required',
                    'policy_id': policy.policy_id,
                    'policy_name': policy.name,
                    'age_days': age_days,
                    'auto_delete': False
                }
        
        # Retain
        days_until_action = policy.retention_period_days - age_days
        return {
            'action': 'retain',
            'reason': f'Within retention period',
            'policy_id': policy.policy_id,
            'policy_name': policy.name,
            'age_days': age_days,
            'days_until_action': days_until_action
        }
    
    def scan_for_expired_data(
        self,
        data_items: List[Dict[str, Any]]
    ) -> Dict[str, List[Dict[str, Any]]]:
        """
        Scan data items for expired data.
        
        Args:
            data_items: List of data items with 'id', 'type', 'created_at', 'classification'
            
        Returns:
            Dictionary with categorized actions
        """
        results = {
            'delete': [],
            'archive': [],
            'review': [],
            'retain': []
        }
        
        for item in data_items:
            decision = self.check_retention(
                data_id=item.get('id'),
                data_type=item.get('type'),
                created_at=item.get('created_at'),
                data_classification=item.get('classification')
            )
            
            action = decision['action']
            results[action].append({
                'item': item,
                'decision': decision
            })
        
        return results
    
    def execute_retention_action(
        self,
        data_id: str,
        action: str,
        deletion_method: Optional[str] = None,
        executed_by: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Execute retention action.
        
        Args:
            data_id: Data identifier
            action: Action to execute (delete, archive, etc.)
            deletion_method: Method for deletion
            executed_by: User executing action
            
        Returns:
            Action result
        """
        action_record = {
            'data_id': data_id,
            'action': action,
            'deletion_method': deletion_method,
            'executed_by': executed_by,
            'executed_at': datetime.utcnow(),
            'success': True,
            'error': None
        }
        
        try:
            if action == 'delete':
                # In production, this would actually delete the data
                logger.info(f"Deleting data {data_id} using {deletion_method}")
                action_record['details'] = f"Data deleted using {deletion_method}"
            
            elif action == 'archive':
                # In production, this would move data to archive storage
                logger.info(f"Archiving data {data_id}")
                action_record['details'] = "Data archived"
            
            else:
                action_record['success'] = False
                action_record['error'] = f"Unknown action: {action}"
        
        except Exception as e:
            logger.error(f"Failed to execute retention action: {e}")
            action_record['success'] = False
            action_record['error'] = str(e)
        
        self.retention_actions.append(action_record)
        return action_record
    
    def get_retention_report(self) -> Dict[str, Any]:
        """
        Generate retention report.
        
        Returns:
            Report dictionary
        """
        total_policies = len(self.policies)
        active_policies = sum(1 for p in self.policies.values() if p.is_active)
        
        total_actions = len(self.retention_actions)
        successful_actions = sum(1 for a in self.retention_actions if a['success'])
        
        actions_by_type = {}
        for action in self.retention_actions:
            action_type = action['action']
            actions_by_type[action_type] = actions_by_type.get(action_type, 0) + 1
        
        return {
            'total_policies': total_policies,
            'active_policies': active_policies,
            'total_actions': total_actions,
            'successful_actions': successful_actions,
            'failed_actions': total_actions - successful_actions,
            'actions_by_type': actions_by_type,
            'policies': [
                {
                    'policy_id': p.policy_id,
                    'name': p.name,
                    'retention_period_days': p.retention_period_days,
                    'auto_delete': p.auto_delete,
                    'is_active': p.is_active
                }
                for p in self.policies.values()
            ]
        }
    
    def create_default_policies(self) -> List[DataRetentionPolicy]:
        """
        Create default retention policies.
        
        Returns:
            List of default policies
        """
        policies = [
            DataRetentionPolicy(
                policy_id="pol_audit_logs",
                name="Audit Logs Retention",
                description="Retain audit logs for 7 years for compliance",
                data_types=["audit_log"],
                retention_period_days=2555,  # 7 years
                auto_delete=False,
                deletion_method="archive"
            ),
            DataRetentionPolicy(
                policy_id="pol_user_data",
                name="User Data Retention",
                description="Retain user data for 3 years after account closure",
                data_types=["user_profile", "user_settings"],
                retention_period_days=1095,  # 3 years
                auto_delete=True,
                deletion_method="anonymize"
            ),
            DataRetentionPolicy(
                policy_id="pol_reports",
                name="Security Reports Retention",
                description="Retain security reports for 2 years",
                data_types=["security_report", "validation_report"],
                retention_period_days=730,  # 2 years
                archive_after_days=365,  # Archive after 1 year
                auto_delete=False,
                deletion_method="soft_delete"
            ),
            DataRetentionPolicy(
                policy_id="pol_pii",
                name="PII Data Retention",
                description="Retain PII for 1 year, then anonymize",
                data_classification=DataClassification.PII,
                retention_period_days=365,
                auto_delete=True,
                deletion_method="anonymize"
            ),
            DataRetentionPolicy(
                policy_id="pol_temp_data",
                name="Temporary Data Retention",
                description="Delete temporary data after 30 days",
                data_types=["temp_file", "cache", "session"],
                retention_period_days=30,
                auto_delete=True,
                deletion_method="hard_delete"
            )
        ]
        
        for policy in policies:
            self.add_policy(policy)
        
        return policies

