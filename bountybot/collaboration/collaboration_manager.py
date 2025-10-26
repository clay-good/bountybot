"""
Collaboration manager for comments, mentions, and team communication.
"""

import re
from datetime import datetime
from typing import Dict, List, Optional, Any
from bountybot.collaboration.models import (
    Comment,
    Mention,
    Notification,
    NotificationType,
    NotificationStatus,
)


class MentionParser:
    """
    Parse @mentions from text content.
    
    Example:
        >>> parser = MentionParser()
        >>> mentions = parser.parse_mentions("Hey @john, can you review this? cc @sarah")
        >>> print(mentions)  # ['john', 'sarah']
    """
    
    # Pattern to match @username (alphanumeric, underscore, hyphen, dot)
    MENTION_PATTERN = r'@([a-zA-Z0-9_\-\.]+)'
    
    @classmethod
    def parse_mentions(cls, content: str) -> List[str]:
        """Parse @mentions from content."""
        matches = re.findall(cls.MENTION_PATTERN, content)
        return list(set(matches))  # Remove duplicates
    
    @classmethod
    def highlight_mentions(cls, content: str) -> str:
        """Highlight mentions in content (for HTML rendering)."""
        def replace_mention(match) -> str:
            """Replace mention with HTML span."""
            username = match.group(1)
            return f'<span class="mention">@{username}</span>'

        return re.sub(cls.MENTION_PATTERN, replace_mention, content)


class CollaborationManager:
    """
    Manage comments, mentions, and team collaboration.
    
    Example:
        >>> manager = CollaborationManager()
        >>> 
        >>> # Add comment with mentions
        >>> comment = manager.add_comment(
        ...     entity_type="report",
        ...     entity_id="report-123",
        ...     user_id="analyst@acme.com",
        ...     user_name="Alice Analyst",
        ...     content="This looks critical. @bob can you verify? @charlie for approval"
        ... )
        >>> 
        >>> # Get comments
        >>> comments = manager.get_comments("report", "report-123")
        >>> 
        >>> # Reply to comment
        >>> reply = manager.add_comment(
        ...     entity_type="report",
        ...     entity_id="report-123",
        ...     user_id="bob@acme.com",
        ...     user_name="Bob Security",
        ...     content="Verified. This is a SQL injection.",
        ...     parent_comment_id=comment.comment_id
        ... )
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize collaboration manager."""
        self.config = config or {}
        self.comments: Dict[str, Comment] = {}
        self.mentions: Dict[str, Mention] = {}
        self.notifications: Dict[str, Notification] = {}
        self.mention_parser = MentionParser()
    
    def add_comment(
        self,
        entity_type: str,
        entity_id: str,
        user_id: str,
        user_name: str,
        content: str,
        parent_comment_id: Optional[str] = None,
        attachments: Optional[List[Dict[str, str]]] = None
    ) -> Comment:
        """Add a comment to an entity."""
        # Parse mentions
        mentioned_usernames = self.mention_parser.parse_mentions(content)
        
        comment = Comment(
            entity_type=entity_type,
            entity_id=entity_id,
            user_id=user_id,
            user_name=user_name,
            content=content,
            parent_comment_id=parent_comment_id,
            mentions=mentioned_usernames,
            attachments=attachments or []
        )
        
        self.comments[comment.comment_id] = comment
        
        # Create mentions
        for username in mentioned_usernames:
            mention = Mention(
                mentioned_user_id=username,
                mentioned_by_user_id=user_id,
                entity_type=entity_type,
                entity_id=entity_id,
                comment_id=comment.comment_id
            )
            self.mentions[mention.mention_id] = mention
            
            # Create notification for mentioned user
            self._create_notification(
                user_id=username,
                notification_type=NotificationType.MENTION,
                title=f"{user_name} mentioned you",
                message=f"{user_name} mentioned you in a comment: {content[:100]}...",
                entity_type=entity_type,
                entity_id=entity_id
            )
        
        # If this is a reply, notify the parent comment author
        if parent_comment_id:
            parent_comment = self.comments.get(parent_comment_id)
            if parent_comment and parent_comment.user_id != user_id:
                self._create_notification(
                    user_id=parent_comment.user_id,
                    notification_type=NotificationType.COMMENT_REPLY,
                    title=f"{user_name} replied to your comment",
                    message=f"{user_name} replied: {content[:100]}...",
                    entity_type=entity_type,
                    entity_id=entity_id
                )
        
        return comment
    
    def update_comment(
        self,
        comment_id: str,
        content: str,
        user_id: str
    ) -> Comment:
        """Update a comment."""
        comment = self.comments.get(comment_id)
        if not comment:
            raise ValueError(f"Comment not found: {comment_id}")
        
        if comment.user_id != user_id:
            raise PermissionError("Only the comment author can edit the comment")
        
        comment.content = content
        comment.updated_at = datetime.utcnow()
        comment.edited = True
        
        # Re-parse mentions
        comment.mentions = self.mention_parser.parse_mentions(content)
        
        return comment
    
    def delete_comment(self, comment_id: str, user_id: str) -> bool:
        """Delete a comment."""
        comment = self.comments.get(comment_id)
        if not comment:
            raise ValueError(f"Comment not found: {comment_id}")
        
        if comment.user_id != user_id:
            raise PermissionError("Only the comment author can delete the comment")
        
        del self.comments[comment_id]
        return True
    
    def get_comments(
        self,
        entity_type: str,
        entity_id: str,
        include_replies: bool = True
    ) -> List[Comment]:
        """Get all comments for an entity."""
        comments = [
            comment for comment in self.comments.values()
            if comment.entity_type == entity_type and comment.entity_id == entity_id
        ]
        
        if not include_replies:
            comments = [c for c in comments if c.parent_comment_id is None]
        
        # Sort by creation time
        comments.sort(key=lambda c: c.created_at)
        return comments
    
    def get_comment_thread(self, comment_id: str) -> List[Comment]:
        """Get a comment and all its replies."""
        comment = self.comments.get(comment_id)
        if not comment:
            raise ValueError(f"Comment not found: {comment_id}")
        
        # Get all replies
        replies = [
            c for c in self.comments.values()
            if c.parent_comment_id == comment_id
        ]
        
        # Sort by creation time
        replies.sort(key=lambda c: c.created_at)
        
        return [comment] + replies
    
    def add_reaction(
        self,
        comment_id: str,
        user_id: str,
        emoji: str
    ) -> Comment:
        """Add a reaction to a comment."""
        comment = self.comments.get(comment_id)
        if not comment:
            raise ValueError(f"Comment not found: {comment_id}")
        
        if emoji not in comment.reactions:
            comment.reactions[emoji] = []
        
        if user_id not in comment.reactions[emoji]:
            comment.reactions[emoji].append(user_id)
        
        return comment
    
    def remove_reaction(
        self,
        comment_id: str,
        user_id: str,
        emoji: str
    ) -> Comment:
        """Remove a reaction from a comment."""
        comment = self.comments.get(comment_id)
        if not comment:
            raise ValueError(f"Comment not found: {comment_id}")
        
        if emoji in comment.reactions and user_id in comment.reactions[emoji]:
            comment.reactions[emoji].remove(user_id)
            
            # Remove emoji key if no more reactions
            if not comment.reactions[emoji]:
                del comment.reactions[emoji]
        
        return comment
    
    def get_user_mentions(
        self,
        user_id: str,
        unread_only: bool = False
    ) -> List[Mention]:
        """Get all mentions for a user."""
        mentions = [
            mention for mention in self.mentions.values()
            if mention.mentioned_user_id == user_id
        ]
        
        if unread_only:
            mentions = [m for m in mentions if not m.read]
        
        # Sort by creation time (newest first)
        mentions.sort(key=lambda m: m.created_at, reverse=True)
        return mentions
    
    def mark_mention_read(self, mention_id: str) -> Mention:
        """Mark a mention as read."""
        mention = self.mentions.get(mention_id)
        if not mention:
            raise ValueError(f"Mention not found: {mention_id}")
        
        mention.read = True
        mention.read_at = datetime.utcnow()
        return mention
    
    def _create_notification(
        self,
        user_id: str,
        notification_type: NotificationType,
        title: str,
        message: str,
        entity_type: Optional[str] = None,
        entity_id: Optional[str] = None,
        action_url: Optional[str] = None
    ) -> Notification:
        """Create a notification for a user."""
        notification = Notification(
            user_id=user_id,
            notification_type=notification_type,
            title=title,
            message=message,
            entity_type=entity_type,
            entity_id=entity_id,
            action_url=action_url
        )
        
        self.notifications[notification.notification_id] = notification
        return notification
    
    def get_user_notifications(
        self,
        user_id: str,
        status: Optional[NotificationStatus] = None,
        limit: int = 50
    ) -> List[Notification]:
        """Get notifications for a user."""
        notifications = [
            notif for notif in self.notifications.values()
            if notif.user_id == user_id
        ]
        
        if status:
            notifications = [n for n in notifications if n.status == status]
        
        # Sort by creation time (newest first)
        notifications.sort(key=lambda n: n.created_at, reverse=True)
        
        return notifications[:limit]
    
    def mark_notification_read(self, notification_id: str) -> Notification:
        """Mark a notification as read."""
        notification = self.notifications.get(notification_id)
        if not notification:
            raise ValueError(f"Notification not found: {notification_id}")
        
        notification.status = NotificationStatus.READ
        notification.read_at = datetime.utcnow()
        return notification
    
    def mark_all_notifications_read(self, user_id: str) -> int:
        """Mark all notifications as read for a user."""
        count = 0
        for notification in self.notifications.values():
            if notification.user_id == user_id and notification.status == NotificationStatus.UNREAD:
                notification.status = NotificationStatus.READ
                notification.read_at = datetime.utcnow()
                count += 1
        
        return count

