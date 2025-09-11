"""
Memory Store - Tracks historical decisions and learns from user feedback
"""

import json
import sqlite3
import logging
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
from dataclasses import dataclass, asdict
import hashlib

from .agentic_types import AgentDecision, ActionType

logger = logging.getLogger(__name__)

@dataclass
class DecisionRecord:
    """Record of a decision made by the agentic system"""
    id: str
    finding_id: str
    rule_id: str
    file_path: str
    line_number: int
    action: str
    confidence: float
    fp_likelihood: float
    fix_confidence: float
    original_code: str
    suggested_fix: Optional[str]
    explanation: str
    metadata: Dict
    timestamp: str
    user_feedback: Optional[str] = None
    feedback_confidence: Optional[float] = None

@dataclass
class SimilarityMatch:
    """Record of similar findings for learning"""
    finding_id: str
    similarity_score: float
    historical_action: str
    historical_confidence: float

class MemoryStore:
    """
    Persistent memory store for tracking decisions and learning from feedback
    """
    
    def __init__(self, db_path: str = "semio_memory.db"):
        self.db_path = db_path
        self._init_database()
    
    def _init_database(self):
        """Initialize the database with required tables"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Create decisions table
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS decisions (
                        id TEXT PRIMARY KEY,
                        finding_id TEXT NOT NULL,
                        rule_id TEXT NOT NULL,
                        file_path TEXT NOT NULL,
                        line_number INTEGER NOT NULL,
                        action TEXT NOT NULL,
                        confidence REAL NOT NULL,
                        fp_likelihood REAL NOT NULL,
                        fix_confidence REAL NOT NULL,
                        original_code TEXT,
                        suggested_fix TEXT,
                        explanation TEXT,
                        metadata TEXT,
                        timestamp TEXT NOT NULL,
                        user_feedback TEXT,
                        feedback_confidence REAL
                    )
                """)
                
                # Create similarity index
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS similarity_index (
                        finding_hash TEXT PRIMARY KEY,
                        rule_id TEXT NOT NULL,
                        code_hash TEXT NOT NULL,
                        file_pattern TEXT,
                        timestamp TEXT NOT NULL
                    )
                """)
                
                # Create feedback table
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS feedback (
                        id TEXT PRIMARY KEY,
                        decision_id TEXT NOT NULL,
                        feedback_type TEXT NOT NULL,
                        feedback_text TEXT,
                        confidence_adjustment REAL,
                        timestamp TEXT NOT NULL,
                        FOREIGN KEY (decision_id) REFERENCES decisions (id)
                    )
                """)
                
                conn.commit()
                logger.info("Memory store database initialized")
                
        except Exception as e:
            logger.error(f"Failed to initialize memory store: {e}")
    
    def store_decision(self, decision: AgentDecision):
        """Store a decision in the memory store"""
        try:
            record = DecisionRecord(
                id=self._generate_decision_id(decision),
                finding_id=decision.finding_id,
                rule_id=decision.rule_id,
                file_path=decision.file_path,
                line_number=decision.line_number,
                action=decision.action.value,
                confidence=decision.confidence,
                fp_likelihood=decision.fp_likelihood,
                fix_confidence=decision.fix_confidence,
                original_code=decision.original_code,
                suggested_fix=decision.suggested_fix,
                explanation=decision.explanation,
                metadata=decision.metadata,
                timestamp=datetime.now().isoformat()
            )
            
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT OR REPLACE INTO decisions 
                    (id, finding_id, rule_id, file_path, line_number, action, 
                     confidence, fp_likelihood, fix_confidence, original_code, 
                     suggested_fix, explanation, metadata, timestamp)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    record.id, record.finding_id, record.rule_id, record.file_path,
                    record.line_number, record.action, record.confidence,
                    record.fp_likelihood, record.fix_confidence, record.original_code,
                    record.suggested_fix, record.explanation, json.dumps(record.metadata),
                    record.timestamp
                ))
                
                # Update similarity index
                self._update_similarity_index(decision)
                
                conn.commit()
                logger.debug(f"Stored decision: {record.id}")
                
        except Exception as e:
            logger.error(f"Failed to store decision: {e}")
    
    def get_similar_decisions(self, finding: Dict, limit: int = 5) -> List[SimilarityMatch]:
        """Find similar historical decisions"""
        try:
            # Generate finding hash for similarity matching
            finding_hash = self._generate_finding_hash(finding)
            rule_id = finding.get('rule_id', '')
            
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Find similar findings by rule_id and code similarity
                cursor.execute("""
                    SELECT finding_id, action, confidence, timestamp
                    FROM decisions 
                    WHERE rule_id = ? 
                    ORDER BY timestamp DESC 
                    LIMIT ?
                """, (rule_id, limit * 2))  # Get more to filter by similarity
                
                similar_decisions = []
                for row in cursor.fetchall():
                    finding_id, action, confidence, timestamp = row
                    
                    # Calculate similarity score (simplified for now)
                    similarity_score = self._calculate_similarity(finding, finding_id)
                    
                    if similarity_score > 0.5:  # Only include reasonably similar
                        similar_decisions.append(SimilarityMatch(
                            finding_id=finding_id,
                            similarity_score=similarity_score,
                            historical_action=action,
                            historical_confidence=confidence
                        ))
                
                # Sort by similarity and return top matches
                similar_decisions.sort(key=lambda x: x.similarity_score, reverse=True)
                return similar_decisions[:limit]
                
        except Exception as e:
            logger.error(f"Failed to get similar decisions: {e}")
            return []
    
    def add_user_feedback(self, decision_id: str, feedback_type: str, 
                         feedback_text: str = "", confidence_adjustment: float = 0.0):
        """Add user feedback to a decision"""
        try:
            feedback_id = f"{decision_id}_feedback_{datetime.now().timestamp()}"
            
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Add feedback record
                cursor.execute("""
                    INSERT INTO feedback 
                    (id, decision_id, feedback_type, feedback_text, confidence_adjustment, timestamp)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (
                    feedback_id, decision_id, feedback_type, feedback_text,
                    confidence_adjustment, datetime.now().isoformat()
                ))
                
                # Update decision with feedback
                cursor.execute("""
                    UPDATE decisions 
                    SET user_feedback = ?, feedback_confidence = ?
                    WHERE id = ?
                """, (feedback_text, confidence_adjustment, decision_id))
                
                conn.commit()
                logger.info(f"Added feedback for decision {decision_id}: {feedback_type}")
                
        except Exception as e:
            logger.error(f"Failed to add user feedback: {e}")
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get statistics about stored decisions and performance"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Total decisions
                cursor.execute("SELECT COUNT(*) FROM decisions")
                total_decisions = cursor.fetchone()[0]
                
                # Action distribution
                cursor.execute("""
                    SELECT action, COUNT(*) 
                    FROM decisions 
                    GROUP BY action
                """)
                action_distribution = dict(cursor.fetchall())
                
                # Average confidence
                cursor.execute("SELECT AVG(confidence) FROM decisions")
                avg_confidence = cursor.fetchone()[0] or 0.0
                
                # Recent decisions (last 30 days)
                thirty_days_ago = (datetime.now() - timedelta(days=30)).isoformat()
                cursor.execute("""
                    SELECT COUNT(*) 
                    FROM decisions 
                    WHERE timestamp > ?
                """, (thirty_days_ago,))
                recent_decisions = cursor.fetchone()[0]
                
                # Feedback statistics
                cursor.execute("SELECT COUNT(*) FROM feedback")
                total_feedback = cursor.fetchone()[0]
                
                return {
                    'total_decisions': total_decisions,
                    'action_distribution': action_distribution,
                    'average_confidence': round(avg_confidence, 3),
                    'recent_decisions_30d': recent_decisions,
                    'total_feedback': total_feedback,
                    'database_size': self._get_database_size()
                }
                
        except Exception as e:
            logger.error(f"Failed to get statistics: {e}")
            return {
                'total_decisions': 0,
                'action_distribution': {},
                'average_confidence': 0.0,
                'recent_decisions_30d': 0,
                'total_feedback': 0,
                'database_size': 0
            }
    
    def _generate_decision_id(self, decision: AgentDecision) -> str:
        """Generate unique ID for a decision"""
        content = f"{decision.finding_id}_{decision.action.value}_{decision.timestamp}"
        return hashlib.md5(content.encode()).hexdigest()[:16]
    
    def _generate_finding_hash(self, finding: Dict) -> str:
        """Generate hash for finding similarity matching"""
        content = f"{finding.get('rule_id', '')}_{finding.get('code', '')}"
        return hashlib.md5(content.encode()).hexdigest()
    
    def _update_similarity_index(self, decision: AgentDecision):
        """Update similarity index for the decision"""
        try:
            finding_hash = self._generate_finding_hash({
                'rule_id': decision.rule_id,
                'code': decision.original_code
            })
            
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT OR REPLACE INTO similarity_index 
                    (finding_hash, rule_id, code_hash, file_pattern, timestamp)
                    VALUES (?, ?, ?, ?, ?)
                """, (
                    finding_hash, decision.rule_id, 
                    hashlib.md5(decision.original_code.encode()).hexdigest(),
                    decision.file_path.split('/')[-1],  # Just filename pattern
                    datetime.now().isoformat()
                ))
                
        except Exception as e:
            logger.error(f"Failed to update similarity index: {e}")
    
    def _calculate_similarity(self, finding: Dict, historical_finding_id: str) -> float:
        """Calculate similarity between current and historical finding"""
        try:
            # This is a simplified similarity calculation
            # In production, you might use more sophisticated methods like:
            # - Code embedding similarity
            # - AST similarity
            # - Semantic similarity using LLM
            
            # For now, use basic rule_id and code length similarity
            rule_similarity = 1.0 if finding.get('rule_id') == finding.get('rule_id') else 0.0
            
            # Code length similarity (simplified)
            current_code_len = len(finding.get('code', ''))
            # We don't have historical code here, so use a default
            code_similarity = 0.5  # Placeholder
            
            # Weighted combination
            return (rule_similarity * 0.7) + (code_similarity * 0.3)
            
        except Exception as e:
            logger.error(f"Failed to calculate similarity: {e}")
            return 0.0
    
    def _get_database_size(self) -> int:
        """Get database size in bytes"""
        try:
            import os
            return os.path.getsize(self.db_path)
        except Exception:
            return 0
    
    def cleanup_old_records(self, days_to_keep: int = 365):
        """Clean up old decision records"""
        try:
            cutoff_date = (datetime.now() - timedelta(days=days_to_keep)).isoformat()
            
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Delete old decisions
                cursor.execute("""
                    DELETE FROM decisions 
                    WHERE timestamp < ?
                """, (cutoff_date,))
                
                # Delete old similarity index entries
                cursor.execute("""
                    DELETE FROM similarity_index 
                    WHERE timestamp < ?
                """, (cutoff_date,))
                
                # Delete old feedback
                cursor.execute("""
                    DELETE FROM feedback 
                    WHERE timestamp < ?
                """, (cutoff_date,))
                
                conn.commit()
                logger.info(f"Cleaned up records older than {days_to_keep} days")
                
        except Exception as e:
            logger.error(f"Failed to cleanup old records: {e}")
