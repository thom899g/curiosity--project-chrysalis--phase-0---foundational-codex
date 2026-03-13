"""
Secure Intent Execution Engine - KERNEL Component
Minimal, provably secure execution of signed intents (Manifests)
Design: Microkernel architecture - ONLY executes, NEVER decides
"""

import hashlib
import json
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Tuple
import logging
from dataclasses import dataclass, asdict
import firebase_admin
from firebase_admin import firestore, credentials
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
import base64

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@dataclass
class IntentManifest:
    """Signed, versioned intent specification with cryptographic verification"""
    
    # Required fields for execution
    manifest_id: str
    action_type: str  # 'PROCUREMENT', 'DEPLOYMENT', 'TRAINING', 'RESEARCH'
    parameters: Dict[str, Any]
    max_budget: float
    conditions: Dict[str, Any]  # Success criteria and constraints
    proposer_signature: str  # Base64 encoded signature
    nonce: int  # Anti-replay protection
    
    # System fields (auto-populated)
    timestamp: Optional[str] = None
    version: str = "1.0.0"
    status: str = "PENDING"  # PENDING, EXECUTING, COMPLETED, FAILED, ROLLED_BACK
    execution_index: int = 0  # Increments on retry
    circuit_breaker_state: Dict[str, Any] = None
    rollback_plan: Optional[Dict[str, Any]] = None
    
    def __post_init__(self):
        """Initialize computed fields after dataclass creation"""
        if self.timestamp is None:
            self.timestamp = datetime.now(timezone.utc).isoformat()
        if self.circuit_breaker_state is None:
            self.circuit_breaker_state = {
                "budget_consumed": 0.0,
                "execution_count": 0,
                "last_execution": None,
                "tripped_at": []
            }
        if self.rollback_plan is None:
            self.rollback_plan = self._generate_rollback_plan()
    
    def _generate_rollback_plan(self) -> Dict[str, Any]:
        """Generate automatic rollback plan based on action type"""
        rollback_actions = []
        
        # Generate rollback steps based on action type
        if self.action_type == "PROCUREMENT":
            rollback_actions = [
                {"action": "CANCEL_ORDER", "condition": "order_placed == true"},
                {"action": "REFUND_REQUEST", "condition": "payment_processed == true"},
                {"action": "UPDATE_INVENTORY", "condition": "item_received == true"}
            ]
        elif self.action_type == "DEPLOYMENT":
            rollback_actions = [
                {"action": "TERMINATE_INSTANCE", "condition": "instance_running == true"},
                {"action": "DELETE_RESOURCES", "condition": "resources_created == true"},
                {"action": "RESTORE_BACKUP", "condition": "data_modified == true"}
            ]
        
        return {
            "actions": rollback_actions,
            "max_rollback_budget": self.max_budget * 0.3,  # 30% of original budget
            "timeout_seconds": 3600  # 1 hour to complete rollback
        }
    
    def verify_signature(self, public_key_pem: str) -> bool:
        """Cryptographically verify the proposer's signature"""
        try:
            # Load public key
            public_key = serialization.load_pem_public_key(
                public_key_pem.encode('utf-8')
            )
            
            # Create the message that was signed (exclude signature itself)
            message_dict = {
                "manifest_id": self.manifest_id,
                "action_type": self.action_type,
                "parameters": self.parameters,
                "max_budget": self.max_budget,
                "conditions": self.conditions,
                "nonce": self.nonce,
                "timestamp": self.timestamp,
                "version": self.version
            }
            
            message_json = json.dumps(message_dict, sort_keys=True)
            message_bytes = message_json.encode('utf-8')
            
            # Verify signature
            signature = base64.b64decode(self.proposer_signature)
            
            public_key.verify(
                signature,
                message_bytes,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            
            logger.info(f"Signature verified for manifest {self.manifest_id}")
            return True
            
        except Exception as e:
            logger.error(f"Signature verification failed for {self.manifest_id}: {e}")
            return False
    
    def calculate_hash(self) -> str:
        """Calculate SHA-256 hash of the manifest for integrity checking"""
        manifest_dict = asdict(self)
        manifest_dict.pop('proposer_signature', None)  # Exclude signature from hash
        
        manifest_json = json.dumps(manifest_dict, sort_keys=True)
        return hashlib.sha256(manifest_json.encode('utf-8')).hexdigest()
    
    def check_circuit_breaker(self, current_cost: float) -> Dict[str, Any]:
        """Check if circuit breaker should trip based on budget consumption"""
        consumption_percentage = (current_cost / self.max_budget) * 100
        
        if consumption_percentage >= 95:
            level = "CRITICAL"
            action = "IMMEDIATE_HALT"
        elif consumption_percentage >= 80:
            level = "HIGH"
            action = "HALT_NEW_EXECUTIONS"
        elif consumption_percentage >= 50:
            level = "MEDIUM"
            action = "REDUCE_CONCURRENCY"
        else:
            level = "NORMAL"
            action = "CONTINUE"
        
        # Check execution velocity (anti-DoS)
        current_time = datetime.now(timezone.utc)
        if self.circuit_breaker_state["last_execution"]:
            last_exec = datetime.fromisoformat(self.circuit_breaker_state["last_execution"])
            time_diff = (current_time - last_exec).total_seconds()
            
            if time_diff < 60 and self.circuit_breaker_state["execution_count"] > 10:
                level = "CRITICAL"
                action = "IMMEDIATE_HALT"
                logger.warning(f"Execution velocity too high for {self.manifest_id}")
        
        return {
            "level": level,
            "action": action,
            "consumption_percentage": consumption_percentage,
            "current_cost": current_cost
        }
    
    def to_firestore(self) -> Dict[str, Any]:
        """Convert to Firestore-compatible document with proper typing"""
        document = {
            'manifest_id': self.manifest_id,
            'action_type': self.action_type,
            'parameters': json.dumps(self.parameters),  # JSON string for nested dicts
            'max_budget': self.max_budget,
            'conditions': json.dumps(self.conditions),
            'proposer_signature': self.proposer_signature,
            'nonce': self.nonce,
            'timestamp': self.timestamp,
            'version': self.version,
            'status': self.status,
            'execution_index': self.execution_index,
            'circuit_breaker_state': json.dumps(self.circuit_breaker_state),
            'rollback_plan': json.dumps(self.rollback_plan) if self.rollback_plan else None,
            'manifest_hash': self.calculate_hash(),
            '_system_metadata': {
                'created_at': datetime.now(timezone.utc).isoformat(),
                'updated_at': datetime.now(timezone.utc).isoformat(),
                'firestore_collection': 'intent_manifests'
            }
        }
        
        # Validate no None values in required fields
        for key, value in document.items():
            if value is None and key not in ['rollback_plan']:
                logger.warning(f"Document field {key} is None for manifest {self.manifest_id}")
        
        return document
    
    @classmethod
    def from_firestore(cls, doc_data: Dict[str, Any]) -> 'IntentManifest':
        """Create IntentManifest from Firestore document"""
        try:
            # Parse JSON strings back to dicts
            parameters = json.loads(doc_data.get('parameters', '{}'))
            conditions = json.loads(doc_data.get('conditions', '{}'))
            circuit_breaker_state = json.loads(doc_data.get('circuit_breaker_state', '{}'))
            rollback_plan = json.loads(doc_data.get('rollback_plan', 'null')) if doc_data.get('rollback_plan') else None
            
            return cls(
                manifest_id=doc_data['manifest_id'],
                action_type=doc_data['action_type'],
                parameters=parameters,
                max_budget=doc_data['max_budget'],
                conditions=conditions,
                proposer_signature=doc_data['proposer_signature'],
                nonce=doc_data['nonce'],
                timestamp=doc_data.get('timestamp'),
                status=doc_data.get('status', 'PENDING'),
                execution_index=doc_data.get('execution_index', 0),
                circuit_breaker_state=circuit_breaker_state,
                rollback_plan=rollback_plan
            )
        except (json.JSONDecodeError, KeyError) as e:
            logger.error(f"Error parsing Firestore document: {e}")
            raise ValueError(f"Invalid Firestore document data: {e}")


class KernelExecutor:
    """Secure execution engine for Intent Manifests"""
    
    def __init__(self, firestore_client=None, public_key_pem: Optional[str] = None):
        """Initialize Kernel with Firestore client and verification key"""
        self.firestore_client = firestore_client or self._initialize_firestore()
        self.public_key_pem = public_key_pem
        
        # Execution state
        self.active_executions = set()
        self.completed_executions = {}
        self.failed_executions = {}
        
        # Circuit breaker registry
        self.circuit_breakers = {}  # manifest_id -> breaker_state
        
        logger.info("Kernel Executor initialized")
    
    def _initialize_firestore(self):
        """Initialize Firebase Admin SDK with error handling"""
        try:
            # Check if Firebase app already initialized
            if not firebase_admin._apps:
                # For production, use environment variable for service account
                import os
                from pathlib import Path
                
                # Try to find service account key
                key_path = os.getenv('GOOGLE_APPLICATION_CREDENTIALS')
                if key_path and Path(key_path).exists():
                    cred = credentials.Certificate(key_path)
                else:
                    # Try default location or use emulator
                    logger.warning("Using Firebase emulator or default credentials")
                    cred = credentials.ApplicationDefault()
                
                firebase_admin.initialize_app(cred)
            
            return firestore.client()
            
        except Exception as e:
            logger.error(f"Firebase initialization failed: {e}")
            # Fallback to dictionary storage for development
            logger.info("Using in-memory storage (Firebase unavailable)")
            return None
    
    def execute_intent(self, manifest: IntentManifest) -> Dict[str, Any]:
        """Execute an intent manifest with full safety checks"""
        try:
            # 1. Validate manifest
            validation_result = self._validate_manifest(manifest)
            if not validation_result["valid"]:
                return {
                    "success": False,
                    "error": f"Manifest validation failed: {validation_result['reason']}",
                    "manifest_id": manifest.manifest_id
                }
            
            # 2. Check circuit breaker
            breaker_check = manifest.check_circuit_breaker(
                manifest.circuit_breaker_state["budget_consumed"]
            )
            
            if breaker_check["action"] in ["IMMEDIATE_HALT", "HALT_NEW_EXECUTIONS"]:
                logger.warning(f"Circuit breaker tripped: {breaker_check}")
                return {
                    "success": False,
                    "error": f"Circuit breaker {breaker_check['level']}: {breaker_check['action']}",
                    "manifest_id": manifest.manifest_id,
                    "circuit_breaker": breaker_check
                }
            
            # 3. Reserve execution slot
            execution_id = f"{manifest.manifest_id}_{manifest.execution_index}"
            if execution_id in self.active_executions:
                return {
                    "success": False,
                    "error": "Execution already in progress",
                    "manifest_id": manifest.manifest_id
                }
            
            self.active_executions.add(execution_id)
            
            try:
                # 4. Create execution record
                execution_record = self._create_execution_record(manifest, execution_id)
                
                # 5. Execute based on action type
                execution_result = self._execute_action(manifest, execution_record)
                
                # 6. Update state
                manifest.status = "COMPLETED" if execution_result["success"] else "FAILED"
                manifest.circuit_breaker_state["execution_count"] += 1
                manifest.circuit_breaker_state["last_execution"] = datetime.now(timezone.utc).isoformat()
                manifest.circuit_breaker_state["budget_consumed"] += execution_result.get("actual_cost", 0)
                
                # 7. Store proof of execution
                proof_of_execution = self._generate_proof_of_execution(
                    manifest, execution_result, execution_record
                )
                
                # 8. Store in Firestore
                if self.firestore_client:
                    self._store_execution_result(
                        manifest, execution_result, proof_of_execution
                    )
                
                return {
                    "success": execution_result["success"],
                    "execution_id": execution_id,
                    "result": execution_result,
                    "proof_of_execution": proof_of_exec