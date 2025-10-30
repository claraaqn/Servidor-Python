from dataclasses import dataclass
from datetime import datetime
from typing import Optional

@dataclass
class User:
    """Modelo representando um usuário do sistema"""
    id: int
    username: str
    password: str
    public_key: str
    salt: str
    created_at: datetime
    is_online: bool = False
    last_seen: Optional[datetime] = None
    
    def to_dict(self):
        """Converte o objeto User para dicionário (sem informações sensíveis)"""
        return {
            'id': self.id,
            'username': self.username,
            'public_key': self.public_key,
            'is_online': self.is_online,
            'last_seen': self.last_seen.isoformat() if self.last_seen else None,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }

@dataclass
class UserStatus:
    """Modelo representando o status de um usuário"""
    user_id: int
    is_online: bool
    last_seen: Optional[datetime]
    
    def to_dict(self):
        """Converte o objeto UserStatus para dicionário"""
        return {
            'user_id': self.user_id,
            'is_online': self.is_online,
            'last_seen': self.last_seen.isoformat() if self.last_seen else None
        }