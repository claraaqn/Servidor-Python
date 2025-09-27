import json
from datetime import datetime, date
from decimal import Decimal

class DateTimeEncoder(json.JSONEncoder):
    """Encoder personalizado para serializar objetos datetime e decimal"""
    def default(self, obj):
        if isinstance(obj, (datetime, date)):
            return obj.isoformat()
        elif isinstance(obj, Decimal):
            return float(obj)
        elif hasattr(obj, '__dict__'):
            return obj.__dict__
        return super().default(obj)

def serialize_data(data):
    """Converte objetos para formato serializável em JSON"""
    if isinstance(data, dict):
        return {k: serialize_data(v) for k, v in data.items()}
    elif isinstance(data, list):
        return [serialize_data(item) for item in data]
    elif isinstance(data, (datetime, date)):
        return data.isoformat()
    elif isinstance(data, Decimal):
        return float(data)
    elif hasattr(data, 'isoformat'):  # Para outros objetos com isoformat
        return data.isoformat()
    elif hasattr(data, 'to_dict'):  # Para objetos com método to_dict
        return data.to_dict()
    else:
        return data

def create_response(success, message, data=None):
    """Cria resposta padronizada"""
    response = {
        'success': success,
        'message': message,
    }
    if data:
        response['data'] = serialize_data(data)
    return response