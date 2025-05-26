from typing import Dict

GDPR_SENSITIVE_DATA: Dict = {
    'personal_data': {
        'patterns': [
            'name', 'address', 'email', 'phone', 'location', 'ip_address', 'cookie',
            'user', 'profile', 'person', 'customer', 'client', 'contact'
        ],
        'risk_level': 'medium'
    },
    'special_categories': {
        'patterns': [
            'health', 'biometric', 'genetic', 'racial', 'ethnic', 'political',
            'religious', 'sexual', 'medical', 'password', 'secret', 'private'
        ],
        'risk_level': 'high'
    },
    'identification': {
        'patterns': [
            'passport', 'ssn', 'id_number', 'drivers_license', 'national_id',
            'tax_id', 'identity', 'social_security', 'birthdate', 'birth_date'
        ],
        'risk_level': 'high'
    },
    'financial': {
        'patterns': [
            'credit_card', 'bank_account', 'iban', 'financial', 'payment',
            'account', 'balance', 'transaction', 'salary', 'income'
        ],
        'risk_level': 'high'
    }
}

# Add this constant to the existing file
GDPR_DB_OPERATIONS = {
    'storage': [
        'save', 'store', 'insert', 'write', 'update', 'create', 'add',
        'put', 'set', 'push', 'upload', 'post', 'execute', 'cursor.execute'
    ],
    'retrieval': [
        'select', 'get', 'fetch', 'read', 'load', 'query', 'find',
        'search', 'retrieve', 'download'
    ]
}

GDPR_REQUIREMENTS: Dict = {
    'consent': {
        'required_patterns': ['consent', 'accept', 'agree', 'permission', 'authorize'],
        'functions': [
            'get_consent', 'check_consent', 'verify_consent', 'has_consent',
            'request_permission', 'validate_consent', 'is_authorized'
        ]
    },
    'data_minimization': {
        'violation_patterns': ['store_all', 'collect_all', 'save_all', '*']
    },
    'retention': {
        'required_patterns': ['retention', 'delete_after', 'expire', 'ttl'],
        'functions': [
            'set_retention', 'delete_expired', 'cleanup_data', 
            'remove_old_data', 'auto_delete'
        ]
    },
    'security': {
        'required_patterns': ['encrypt', 'hash', 'secure', 'protected'],
        'functions': [
            'encrypt_data', 'hash_password', 'secure_data', 'protect_info',
            'ssl', 'tls', 'cryptography'
        ]
    }
}