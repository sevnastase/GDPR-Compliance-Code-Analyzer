from typing import Dict, List, Set

GDPR_SENSITIVE_DATA: Dict = {
    'personal_data': {
        'patterns': [
            'name', 'address', 'email', 'phone', 'location', 'ip_address', 'cookie',
            'user', 'profile', 'person', 'customer', 'client', 'contact', 'birthday',
            'age', 'gender', 'postal', 'zip_code', 'social_media', 'photo', 'image'
        ],
        'risk_level': 'medium'
    },
    'special_categories': {
        'patterns': [
            'health', 'biometric', 'genetic', 'racial', 'ethnic', 'political',
            'religious', 'sexual', 'medical', 'password', 'secret', 'private',
            'disability', 'mental_health', 'blood_type', 'dna', 'fingerprint',
            'retina', 'criminal', 'offense', 'union_membership'
        ],
        'risk_level': 'high'
    },
    'identification': {
        'patterns': [
            'passport', 'ssn', 'id_number', 'drivers_license', 'national_id',
            'tax_id', 'identity', 'social_security', 'birthdate', 'birth_date',
            'license_number', 'vehicle_id', 'plate_number', 'insurance_number'
        ],
        'risk_level': 'high'
    },
    'financial': {
        'patterns': [
            'credit_card', 'bank_account', 'iban', 'financial', 'payment',
            'account', 'balance', 'transaction', 'salary', 'income', 'tax',
            'pension', 'loan', 'debt', 'cvv', 'expiry_date', 'swift', 'routing'
        ],
        'risk_level': 'high'
    }
}

GDPR_REQUIREMENTS: Dict = {
    'consent': {
        'required_patterns': [
            'consent', 'accept', 'agree', 'permission', 'authorize', 'opt_in',
            'gdpr_consent', 'data_processing_agreement'
        ],
        'functions': [
            'get_consent', 'check_consent', 'verify_consent', 'has_consent',
            'request_permission', 'validate_consent', 'is_authorized',
            'opt_in_status', 'can_process_data', 'user_agreed'
        ],
        'required_documentation': [
            'purpose_of_processing',
            'type_of_data_collected',
            'retention_period',
            'user_rights'
        ]
    },
    'data_minimization': {
        'violation_patterns': [
            'store_all', 'collect_all', 'save_all', '*', 'everything',
            'full_data', 'complete_profile'
        ],
        'required_patterns': [
            'minimize', 'essential_only', 'required_fields',
            'minimal_data', 'data_limit'
        ]
    },
    'retention': {
        'required_patterns': [
            'retention', 'delete_after', 'expire', 'ttl', 'auto_delete',
            'data_lifetime', 'storage_period'
        ],
        'functions': [
            'set_retention', 'delete_expired', 'cleanup_data', 
            'remove_old_data', 'auto_delete', 'schedule_deletion'
        ]
    },
    'security': {
        'required_patterns': [
            'encrypt', 'hash', 'secure', 'protected', 'ssl', 'tls',
            'cipher', 'salt', 'key', 'certificate'
        ],
        'functions': [
            'encrypt_data', 'hash_password', 'secure_data', 'protect_info',
            'ssl_encrypt', 'tls_protect', 'apply_encryption'
        ],
        'required_measures': [
            'encryption_at_rest',
            'encryption_in_transit',
            'access_control',
            'audit_logging'
        ]
    },
    'user_rights': {
        'required_functions': [
            'export_data', 'delete_account', 'update_info', 'get_user_data',
            'forget_user', 'data_portability', 'access_rights'
        ],
        'patterns': [
            'right_to_access',
            'right_to_rectification',
            'right_to_erasure',
            'right_to_portability'
        ]
    }
}

GDPR_DB_OPERATIONS: Dict = {
    'storage': [
        'save', 'store', 'insert', 'write', 'update', 'create', 'add',
        'put', 'set', 'push', 'upload', 'post', 'execute', 'cursor.execute',
        'bulk_insert', 'upsert', 'persist', 'commit'
    ],
    'retrieval': [
        'select', 'get', 'fetch', 'read', 'load', 'query', 'find',
        'search', 'retrieve', 'download', 'cursor.fetchall', 'cursor.fetchone'
    ],
    'deletion': [
        'delete', 'remove', 'drop', 'truncate', 'clear', 'purge',
        'forget', 'erase', 'destroy'
    ],
    'sensitive_operations': [
        'bulk_collect', 'mass_update', 'full_scan', 'dump',
        'backup', 'replicate', 'transfer'
    ]
}

COMMON_FRAMEWORKS: Dict[str, List[str]] = {
    'django': [
        'Model.objects.create',
        'Model.objects.get',
        'Model.objects.filter',
        'request.POST.get',
        'request.GET.get'
    ],
    'flask': [
        'request.form.get',
        'request.args.get',
        'session',
        'jsonify'
    ],
    'sqlalchemy': [
        'session.add',
        'session.query',
        'session.commit',
        'execute'
    ],
    'pymongo': [
        'insert_one',
        'insert_many',
        'find_one',
        'find',
        'update_one'
    ]
}

DATA_TRANSFER_PATTERNS: Set[str] = {
    'send_email',
    'http.post',
    'requests.post',
    'ftp.put',
    'transfer_data',
    'share_data',
    'export_data',
    'upload',
    'transmit',
    'send_file',
    'send_data',
    'api.send',
    'api.post',
    'socket.send',
    'urllib.request',
    'transfer'
}