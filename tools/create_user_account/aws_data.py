from dotmap import DotMap

# can use as dictionary or object with attributes like:
# account_info.dev.name or account_info['dev']['name']

account_info = DotMap({
    'account1': {
        'acct_number': '<account_number>',
        'env': '<env_name>',
        'url': 'https://<specific_account_alias>.signin.aws.amazon.com/console',
        'iam_default_groups': ['<group1>', '<group2>']
    },
	'account2': {
        'acct_number': '<account_number>',
        'env': '<env_name>',
        'url': 'https://<specific_account_alias>.signin.aws.amazon.com/console',
        'iam_default_groups': ['<group1>', '<group4>']
    },
    'account3': {
        'acct_number': '<account_number>',
        'env': '<env_name>',
        'url': 'https://<specific_account_alias>.signin.aws.amazon.com/console',
        'iam_default_groups': ['<group1>', '<group2>','<group4>']
    }
})