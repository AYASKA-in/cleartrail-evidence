from unittest.mock import patch

from cleartrail.deployment_checks import validate_providers
from test_hosted import setup as setup


def test_missing_provider_setup_is_blocked_without_any_external_call(setup):
    with patch('cleartrail.deployment_checks.run_isolated_collection') as collect:
        result=validate_providers(setup[1],setup[2])
    assert not result['provider_validation_complete'] and not collect.called
    assert {value['code'] for value in result['providers'].values()}=={'not_configured'}


def test_provider_errors_and_secrets_are_not_copied_into_live_report(setup):
    repo,tenant=setup[1:3]
    repo.set_integration(tenant,'alice','github',{'enabled':True,'org':'example','expected_repositories':['app']},{'token':'synthetic-token-do-not-print'})
    with patch('cleartrail.deployment_checks.run_isolated_collection',side_effect=RuntimeError('synthetic-token-do-not-print')):
        result=validate_providers(repo,tenant)
    assert result['providers']['github']['status']=='failed'
    assert 'synthetic-token-do-not-print' not in str(result)
