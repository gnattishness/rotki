import pytest

from rotkehlchen.tests.utils.exchanges import create_test_btcmarkets


@pytest.fixture(scope='session')
def btcmarkets(
        session_inquirer,  # pylint: disable=unused-argument
        messages_aggregator,
        session_database,
):
    return create_test_btcmarkets(
        database=session_database,
        msg_aggregator=messages_aggregator,
    )


@pytest.fixture(scope='function')
def function_scope_btcmarkets(
        inquirer,  # pylint: disable=unused-argument
        function_scope_messages_aggregator,
        database,
):
    return create_test_btcmarkets(
        database=database,
        msg_aggregator=function_scope_messages_aggregator,
    )
