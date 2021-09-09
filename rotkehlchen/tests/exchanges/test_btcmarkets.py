import warnings as test_warnings
from unittest.mock import patch
import os
import base64

import pytest

from rotkehlchen.accounting.structures import Balance
from rotkehlchen.constants.assets import A_AUD, A_ETC, A_ETH
from rotkehlchen.errors import UnknownAsset
from rotkehlchen.exchanges.data_structures import Location, Trade, TradeType
from rotkehlchen.exchanges.btcmarkets import (
    BTCMarkets,
)
from rotkehlchen.assets.converters import asset_from_btc_markets
from rotkehlchen.fval import FVal
from rotkehlchen.tests.utils.mock import MockResponse

import time


def test_location():
    exchange = BTCMarkets('btcmarkets1', 'a', b'a', object(), object())
    assert exchange.location == Location.BTCMARKETS
    assert exchange.name == 'btcmarkets1'


def test_assets_are_known():
    # TODO Why this over the fixture?
    exchange = BTCMarkets('btcmarkets1', 'a', b'a', object(), object())
    data, raw_response = exchange._api_query('GET', 'assets')
    for entry in data:
        # if this raises a keyError, we have an unexpected/malformed response
        name = entry["assetName"]
        try:
            asset_from_btc_markets(name)
        except UnknownAsset:
            test_warnings.warn(UserWarning(
                f'Found unknown asset {name} in BTC Markets. '
                f'Support for it has to be added',
            ))


@pytest.mark.parametrize('should_mock_current_price_queries', [True])
def test_query_balances(
        function_scope_btcmarkets,
        inquirer,  # pylint: disable=unused-argument
):
    """Test all balances returned by IndependentReserve are proccessed properly"""
    exchange = function_scope_btcmarkets

    def mock_api_return(method, url, **kwargs):    # pylint: disable=unused-argument
        assert method == 'GET'
        response = """[{"assetName": "AUD", "balance": "150.55", "available": "112.45", "locked": "38.10"},
        {"assetName": "BTC", "balance": "150.55", "available": "112.45", "locked": "38.10"},
        {"assetName": "LTC", "balance": "150.55", "available": "112.45", "locked": "38.10"},
        {"assetName": "ETH", "balance": "150.55", "available": "112.45", "locked": "38.10"},
        {"assetName": "XRP", "balance": "150.55", "available": "112.45", "locked": "38.10"},
        {"assetName": "ETC", "balance": "150.55", "available": "112.45", "locked": "38.10"},
        {"assetName": "POWR", "balance": "150.55", "available": "112.45", "locked": "38.10"},
        {"assetName": "OMG", "balance": "150.55", "available": "112.45", "locked": "38.10"},
        {"assetName": "BCH", "balance": "150.55", "available": "112.45", "locked": "38.10"},
        {"assetName": "BSV", "balance": "150.55", "available": "112.45", "locked": "38.10"},
        {"assetName": "GNT", "balance": "150.55", "available": "112.45", "locked": "38.10"},
        {"assetName": "BAT", "balance": "150.55", "available": "112.45", "locked": "38.10"},
        {"assetName": "XLM", "balance": "150.55", "available": "112.45", "locked": "38.10"},
        {"assetName": "ENJ", "balance": "150.55", "available": "112.45", "locked": "38.10"},
        {"assetName": "LINK", "balance": "150.55", "available": "112.45", "locked": "38.10"},
        {"assetName": "COMP", "balance": "150.55", "available": "112.45", "locked": "38.10"},
        {"assetName": "ALGO", "balance": "150.55", "available": "112.45", "locked": "38.10"},
        {"assetName": "MCAU", "balance": "150.55", "available": "112.45", "locked": "38.10"},
        {"assetName": "USDT", "balance": "150.55", "available": "112.45", "locked": "38.10"}]
        """
        return MockResponse(200, response)

    with patch.object(exchange.session, 'request', side_effect=mock_api_return):
        balances, msg = exchange.query_balances()

    assert msg == ''
    assets_seen = set()
    for asset, balance in balances.items():
        assert asset not in assets_seen
        assets_seen.add(asset)
        assert balance.amount == FVal('150.55')

#
#@pytest.mark.parametrize('should_mock_current_price_queries', [True])
#def test_query_some_balances(
#        function_scope_independentreserve,
#        inquirer,  # pylint: disable=unused-argument
#):
#    """Just like test_query_balances but make sure 0 balances are skipped"""
#    exchange = function_scope_independentreserve
#
#    def mock_api_return(method, url, **kwargs):    # pylint: disable=unused-argument
#        assert method == 'post'
#        response = """[{"AccountGuid": "foo", "AccountStatus": "Active", "AvailableBalance": 1.2, "CurrencyCode": "Aud", "TotalBalance": 2.5},
#{"AccountGuid": "foo", "AccountStatus": "Active", "AvailableBalance": 0.0, "CurrencyCode": "Usd", "TotalBalance": 0.0},
#{"AccountGuid": "foo", "AccountStatus": "Active", "AvailableBalance": 0.0, "CurrencyCode": "Nzd", "TotalBalance": 0.0},
#{"AccountGuid": "foo", "AccountStatus": "Active", "AvailableBalance": 0.0, "CurrencyCode": "Sgd", "TotalBalance": 0.0},
#{"AccountGuid": "foo", "AccountStatus": "Active", "AvailableBalance": 0.0, "CurrencyCode": "Xbt", "TotalBalance": 0.0},
#{"AccountGuid": "foo", "AccountStatus": "Active", "AvailableBalance": 0.0, "CurrencyCode": "Eth", "TotalBalance": 0.0},
#{"AccountGuid": "foo", "AccountStatus": "Active", "AvailableBalance": 0.0, "CurrencyCode": "Xrp", "TotalBalance": 0.0},
#{"AccountGuid": "foo", "AccountStatus": "Active", "AvailableBalance": 0.0, "CurrencyCode": "Ada", "TotalBalance": 0.0},
#{"AccountGuid": "foo", "AccountStatus": "Active", "AvailableBalance": 0.0, "CurrencyCode": "Dot", "TotalBalance": 0.0},
#{"AccountGuid": "foo", "AccountStatus": "Active", "AvailableBalance": 0.0, "CurrencyCode": "Uni", "TotalBalance": 0.0},
#{"AccountGuid": "foo", "AccountStatus": "Active", "AvailableBalance": 0.0, "CurrencyCode": "Link", "TotalBalance": 0.0},
#{"AccountGuid": "foo", "AccountStatus": "Active", "AvailableBalance": 0.0, "CurrencyCode": "Usdt", "TotalBalance": 0.0},
#{"AccountGuid": "foo", "AccountStatus": "Active", "AvailableBalance": 0.0, "CurrencyCode": "Usdc", "TotalBalance": 0.0},
#{"AccountGuid": "foo", "AccountStatus": "Active", "AvailableBalance": 0.0, "CurrencyCode": "Bch", "TotalBalance": 0.0},
#{"AccountGuid": "foo", "AccountStatus": "Active", "AvailableBalance": 0.0, "CurrencyCode": "Ltc", "TotalBalance": 0.0},
#{"AccountGuid": "foo", "AccountStatus": "Active", "AvailableBalance": 0.0, "CurrencyCode": "Mkr", "TotalBalance": 0.0},
#{"AccountGuid": "foo", "AccountStatus": "Active", "AvailableBalance": 0.0, "CurrencyCode": "Dai", "TotalBalance": 0.0},
#{"AccountGuid": "foo", "AccountStatus": "Active", "AvailableBalance": 0.0, "CurrencyCode": "Comp", "TotalBalance": 0.0},
#{"AccountGuid": "foo", "AccountStatus": "Active", "AvailableBalance": 0.0, "CurrencyCode": "Snx", "TotalBalance": 0.0},
#{"AccountGuid": "foo", "AccountStatus": "Active", "AvailableBalance": 0.0, "CurrencyCode": "Grt", "TotalBalance": 0.0},
#{"AccountGuid": "foo", "AccountStatus": "Active", "AvailableBalance": 0.0, "CurrencyCode": "Eos", "TotalBalance": 0.0},
#{"AccountGuid": "foo", "AccountStatus": "Active", "AvailableBalance": 0.0, "CurrencyCode": "Xlm", "TotalBalance": 0.0},
#{"AccountGuid": "foo", "AccountStatus": "Active", "AvailableBalance": 0.0, "CurrencyCode": "Etc", "TotalBalance": 100.0},
#{"AccountGuid": "foo", "AccountStatus": "Active", "AvailableBalance": 0.0, "CurrencyCode": "Bat", "TotalBalance": 0.0},
#{"AccountGuid": "foo", "AccountStatus": "Active", "AvailableBalance": 0.0, "CurrencyCode": "Pmgt", "TotalBalance": 0.0},
#{"AccountGuid": "foo", "AccountStatus": "Active", "AvailableBalance": 0.0, "CurrencyCode": "Yfi", "TotalBalance": 0.0},
#{"AccountGuid": "foo", "AccountStatus": "Active", "AvailableBalance": 0.0, "CurrencyCode": "Aave", "TotalBalance": 0.0},
#{"AccountGuid": "foo", "AccountStatus": "Active", "AvailableBalance": 0.0, "CurrencyCode": "Zrx", "TotalBalance": 0.0},
#{"AccountGuid": "foo", "AccountStatus": "Active", "AvailableBalance": 0.0, "CurrencyCode": "Omg", "TotalBalance": 0.0}]"""  # noqa: E501
#        return MockResponse(200, response)
#
#    with patch.object(exchange.session, 'request', side_effect=mock_api_return):
#        balances, msg = exchange.query_balances()
#
#    assert msg == ''
#    assert balances == {
#        A_AUD: Balance(amount=FVal(2.5), usd_value=FVal(3.75)),
#        A_ETC: Balance(amount=FVal(100), usd_value=FVal(150)),
#    }
#
#
#def test_query_trade_history(function_scope_independentreserve):
#    """Happy path test for independentreserve trade history querying"""
#    exchange = function_scope_independentreserve
#
#    def mock_api_return(method, url, **kwargs):    # pylint: disable=unused-argument
#        assert method == 'post'
#        response = """{"Data": [
#        {"AvgPrice": 603.7,
#        "CreatedTimestampUtc": "2017-11-22T22:54:40.3249401Z",
#        "FeePercent": 0.005,
#        "OrderGuid": "foo1",
#        "OrderType": "MarketOffer",
#        "Original": {"Outstanding": 0.0, "Volume": 0.5, "VolumeCurrencyType": "Primary"},
#        "Outstanding": 0.0,
#        "Price": null,
#        "PrimaryCurrencyCode": "Eth",
#        "SecondaryCurrencyCode": "Aud",
#        "Status": "Filled",
#        "Value": 301.85,
#        "Volume": 0.5
#        }, {
#        "AvgPrice": 257.25,
#        "CreatedTimestampUtc": "2017-07-28T09:39:19.8799244Z",
#        "FeePercent": 0.005,
#        "OrderGuid": "foo2",
#        "OrderType": "MarketBid",
#        "Original": {"Outstanding": 0.0, "Volume": 2.64117379, "VolumeCurrencyType": "Primary"},
#        "Outstanding": 0.0,
#        "Price": null,
#        "PrimaryCurrencyCode": "Eth",
#        "SecondaryCurrencyCode": "Aud",
#        "Status": "Filled",
#        "Value": 679.44,
#        "Volume": 2.64117379
#        }],
# "PageSize": 50,
# "TotalItems": 2,
# "TotalPages": 1}
#"""  # noqa: E501
#        return MockResponse(200, response)
#
#    with patch.object(exchange.session, 'request', side_effect=mock_api_return):
#        trades = exchange.query_trade_history(
#            start_ts=0,
#            end_ts=1565732120,
#            only_cache=False,
#        )
#    expected_trades = [
#        Trade(
#            timestamp=1501234760,
#            location=Location.INDEPENDENTRESERVE,
#            base_asset=A_ETH,
#            quote_asset=A_AUD,
#            trade_type=TradeType.BUY,
#            amount=FVal('2.64117379'),
#            rate=FVal('257.25'),
#            fee=FVal('0.01320586895'),
#            fee_currency=A_ETH,
#            link='foo2',
#        ), Trade(
#            timestamp=1511391280,
#            location=Location.INDEPENDENTRESERVE,
#            base_asset=A_ETH,
#            quote_asset=A_AUD,
#            trade_type=TradeType.SELL,
#            amount=FVal('0.5'),
#            rate=FVal('603.7'),
#            fee=FVal('0.0025'),
#            fee_currency=A_ETH,
#            link='foo1',
#        )]
#    assert trades == expected_trades[::-1]
#
#
## TODO: Make a test for asset movements.
## Would need more mocking as it would require mocking of multiple calls
