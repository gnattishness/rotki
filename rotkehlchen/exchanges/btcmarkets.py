import base64
import hashlib
from http import HTTPStatus
import hmac
import json
import logging  # lgtm [py/import-and-import-from]  # https://github.com/github/codeql/issues/6088
import time
from collections import OrderedDict
from json.decoder import JSONDecodeError
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Tuple

import gevent
import requests
from typing_extensions import Literal

from rotkehlchen.accounting.structures import Balance
from rotkehlchen.assets.asset import Asset
from rotkehlchen.assets.converters import asset_from_btc_markets
from rotkehlchen.constants.misc import ZERO
from rotkehlchen.constants.timing import DEFAULT_TIMEOUT_TUPLE, QUERY_RETRY_TIMES
from rotkehlchen.errors import DeserializationError, RemoteError, UnknownAsset
from rotkehlchen.exchanges.data_structures import (
    AssetMovement,
    Location,
    MarginPosition,
    Price,
    Trade,
)
from rotkehlchen.exchanges.exchange import ExchangeInterface, ExchangeQueryBalances
from rotkehlchen.fval import FVal
from rotkehlchen.inquirer import Inquirer
from rotkehlchen.logging import RotkehlchenLogsAdapter
from rotkehlchen.serialization.deserialize import (
    deserialize_asset_amount,
    deserialize_asset_movement_category,
    deserialize_timestamp_from_date,
)
from rotkehlchen.typing import (
    ApiKey,
    ApiSecret,
    AssetAmount,
    AssetMovementCategory,
    Fee,
    Timestamp,
    TradeType,
)
from rotkehlchen.user_messages import MessagesAggregator
from rotkehlchen.utils.misc import timestamp_to_iso8601

if TYPE_CHECKING:
    from rotkehlchen.db.dbhandler import DBHandler

logger = logging.getLogger(__name__)
log = RotkehlchenLogsAdapter(logger)
PAGINATION_LIMIT = 200



def _trade_from_independentreserve(raw_trade: Dict) -> Trade:
    """Convert IndependentReserve raw data to a trade

    https://www.independentreserve.com/products/api#GetClosedFilledOrders
    May raise:
    - DeserializationError
    - UnknownAsset
    - KeyError
    """
    log.debug(f'Processing raw IndependentReserve trade: {raw_trade}')
    trade_type = TradeType.BUY if 'Bid' in raw_trade['OrderType'] else TradeType.SELL
    base_asset = independentreserve_asset(raw_trade['PrimaryCurrencyCode'])
    quote_asset = independentreserve_asset(raw_trade['SecondaryCurrencyCode'])
    amount = FVal(raw_trade['Volume']) - FVal(raw_trade['Outstanding'])
    timestamp = deserialize_timestamp_from_date(
        date=raw_trade['CreatedTimestampUtc'],
        formatstr='iso8601',
        location='IndependentReserve',
    )
    rate = Price(FVal(raw_trade['AvgPrice']))
    fee_amount = FVal(raw_trade['FeePercent']) * amount
    fee_asset = base_asset
    return Trade(
        timestamp=timestamp,
        location=Location.INDEPENDENTRESERVE,
        base_asset=base_asset,
        quote_asset=quote_asset,
        trade_type=trade_type,
        amount=AssetAmount(amount),
        rate=rate,
        fee=Fee(fee_amount),
        fee_currency=fee_asset,
        link=str(raw_trade['OrderGuid']),
    )


def _asset_movement_from_independentreserve(raw_tx: Dict) -> Optional[AssetMovement]:
    """Convert IndependentReserve raw data to an AssetMovement

    https://www.independentreserve.com/products/api#GetTransactions
    May raise:
    - DeserializationError
    - UnknownAsset
    - KeyError
    """
    log.debug(f'Processing raw IndependentReserve transaction: {raw_tx}')
    movement_type = deserialize_asset_movement_category(raw_tx['Type'])
    asset = independentreserve_asset(raw_tx['CurrencyCode'])
    bitcoin_tx_id = raw_tx.get('BitcoinTransactionId')
    eth_tx_id = raw_tx.get('EthereumTransactionId')
    if asset == A_BTC and bitcoin_tx_id is not None:
        transaction_id = raw_tx['BitcoinTransactionId']
    elif eth_tx_id is not None:
        transaction_id = eth_tx_id
    else:
        transaction_id = None

    timestamp = deserialize_timestamp_from_date(
        date=raw_tx['CreatedTimestampUtc'],
        formatstr='iso8601',
        location='IndependentReserve',
    )

    comment = raw_tx.get('Comment')
    address = None
    if comment is not None and comment.startswith('Withdrawing to'):
        address = comment.rsplit()[-1]

    raw_amount = raw_tx.get('Credit') if movement_type == AssetMovementCategory.DEPOSIT else raw_tx.get('Debit')  # noqa: E501

    if raw_amount is None:  # skip
        return None   # Can end up being None for some things like this: 'Comment': 'Initial balance after Bitcoin fork'  # noqa: E501
    amount = deserialize_asset_amount(raw_amount)

    return AssetMovement(
        location=Location.INDEPENDENTRESERVE,
        category=movement_type,
        address=address,
        transaction_id=transaction_id,
        timestamp=timestamp,
        asset=asset,
        amount=amount,
        fee_asset=asset,  # whatever -- no fee
        fee=Fee(ZERO),  # we can't get fee from this exchange
        link=raw_tx['CreatedTimestampUtc'] + str(amount) + str(movement_type) + asset.identifier,
    )

def _sign_bm_message(secret: bytes, message: str) -> str:
    """Returns message signature as a base64 encoded string.

    Uses hmac_sha512.
    """
    # NOTE: CPython is faster if digest is a string supported by OpenSSL
    # See https://docs.python.org/3.7/library/hmac.html#hmac.digest
    sig_bytes = hmac.digest(
            secret,
            msg=message.encode('utf-8'),
            digest='sha512',
        )
    b64_bytes = base64.b64encode(sig_bytes)
    return b64_bytes.decode('utf-8')



class BTCMarkets(ExchangeInterface):  # lgtm[py/missing-call-to-init]
    # NOTE: the apisecret is provided as a b64 encoded string, needs to be decoded to be valid
    def __init__(
            self,
            name: str,
            api_key: ApiKey,
            secret: ApiSecret,
            database: 'DBHandler',
            msg_aggregator: MessagesAggregator,
    ):
        super().__init__(
            name=name,
            location=Location.BTCMARKETS,
            api_key=api_key,
            secret=secret,
            database=database,
        )
        self.base_uri = 'https://api.btcmarkets.net'
        self.api_version = 'v3'
        self.msg_aggregator = msg_aggregator
        self.session.headers.update({'Content-Type': 'application/json', 'BM-AUTH-APIKEY': api_key})

    def first_connection(self) -> None:
        self.first_connection_made = True

    def edit_exchange_credentials(
            self,
            api_key: Optional[ApiKey],
            api_secret: Optional[ApiSecret],
            passphrase: Optional[str],
    ) -> bool:
        changed = super().edit_exchange_credentials(api_key, api_secret, passphrase)
        if api_key is not None:
            self.session.headers.update({'BM-AUTH-APIKEY': api_key})
        return changed

    # TODO typing overload - payload should be None for GET & DELETE
    def _api_query(
            self,
            verb: Literal['GET', 'POST', 'DELETE'],
            endpoint: str,
            params: Optional[Dict[str,str]] = None,
            payload: Optional[Dict[str, Any]] = None,
            # limit here? or keep in payload?
    ) -> Dict:
        """A BTC Markets query

        See https://api.btcmarkets.net/doc/v3
        May raise RemoteError
        """
        path = f'/{self.api_version}/{endpoint}'
        # TODO ensure that path doesn't start or end with `/`

        tries = QUERY_RETRY_TIMES
        while True:
            # data = None
            # does data need to change over retries?
            # I think the message sig doesn't need to change over pagination? not if it's a query parameter
            log.debug(
                'BTC Markets API Query',
                verb=verb,
                url=path,
                payload=payload,
                params=params,
            )
            timestamp = str(int(time.time() * 1000))
            datastr = json.dumps(payload, sort_keys=False) if payload else ''
            # NOTE: path doesn't contain query parameters
            # TODO double check
            message = ''.join((verb, path, timestamp, datastr))
            signature = _sign_bm_message(
                self.secret,
                message,
                )
            try:
                # NOTE local request headers are merged with session headers
                response = self.session.request(
                    method=verb,
                    url=self.base_uri + path,
                    data=datastr,
                    params=params,
                    headers = {
                        "BM-AUTH-TIMESTAMP": timestamp,
        "BM-AUTH-SIGNATURE": signature,
                        },
                    timeout=DEFAULT_TIMEOUT_TUPLE,
                )
            except requests.exceptions.RequestException as e:
                raise RemoteError(f'BTC Markets API request failed due to {str(e)}') from e

            if response.status_code not in (HTTPStatus.OK, HTTPStatus.TOO_MANY_REQUESTS):
                # TODO specific permission error for 403
                raise RemoteError(
                    f'BTC Markets api request for {response.url} failed with HTTP status '
                    f'code {response.status_code} and response {response.text}',
                )

            if response.status_code == HTTPStatus.TOO_MANY_REQUESTS:
                if tries >= 1:
                    backoff_seconds = 10 / tries
                    log.debug(
                        f'Got a 429 from BTC Markets. Backing off for {backoff_seconds}')
                    gevent.sleep(backoff_seconds)
                    tries -= 1
                    continue

                # else
                raise RemoteError(
                    f'BTC Markets api request for {response.url} failed with HTTP '
                    f'status code {response.status_code} and response {response.text}.'
                    'No remaining retries.',
                )

            break  # else all good, we can break off the retry loop

        # TODO pagination
        try:
            json_ret = json.loads(response.text)
        except JSONDecodeError as e:
            raise RemoteError('BTC Markets returned invalid JSON response') from e

        return json_ret

    def validate_api_key(self) -> Tuple[bool, str]:
        """Validates that the BTC Markets API key is good for usage in rotki"""
        # NOTE: the least privileged API Key can still read everything, so if it's a valid API Key,
        # it's good enough for us.
        try:
            self._api_query(verb='GET', endpoint='accounts/me/balances')
            return True, ""

        except RemoteError as e:
            return False, str(e)

    # TODO protect with lock, cache response?
    def query_balances(self, **kwargs: Any) -> ExchangeQueryBalances:
        assets_balance: Dict[Asset, Balance] = {}
        try:
            response = self._api_query(verb='GET', endpoint='accounts/me/balances')
        except RemoteError as e:
            msg = f'BTC Markets request failed. Could not reach the exchange due to {str(e)}'  # noqa: E501
            log.error(msg)
            return None, msg

        log.debug(f'BTC Markets account response: {response}')
        for entry in response:
            amount = deserialize_asset_amount(entry['balance'])


            ## TODO uncomment after testing
            ## ignore empty balances. BTC Markets returns zero balances some unowned assets.
            #if amount == ZERO:
            #    continue

            try:
                asset = asset_from_btc_markets(entry['assetName'])
                usd_price = Inquirer().find_usd_price(asset=asset)
            except UnknownAsset as e:
                self.msg_aggregator.add_warning(
                    f'Found BTC Markets balance result with unknown asset '
                    f'{e.asset_name}. Ignoring it.',
                )
                continue
            except RemoteError as e:  # raised only by find_usd_price
                self.msg_aggregator.add_error(
                    f'Error processing BTC Markets balance entry due to inability to '
                    f'query USD price: {str(e)}. Skipping balance entry',
                )
                continue
            except (DeserializationError, KeyError) as e:
                msg = str(e)
                if isinstance(e, KeyError):
                    msg = f'Missing key entry for {msg}.'
                return None, f'Error processing BTC Markets balance entry {entry}. {msg}'

            # TODO delete after testing - just used to check if more assets are mismatched.
            if amount == ZERO:
                continue

            assets_balance[asset] = Balance(
                amount=amount,
                usd_value=amount * usd_price,
            )

        return assets_balance, ''

    def _gather_paginated_data(self, path: str, extra_options: Optional[Dict] = None) -> List[Dict[str, Any]]:  # noqa: E501
        """May raise KeyError"""
        page = 1
        page_size = 50
        data = []
        while True:
            call_options = extra_options.copy() if extra_options is not None else {}
            call_options.update({'pageIndex': page, 'pageSize': page_size})
            resp = self._api_query(
                verb='post',
                method_type='Private',
                path=path,
                options=call_options,
            )
            data.extend(resp['Data'])
            if len(resp['Data']) < 50:
                break  # get out of the loop

            page += 1  # go to the next page

        return data

    def query_online_trade_history(
            self,
            start_ts: Timestamp,
            end_ts: Timestamp,
    ) -> List[Trade]:
        """May raise RemoteError"""
        try:
            resp_trades = self._gather_paginated_data(path='GetClosedFilledOrders')
        except KeyError as e:
            self.msg_aggregator.add_error(
                f'Error processing independentreserve trades response. '
                f'Missing key: {str(e)}.',
            )
            return []

        trades = []
        for raw_trade in resp_trades:
            try:
                trade = _trade_from_independentreserve(raw_trade)
                if trade.timestamp < start_ts or trade.timestamp > end_ts:
                    continue
                trades.append(trade)
            except UnknownAsset as e:
                self.msg_aggregator.add_warning(
                    f'Found IndependentReserve trade with unknown asset '
                    f'{e.asset_name}. Ignoring it.',
                )
                continue
            except (DeserializationError, KeyError) as e:
                msg = str(e)
                if isinstance(e, KeyError):
                    msg = f'Missing key entry for {msg}.'
                self.msg_aggregator.add_error(
                    'Error processing an IndependentReserve trade. Check logs '
                    'for details. Ignoring it.',
                )
                log.error(
                    'Error processing an IndependentReserve trade',
                    trade=raw_trade,
                    error=msg,
                )
                continue

        return trades

    def query_online_deposits_withdrawals(
            self,  # pylint: disable=no-self-use
            start_ts: Timestamp,  # pylint: disable=unused-argument
            end_ts: Timestamp,  # pylint: disable=unused-argument
    ) -> List[AssetMovement]:
        if self.account_guids is None:
            self.query_balances()  # do a balance query to populate the account guids
        movements = []
        for guid in self.account_guids:  # type: ignore  # we know its not None
            try:
                resp = self._gather_paginated_data(
                    path='GetTransactions',
                    extra_options={
                        'accountGuid': guid,
                        'fromTimestampUtc': timestamp_to_iso8601(start_ts, utc_as_z=True),
                        'toTimestampUtc': timestamp_to_iso8601(end_ts, utc_as_z=True),
                        # if we filter by tx type in my tests I started getting
                        # {"Message":"A server error occurred. Please wait a few minutes and try again."}   # noqa: E501
                        # 'txTypes': 'Deposit,Withdrawal',  # there is also DepositFee
                    },
                )
            except KeyError as e:
                self.msg_aggregator.add_error(
                    f'Error processing IndependentReserve transactions response. '
                    f'Missing key: {str(e)}.',
                )
                return []

            for entry in resp:
                entry_type = entry.get('Type')
                if entry_type is None or entry_type not in ('Deposit', 'Withdrawal'):
                    continue

                try:
                    movement = _asset_movement_from_independentreserve(entry)
                    if movement:
                        movements.append(movement)
                except UnknownAsset as e:
                    self.msg_aggregator.add_warning(
                        f'Found unknown IndependentReserve asset {e.asset_name}. '
                        f'Ignoring the deposit/withdrawal containing it.',
                    )
                    continue
                except (DeserializationError, KeyError) as e:
                    msg = str(e)
                    if isinstance(e, KeyError):
                        msg = f'Missing key entry for {msg}.'
                    self.msg_aggregator.add_error(
                        'Failed to deserialize an IndependentReserve deposit/withdrawal. '
                        'Check logs for details. Ignoring it.',
                    )
                    log.error(
                        'Error processing an IndependentReserve deposit/withdrawal.',
                        raw_asset_movement=entry,
                        error=msg,
                    )
                    continue

        return movements

    def query_online_margin_history(
            self,  # pylint: disable=no-self-use
            start_ts: Timestamp,  # pylint: disable=unused-argument
            end_ts: Timestamp,  # pylint: disable=unused-argument
    ) -> List[MarginPosition]:
        return []  # noop for independentreserve
