import base64
import binascii
from http import HTTPStatus
import hmac
import itertools
import json
import logging  # lgtm [py/import-and-import-from]  # https://github.com/github/codeql/issues/6088
import time
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
from rotkehlchen.errors import DeserializationError, RemoteError, UnknownAsset, InputError
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
    deserialize_fee,
    deserialize_int_from_str,
)
from rotkehlchen.typing import (
    ApiKey,
    ApiSecret,
    Timestamp,
    TradeType,
)
from rotkehlchen.user_messages import MessagesAggregator

if TYPE_CHECKING:
    from rotkehlchen.db.dbhandler import DBHandler

logger = logging.getLogger(__name__)
log = RotkehlchenLogsAdapter(logger)
MAX_LIMIT_PER_PAGE = 200


def _trade_from_btcmarkets(raw_trade: Dict) -> Trade:
    """Convert BTC Markets raw data to a trade

    https://api.btcmarkets.net/doc/v3#operation/getTrades
    May raise:
    - DeserializationError
    - UnknownAsset
    - KeyError
    """
    log.debug(f"Processing raw BTC Markets trade: {raw_trade}")
    # Labelled as "Bid" or "Ask"
    trade_type = TradeType.BUY if "Bid" in raw_trade["side"] else TradeType.SELL
    # TODO is it ok to get base & quote from the market ID `base-quote`
    # or better to get from listing active markets? (and cache the values)
    # - otherwise GET markets to confirm base & quote
    base_name, quote_name = raw_trade["marketId"].split("-", maxsplit=1)
    base_asset = asset_from_btc_markets(base_name)
    quote_asset = asset_from_btc_markets(quote_name)
    amount = deserialize_asset_amount(raw_trade["amount"])
    timestamp = deserialize_timestamp_from_date(
        date=raw_trade["timestamp"],
        formatstr="iso8601",
        location="BTC Markets",
    )
    rate = Price(FVal(raw_trade["price"]))
    fee_amount = deserialize_fee(raw_trade["fee"])
    # TODO is the fee always in the quote asset?
    # or in whatever asset you have? - e.g. for buy its the quote asset, sell it's the base asset? (e.g. for poloniex)
    fee_asset = quote_asset
    return Trade(
        timestamp=timestamp,
        location=Location.BTCMARKETS,
        base_asset=base_asset,
        quote_asset=quote_asset,
        trade_type=trade_type,
        amount=amount,
        rate=rate,
        fee=fee_amount,
        fee_currency=fee_asset,
        link=str(raw_trade["orderId"]),
    )


def _asset_movement_from_btcmarkets(raw_tx: Dict) -> Optional[AssetMovement]:
    """Convert BTC Markets raw data to an AssetMovement

    https://api.btcmarkets.net/doc/v3#tag/Fund-Management-APIs/paths/~1v3~1transfers/get
    May raise:
    - DeserializationError
    - UnknownAsset
    - KeyError
    """
    log.debug(f"Processing raw BTC Markets transaction: {raw_tx}")
    movement_type = deserialize_asset_movement_category(raw_tx["type"])
    asset = asset_from_btc_markets(raw_tx["assetName"])
    # paymentDetail can sometimes have address or tx ID?
    # is also there for fiat deposits

    if "paymentDetail" in raw_tx:
        transaction_id = raw_tx["paymentDetail"].get("txId")
        address = raw_tx["paymentDetail"].get("address")
    else:
        transaction_id = None
        address = None

    # NOTE: could also use "creationTime" field, but that's when the withdrawal may have started
    # which may be different to when it became "complete"
    # TODO which one is relevant from a financial/legal perspective?
    timestamp = deserialize_timestamp_from_date(
        date=raw_tx["lastUpdate"],
        formatstr="iso8601",
        location="BTCMarkets",
    )

    amount = deserialize_asset_amount(raw_tx["amount"])

    fee = deserialize_fee(raw_tx["fee"])

    return AssetMovement(
        location=Location.BTCMARKETS,
        category=movement_type,
        address=address,
        transaction_id=transaction_id,
        timestamp=timestamp,
        asset=asset,
        amount=amount,
        fee_asset=asset,  # Fee is taken in the same asset
        fee=fee,
        link=raw_tx["id"],
    )


def _sign_bm_message(secret: bytes, message: str) -> str:
    """Returns message signature as a base64 encoded string.

    Uses hmac_sha512.
    """
    # CPython is faster if digest is a string supported by OpenSSL
    # See https://docs.python.org/3.7/library/hmac.html#hmac.digest
    sig_bytes = hmac.digest(
        secret,
        msg=message.encode("utf-8"),
        digest="sha512",
    )
    b64_bytes = base64.b64encode(sig_bytes)
    return b64_bytes.decode("utf-8")

def _decode_bm_secret(encoded_secret: ApiSecret) -> ApiSecret:
    """Returns decoded secret.

    Can raise InputError if .

    :dev: The API Secret provided by BTC Markets is a base64-encoded string
        that needs to be decoded for use.
    """
    secret_str = encoded_secret.decode()  # TODO this step might not be needed
    try:
        decoded_secret = ApiSecret(base64.b64decode(secret_str, validate=True))
    except binascii.Error:
        # Avoid echoing the error message in case it contains sensitive info.
        raise InputError(
            "The BTC Markets secret provided is malformed, "
            "containing invalid or missing characters"
        )
    return decoded_secret

class Btcmarkets(ExchangeInterface):  # lgtm[py/missing-call-to-init]
    def __init__(
        self,
        name: str,
        api_key: ApiKey,
        secret: ApiSecret,
        database: "DBHandler",
        msg_aggregator: MessagesAggregator,
    ):
        # NOTE: we assume the secret provided has not yet been decoded from its base64 encoding
        decoded_secret = _decode_bm_secret(secret)
        super().__init__(
            name=name,
            location=Location.BTCMARKETS,
            api_key=api_key,
            secret=decoded_secret,
            database=database,
        )
        self.base_uri = "https://api.btcmarkets.net"
        self.api_version = "v3"
        self.msg_aggregator = msg_aggregator
        self.session.headers.update(
            {"Content-Type": "application/json", "BM-AUTH-APIKEY": api_key},
        )

    def first_connection(self) -> None:
        self.first_connection_made = True

    # TODO should this be = None to properly be optional?
    def edit_exchange_credentials(
        self,
        api_key: Optional[ApiKey],
        api_secret: Optional[ApiSecret],
        passphrase: Optional[str],
    ) -> bool:
        maybe_decoded_secret = api_secret and _decode_bm_secret(api_secret)
        changed = super().edit_exchange_credentials(api_key, maybe_decoded_secret, passphrase)
        if api_key is not None:
            self.session.headers.update({"BM-AUTH-APIKEY": api_key})
        return changed

    # TODO typing overload - payload should be None for GET & DELETE
    # TODO typing return? JSON only has "ANY"
    def _api_query(
        self,
        verb: Literal["GET", "POST", "DELETE"],
        endpoint: str,
        params: Optional[Dict[str, str]] = None,
        payload: Optional[Dict[str, Any]] = None,
    ) -> Tuple[Any, requests.Response]:
        """A BTC Markets query

        See https://api.btcmarkets.net/doc/v3
        May raise RemoteError
        """
        path = f"/{self.api_version}/{endpoint}"
        # TODO ensure that path doesn't start or end with `/`

        tries = QUERY_RETRY_TIMES
        while True:
            # does data need to change over retries?
            # TODO
            # I think the message sig doesn't need to change over pagination? not if it's a query parameter
            log.debug(
                "BTC Markets API Query",
                verb=verb,
                url=path,
                payload=payload,
                params=params,
            )
            timestamp = str(int(time.time() * 1000))
            datastr = json.dumps(payload, sort_keys=False) if payload else ""
            # NOTE: path doesn't contain query parameters
            # TODO double check
            message = "".join((verb, path, timestamp, datastr))
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
                    headers={
                        "BM-AUTH-TIMESTAMP": timestamp,
                        "BM-AUTH-SIGNATURE": signature,
                    },
                    timeout=DEFAULT_TIMEOUT_TUPLE,
                )
            except requests.exceptions.RequestException as e:
                raise RemoteError(
                    f"BTC Markets API request failed due to {str(e)}"
                ) from e

            if response.status_code not in (
                HTTPStatus.OK,
                HTTPStatus.TOO_MANY_REQUESTS,
            ):
                # TODO specific permission error for 403
                raise RemoteError(
                    f"BTC Markets api request for {response.url} failed with HTTP status "
                    f"code {response.status_code} and response {response.text}",
                )

            if response.status_code == HTTPStatus.TOO_MANY_REQUESTS:
                if tries >= 1:
                    backoff_seconds = 10 / tries
                    log.debug(
                        f"Got a 429 from BTC Markets. Backing off for {backoff_seconds}"
                    )
                    gevent.sleep(backoff_seconds)
                    tries -= 1
                    continue

                # else
                raise RemoteError(
                    f"BTC Markets api request for {response.url} failed with HTTP "
                    f"status code {response.status_code} and response {response.text}."
                    "No remaining retries.",
                )

            break  # else all good, we can break off the retry loop

        try:
            json_ret = json.loads(response.text)
        except JSONDecodeError as e:
            raise RemoteError("BTC Markets returned invalid JSON response") from e

        return (json_ret, response)

    def validate_api_key(self) -> Tuple[bool, str]:
        """Validates that the BTC Markets API key is good for usage in rotki"""
        # NOTE: the least privileged API Key can still read everything, so if it's a valid API Key,
        # it's good enough for us.
        try:
            _ = self._api_query(verb="GET", endpoint="accounts/me/balances")
            return True, ""

        except RemoteError as e:
            return False, str(e)

    # TODO protect with lock, cache response?
    def query_balances(self, **kwargs: Any) -> ExchangeQueryBalances:
        assets_balance: Dict[Asset, Balance] = {}
        try:
            (response, _) = self._api_query(verb="GET", endpoint="accounts/me/balances")
        except RemoteError as e:
            msg = f"BTC Markets request failed. Could not reach the exchange due to {str(e)}"  # noqa: E501
            log.error(msg)
            return None, msg

        log.debug(f"BTC Markets account response: {response}")
        for entry in response:
            amount = deserialize_asset_amount(entry["balance"])

            # ignore empty balances. BTC Markets returns zero balances some unowned assets.
            if amount == ZERO:
                continue

            try:
                asset = asset_from_btc_markets(entry["assetName"])
                usd_price = Inquirer().find_usd_price(asset=asset)
            except UnknownAsset as e:
                self.msg_aggregator.add_warning(
                    f"Found BTC Markets balance result with unknown asset "
                    f"{e.asset_name}. Ignoring it.",
                )
                continue
            except RemoteError as e:  # raised only by find_usd_price
                self.msg_aggregator.add_error(
                    f"Error processing BTC Markets balance entry due to inability to "
                    f"query USD price: {str(e)}. Skipping balance entry",
                )
                continue
            except (DeserializationError, KeyError) as e:
                msg = str(e)
                if isinstance(e, KeyError):
                    msg = f"Missing key entry for {msg}."
                return (
                    None,
                    f"Error processing BTC Markets balance entry {entry}. {msg}",
                )

            assets_balance[asset] = Balance(
                amount=amount,
                usd_value=amount * usd_price,
            )

        return assets_balance, ""

    def _gather_paginated_data(
        self,
        verb: Literal["GET", "POST", "DELETE"],
        endpoint: str,
        params: Optional[Dict[str, str]] = None,
        payload: Optional[Dict[str, Any]] = None,
        page_size: int = MAX_LIMIT_PER_PAGE,
    ) -> List[Dict[str, Any]]:  # noqa: E501
        """May raise KeyError, RemoteError, ValueError (if provided invalid input).

        :dev: ValueError indicates programmer error.
        """
        # TODO what should I do when this is called on an endpoint that doesn't support pagination?
        # - get single page and warn? or raise error
        # - either programmer error or the API changed
        # TODO could also specify a persistent limit across queries
        # (e.g. if we only want to get the first 205 values)
        # forward or back directions?
        # TODO "stop_when" callable? evaluated on each result?
        # when would you want to page forward?
        if page_size > MAX_LIMIT_PER_PAGE:
            raise ValueError(
                f'Requested page_size {page_size} greater than MAX_LIMIT_PER_PAGE {MAX_LIMIT_PER_PAGE}'
            )
        data_pages = []
        # TODO do both before & after get returned?
        # or is it always one or the other?
        last_before: Optional[int] = None
        last_after: Optional[int] = None
        while True:
            call_params = params.copy() if params else {}
            call_params["limit"] = page_size
            if last_before is not None:
                call_params["before"] = last_before
            ## I think this breaks, can't have both before and after
            # if last_after is not None:
            #     call_params["after"] = last_after
            # Nicer name for ret_data!!
            (ret_data, response) = self._api_query(
                verb=verb,
                endpoint=endpoint,
                params=call_params,
            )
            data_pages.append(ret_data)
            if len(ret_data) < page_size:
                break  # get out of the loop
            # TODO does this need to be an int?
            # TODO handle wrap keyerror - should this be a remoteError?
            last_before = deserialize_int_from_str(response.headers["BM-BEFORE"], "BTC Markets API Response Header")
            last_after = deserialize_int_from_str(response.headers["BM-AFTER"], "BTC Markets API Response Header")

        # aggregate pages
        # NOTE: need to reverse if iterating via "after"
        data = list(itertools.chain.from_iterable(data_pages))
        return data

    def query_online_trade_history(
        self,
        start_ts: Timestamp,
        end_ts: Timestamp,
    ) -> List[Trade]:
        """May raise RemoteError"""
        # NOTE: returns all trades starting from most recent, API doesn't filter by timestamps
        # TODO stop paginating once we get values before the start_ts?
        # currently gets **all** historical trades before filtering to the ts
        # They are sorted so it should be doable
        try:
            resp_trades = self._gather_paginated_data(verb="GET", endpoint="trades")
        except KeyError as e:
            self.msg_aggregator.add_error(
                f"Error processing BTC Markets trades response. "
                f"Missing key: {str(e)}.",
            )
            return []

        trades = []
        for raw_trade in resp_trades:
            try:
                trade = _trade_from_btcmarkets(raw_trade)
                if trade.timestamp < start_ts or trade.timestamp > end_ts:
                    continue
                trades.append(trade)
            except UnknownAsset as e:
                self.msg_aggregator.add_warning(
                    f"Found BTC Markets trade with unknown asset "
                    f"{e.asset_name}. Ignoring it.",
                )
                continue
            except (DeserializationError, KeyError) as e:
                msg = str(e)
                if isinstance(e, KeyError):
                    msg = f"Missing key entry for {msg}."
                self.msg_aggregator.add_error(
                    "Error processing a BTC Markets trade. Check logs "
                    "for details. Ignoring it.",
                )
                log.error(
                    "Error processing an BTC Markets trade",
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
        movements = []
        try:
            resp = self._gather_paginated_data(
                verb="GET",
                endpoint="transfers",
            )
        except KeyError as e:
            self.msg_aggregator.add_error(
                f"Error processing BTC Markets transactions response. "
                f"Missing key: {str(e)}.",
            )
            return []

        for entry in resp:
            try:
                if entry["status"] != "Complete":
                    # Can also be "Pending Authorization" etc
                    continue
            except KeyError as e:
                msg = f"Unexpected/malformed response structure. Missing 'status' field for {str(e)}."
                self.msg_aggregator.add_error(
                    "Error processing BTC Markets transactions response. "
                    "Check logs for details, ignoring it.",
                )
                log.error(
                    "Error processing an BTC Markets transfers response.",
                    raw_asset_movement=entry,
                    error=msg,
                )
                continue

            try:
                movement = _asset_movement_from_btcmarkets(entry)
                # TODO fix
                # dodgy again, where we get all the transactions then filter ones outside the timestamps
                if movement and movement.timestamp >= start_ts and movement.timestamp <= end_ts:
                    movements.append(movement)
            except UnknownAsset as e:
                self.msg_aggregator.add_warning(
                    f"Found unknown BTC Markets asset {e.asset_name}. "
                    f"Ignoring the deposit/withdrawal containing it.",
                )
                continue
            except (DeserializationError, KeyError) as e:
                msg = str(e)
                if isinstance(e, KeyError):
                    msg = f"Missing key entry for {msg}."
                self.msg_aggregator.add_error(
                    "Failed to deserialize a BTC Markets deposit/withdrawal. "
                    "Check logs for details. Ignoring it.",
                )
                log.error(
                    "Error processing a BTC Markets deposit/withdrawal.",
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
        return []  # noop for BTC Markets
        # TODO is there any of this in BM?
