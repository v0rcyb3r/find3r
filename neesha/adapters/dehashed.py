"""DeHashed contract readiness: fail closed until official V2 docs are verified.

The vendor's API page links to https://app.dehashed.com/documentation/api,
which currently requires the JavaScript application. Legacy /docs URLs return
404. Third-party clients disagree across API generations, so this module does
not guess an endpoint, authentication scheme, response contract, or price.
"""
from typing import ClassVar

from neesha.adapters.base import AdapterError, BaseAdapter, Cost, RawResult, Reference, Request

API_DOCUMENTATION = 'https://app.dehashed.com/documentation/api'
UNAVAILABLE_REASON = ('DeHashed V2 contract is not verified against accessible official documentation. '
                      'No live calls or credential-record collection are implemented.')


class DeHashedAdapter(BaseAdapter):
    name: ClassVar[str] = 'dehashed'
    tier: ClassVar[str] = 'C'
    default_enabled: ClassVar[bool] = False
    collection_mode: ClassVar[str] = 'third_party_passive'
    source_type: ClassVar[str] = 'commercial_api'
    description: ClassVar[str] = 'DeHashed metadata connector awaiting verified official API contract'
    produces: ClassVar[frozenset[str]] = frozenset()
    accepts: ClassVar[frozenset[str]] = frozenset({'company', 'domain'})
    requires_techniques: ClassVar[frozenset[str]] = frozenset({'breach_metadata'})

    def availability(self) -> dict:
        return {'available': False, 'reason': UNAVAILABLE_REASON}

    def estimate_cost(self, request: Request) -> Cost:
        raise AdapterError(UNAVAILABLE_REASON)

    def search(self, request: Request) -> list[Reference]:
        raise AdapterError(UNAVAILABLE_REASON)

    def fetch(self, reference: Reference) -> RawResult:
        raise AdapterError(UNAVAILABLE_REASON)

    def parse(self, raw: RawResult, request: Request):
        raise AdapterError(UNAVAILABLE_REASON)
