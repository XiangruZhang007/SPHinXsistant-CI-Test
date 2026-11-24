"""Bounded GitHub Git Database transport for the existing B4.1 protocol.

A transport credential is not Owner authorization. Writes are private, explicitly
scoped primitives. The Hosted entry separately authenticates the reviewed run,
Writer and versioned governance contract before choosing a mutation scope.
No retry, redirect, reset or delete is offered.
"""
from copy import deepcopy
import hashlib
import json
import re
import urllib.error
import urllib.request

from . import parent_authority_git_audit as audit
from .corpus_snapshot import canonical, digest
from .trusted_snapshot import repository_identity
from scripts import parent_authority_writer_bootstrap as layout

API = 'https://api.github.com/'
MAX_RESPONSE = 1024 * 1024
MAX_REQUESTS = 128
EMPTY_TREE = hashlib.sha1(b'tree 0\0').hexdigest()
AUDIT_TREE = layout.TREE
MAX_DIAGNOSTICS = 8
MAX_ERROR_BODY = 4096


def _error_code(raw):
    """Closed classifications only: never return remote strings or body excerpts."""
    if len(raw) > MAX_ERROR_BODY:
        return 'ERROR_BODY_TOO_LARGE'
    try:
        def unique(pairs):
            value = {}
            for k, v in pairs:
                if k in value: raise ValueError()
                value[k] = v
            return value
        value = json.loads(raw, object_pairs_hook=unique,
            parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
        message = value.get('message') if isinstance(value, dict) else None
        return {'Not Found': 'NOT_FOUND', 'Bad credentials': 'BAD_CREDENTIALS',
            'Resource not accessible by integration': 'INTEGRATION_ACCESS_DENIED',
            'Validation Failed': 'VALIDATION_FAILED',
            'Tree does not contain any files': 'TREE_HAS_NO_FILES',
            'Tree does not exist': 'TREE_NOT_FOUND'}.get(message, 'UNCLASSIFIED_API_ERROR') if isinstance(message, str) else 'UNCLASSIFIED_API_ERROR'
    except Exception:
        return 'INVALID_ERROR_BODY'


def _record_http(client, method, endpoint, status, outcome, api_error=None):
    # Also used by the existing derived-state client's shared _exchange call.
    operation = 'REPOSITORY_OR_RULE_READ'
    for name in ('trees', 'blobs', 'commits', 'refs', 'ref', 'matching-refs'):
        if '/git/' + name in endpoint:
            operation = 'GIT_' + name.upper().replace('-', '_'); break
    scope = getattr(client, '_scope', None)
    item = {'method': method, 'operation': operation,
        'http_status': status if type(status) is int and 100 <= status <= 599 else None,
        'outcome': outcome, 'request_index': client._requests,
        'scope': scope if scope in ('INITIALIZE', 'APPEND') else 'READ_OR_DERIVED'}
    if api_error is not None: item['api_error_code'] = api_error
    client._http_diagnostics = (getattr(client, '_http_diagnostics', []) + [item])[-MAX_DIAGNOSTICS:]


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class GitHubAuditTransport:
    """Pinned endpoint allowlist; `write_scope` never supplies research authority.

    None is read-only; INITIALIZE permits only pinned audit-tree/root/ref provisioning;
    APPEND permits only canonical single-parent protocol commits + force=false.
    Callers must obtain separate operation authorization before choosing a scope.
    Scope selection does not replace the Hosted entry's authorization checks.
    """
    def __init__(self, config, binding, token, *, write_scope=None):
        # Reuse the actual protocol's complete config/binding shape validation.
        audit._IsolatedGitProtocol(self, config, binding)
        audit._need(config['tree_sha'] in (EMPTY_TREE, AUDIT_TREE), 'AUDIT_CONTENT_FREE_TREE_REQUIRED')
        audit._need(isinstance(token, str) and 0 < len(token) <= 4096
                    and not any(ch.isspace() for ch in token), 'AUDIT_TOKEN_REQUIRED')
        audit._need(write_scope in (None, 'INITIALIZE', 'APPEND'), 'INVALID_AUDIT_WRITE_SCOPE')
        self.config, self.binding = deepcopy(config), deepcopy(binding)
        self._token, self._scope = token, write_scope
        self._prefix = 'repos/' + config['repository']
        self._requests = 0
        self._opener = urllib.request.build_opener(_NoRedirect())
        self._seen_ref = False
        self._initialization_attempted = False
        self._ref_creation_ready = False
        self._created = {}
        self._attempted_updates = set()
        self._mutation_keys = set()
        self._writes_closed = False

    def http_diagnostics(self):
        return deepcopy(getattr(self, '_http_diagnostics', []))

    def _require(self, condition, reason):
        if not condition:
            error = audit.AuditError(reason)
            error.api_diagnostics = self.http_diagnostics()
            raise error

    def _exchange(self, method, endpoint, body):
        """Single bounded authenticated request. No raw remote error is exposed."""
        self._requests += 1
        audit._need(self._requests <= MAX_REQUESTS, 'AUDIT_REQUEST_BUDGET_EXCEEDED')
        raw = None if body is None else canonical(body)
        audit._need(raw is None or len(raw) <= audit.LIMIT * 2, 'OVERSIZED_AUDIT_REQUEST')
        req = urllib.request.Request(API + endpoint, data=raw, method=method, headers={
            'Authorization': 'Bearer ' + self._token,
            'Accept': 'application/vnd.github+json', 'Content-Type': 'application/json',
            'X-GitHub-Api-Version': '2022-11-28', 'User-Agent': 'SPHinXsistant-audit-v1'})
        status = None
        try:
            with self._opener.open(req, timeout=15) as response:
                status = response.status
                audit._need(response.geturl() == API + endpoint, 'AUDIT_REDIRECT_REJECTED')
                data = response.read(MAX_RESPONSE + 1)
                audit._need(len(data) <= MAX_RESPONSE, 'OVERSIZED_AUDIT_RESPONSE')
                # Strict duplicate-key/non-finite JSON handling without requiring
                # GitHub's ordinary response JSON to use canonical whitespace.
                def unique(pairs):
                    result = {}
                    for k, v in pairs:
                        audit._need(k not in result, 'INVALID_AUDIT_JSON')
                        result[k] = v
                    return result
                value = json.loads(data, object_pairs_hook=unique,
                    parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
                audit._need(isinstance(value, (dict, list)), 'INVALID_AUDIT_JSON')
                _record_http(self, method, endpoint, status, 'HTTP_RESPONSE')
                return status, value
        except urllib.error.HTTPError as error:
            status = error.code
            try: code = _error_code(error.read(MAX_ERROR_BODY + 1))
            except Exception: code = 'ERROR_BODY_UNAVAILABLE'
            finally: error.close()
            _record_http(self, method, endpoint, status, 'HTTP_ERROR', code)
            return status, {}
        except Exception:
            _record_http(self, method, endpoint, status, 'TRANSPORT_OR_RESPONSE_UNCERTAIN')
            error = audit.AuditError('AUDIT_API_OUTCOME_UNCERTAIN')
            error.api_diagnostics = deepcopy(self._http_diagnostics)
            raise error from None

    def request(self, method, endpoint, body=None):
        """The existing protocol transport interface; no generic API proxy."""
        c = self.config
        audit._need(isinstance(endpoint, str) and endpoint.startswith(self._prefix)
                    and method in ('GET', 'POST', 'PATCH'), 'AUDIT_ENDPOINT_DENIED')
        suffix = endpoint[len(self._prefix):]
        ref = c['ref'][5:]
        if method == 'GET':
            allowed = suffix in ('', '/git/ref/' + ref, '/git/matching-refs/' + ref,
                                 '/rules/branches/' + ref[6:], '/git/blobs/' + layout.EMPTY_BLOB) or bool(re.fullmatch(
                r'/git/(?:commits|trees)/[0-9a-f]{40}|/rulesets/[1-9][0-9]*', suffix))
            audit._need(allowed and body is None, 'AUDIT_ENDPOINT_DENIED')
        else:
            audit._need(self._scope is not None and not self._writes_closed
                        and isinstance(body, dict), 'AUDIT_WRITES_NOT_AUTHORIZED')
            if suffix == '/git/trees':
                audit._need(method == 'POST' and self._scope == 'INITIALIZE'
                    and body == layout.tree_request(c['tree_sha']),
                    'AUDIT_TREE_CREATION_DENIED')
            elif suffix == '/git/commits':
                audit._need(method == 'POST' and body.get('tree') == c['tree_sha'],
                            'AUDIT_COMMIT_CREATION_DENIED')
                value = audit._parse(body.get('message'))
                if self._scope == 'INITIALIZE':
                    audit._need(set(body) == {'message', 'tree', 'parents', 'author', 'committer'}
                        and body['parents'] == [] and value == audit._genesis(c, self.binding)
                        and body['author'] == body['committer'], 'AUDIT_GENESIS_CREATION_DENIED')
                    person = body['author']
                    audit._need(isinstance(person, dict) and set(person) == {'name', 'email', 'date'}
                        and all(isinstance(v, str) and 0 < len(v) <= 200
                                and not any(ch in v for ch in '\r\n\0') for v in person.values()),
                        'AUDIT_REVIEWED_GIT_IDENTITY_REQUIRED')
                else:
                    audit._need(set(body) == {'message', 'tree', 'parents'}
                        and isinstance(body['parents'], list) and len(body['parents']) == 1
                        and audit._hash(body['parents'][0], 40)
                        and isinstance(value, dict) and set(value) == audit.EVENT_FIELDS
                        and value['protocol'] == audit.PROTOCOL
                        and value['binding'] == self.binding
                        and value['previous_sha'] == body['parents'][0], 'AUDIT_APPEND_CREATION_DENIED')
            elif suffix == '/git/refs':
                audit._need(method == 'POST' and self._scope == 'INITIALIZE'
                    and body == {'ref': c['ref'], 'sha': c['genesis_sha']}
                    and self._initialization_attempted and self._ref_creation_ready
                    and not self._seen_ref,
                    'AUDIT_REF_CREATION_DENIED')
                self._ref_creation_ready = False
            elif suffix == '/git/refs/' + ref:
                audit._need(method == 'PATCH' and self._scope == 'APPEND'
                    and set(body) == {'sha', 'force'} and body['force'] is False
                    and audit._hash(body['sha'], 40) and body['sha'] in self._created,
                    'AUDIT_REF_UPDATE_DENIED')
                candidate = body['sha']
                audit._need(candidate not in self._attempted_updates, 'AUDIT_UPDATE_RETRY_DENIED')
                self._attempted_updates.add(candidate)  # Burn BEFORE any uncertain request.
                status, current = self.request('GET', self._prefix + '/git/ref/' + ref)
                audit._need(status == 200 and current.get('ref') == c['ref']
                    and current.get('object', {}).get('type') == 'commit'
                    and current['object'].get('sha') == self._created[candidate],
                    'AUDIT_STALE_PARENT')
                # This is a precheck, NOT an atomic expected-old API parameter.
                # A racing sibling still relies on GitHub's FF check at mutation.
            else:
                raise audit.AuditError('AUDIT_ENDPOINT_DENIED')
        if method != 'GET':
            status, repository = self.request('GET', self._prefix)
            audit._need(status == 200, 'AUDIT_REPOSITORY_UNAVAILABLE')
            key = (method, endpoint, digest(body))
            audit._need(key not in self._mutation_keys, 'AUDIT_MUTATION_RETRY_DENIED')
            self._mutation_keys.add(key)
        try:
            status, value = self._exchange(method, endpoint, body)
        except Exception:
            if method != 'GET': self._writes_closed = True
            raise
        if method != 'GET' and status != (201 if method == 'POST' else 200):
            self._writes_closed = True
        if method == 'GET' and suffix == '':
            audit._need(status != 200 or repository_identity(value, c['repository'], c['repository_id']),
                        'AUDIT_REPOSITORY_IDENTITY_MISMATCH')
        if method == 'GET' and suffix == '/git/ref/' + ref:
            if status == 200: self._seen_ref = True
            elif self._seen_ref: raise audit.AuditError('AUDIT_PREVIOUSLY_OBSERVED_REF_UNAVAILABLE')
        if method == 'POST' and suffix == '/git/commits' and status == 201:
            if not (isinstance(value, dict) and audit._hash(value.get('sha'), 40)):
                self._writes_closed = True
                raise audit.AuditError('AUDIT_CREATED_COMMIT_MISMATCH')
            if self._scope == 'APPEND': self._created[value['sha']] = body['parents'][0]
        return status, value

    def verify_tree(self):
        status, tree = self.request('GET', self._prefix + '/git/trees/' + self.config['tree_sha'])
        self._require(status == 200 and layout.tree_matches(self.config['tree_sha'], tree),
            'AUDIT_CONTENT_FREE_TREE_REQUIRED')
        if self.config['tree_sha'] == AUDIT_TREE:
            status, blob = self.request('GET', self._prefix + '/git/blobs/' + layout.EMPTY_BLOB)
            self._require(status == 200 and isinstance(blob, dict)
                and blob.get('sha') == layout.EMPTY_BLOB and blob.get('encoding') == 'base64'
                and type(blob.get('size')) is int and blob['size'] == 0
                and blob.get('content') in ('', '\n'), 'AUDIT_ZERO_BYTE_BLOB_REQUIRED')
        return tree

    def create_genesis(self, reviewed_git_identity):
        """Provisioning only; no automatic ref creation, pin replacement or retry."""
        audit._need(self._scope == 'INITIALIZE' and not self._initialization_attempted,
                    'AUDIT_INITIALIZATION_NOT_AUTHORIZED')
        self._initialization_attempted = True
        status, tree = self.request('POST', self._prefix + '/git/trees', layout.tree_request(self.config['tree_sha']))
        self._require(status == 201 and tree.get('sha') == self.config['tree_sha'],
                    'AUDIT_TREE_CREATION_FAILED')
        self.verify_tree()
        status, commit = self.request('POST', self._prefix + '/git/commits', {
            'message': audit._message(audit._genesis(self.config, self.binding)),
            'tree': self.config['tree_sha'], 'parents': [],
            'author': reviewed_git_identity, 'committer': reviewed_git_identity})
        self._require(status == 201 and commit.get('sha') == self.config['genesis_sha'],
                    'AUDIT_GENESIS_PIN_MISMATCH')
        self._verify_genesis()
        return {'status': 'GENESIS_OBJECT_VERIFIED', 'authorization': 'NOT_GRANTED'}

    def _verify_genesis(self):
        self.verify_tree()
        audit._IsolatedGitProtocol(self, self.config, self.binding)._commit(self.config['genesis_sha'])
        status, obj = self.request('GET', self._prefix + '/git/commits/' + self.config['genesis_sha'])
        self._require(status == 200 and obj.get('parents') == []
                    and audit._parse(obj.get('message')) == audit._genesis(self.config, self.binding),
                    'AUDIT_GENESIS_MISMATCH')

    def verify_absent_ref(self):
        """Read-only absence proof before provisioning any Git object."""
        status, repo = self.request('GET', self._prefix)
        audit._need(status == 200, 'AUDIT_REPOSITORY_UNAVAILABLE')
        status, existing = self.request('GET', self._prefix + '/git/ref/' + self.config['ref'][5:])
        audit._need(status == 404 and not self._seen_ref, 'AUDIT_REF_NOT_PROVEN_ABSENT')
        status, matching = self.request('GET', self._prefix + '/git/matching-refs/' + self.config['ref'][5:])
        audit._need(status == 200 and matching == [], 'AUDIT_REF_NOT_PROVEN_ABSENT')
        return {'status': 'AUDIT_REF_PROVEN_ABSENT', 'authorization': 'NOT_GRANTED'}

    def initialize_ref(self):
        """Explicit one-shot provision; never called automatically by reserve()."""
        audit._need(self._scope == 'INITIALIZE' and not self._initialization_attempted,
                    'AUDIT_INITIALIZATION_NOT_AUTHORIZED')
        self._initialization_attempted = True
        self.verify_absent_ref()
        self._verify_genesis()
        self._ref_creation_ready = True
        status, result = self.request('POST', self._prefix + '/git/refs', {
            'ref': self.config['ref'], 'sha': self.config['genesis_sha']})
        self._require(status == 201, 'AUDIT_REF_CREATION_UNCERTAIN')
        self._require(result.get('ref') == self.config['ref']
            and result.get('object', {}).get('sha') == self.config['genesis_sha']
            and result['object'].get('type') == 'commit', 'AUDIT_REF_CREATION_READBACK_MISMATCH')
        audit._need(audit._IsolatedGitProtocol(self, self.config, self.binding).inspect()['status']
                    == 'NOT_RESERVED_REVIEW_REQUIRED', 'AUDIT_INITIALIZATION_READBACK_FAILED')
        return {'status': 'AUDIT_REF_INITIALIZED', 'authorization': 'NOT_GRANTED', 'ref': result}

    def observe_governance(self, history_id, writer_id, integration_id, *,
                           project=None, policy=None, operation=None):
        """Live GET observations, never proof of independent control-plane trust."""
        audit._need(all(type(n) is int and n > 0 for n in (history_id, writer_id, integration_id))
                    and history_id != writer_id, 'AUDIT_GOVERNANCE_IDENTITIES_REQUIRED')
        if policy is not None:
            from scripts import runtime_ruleset_observation as observation
            audit._need(all(type(policy[k]) is type(self.config[k]) and policy[k] == self.config[k]
                for k in ('repository', 'repository_id')), 'AUDIT_RUNTIME_POLICY_REPOSITORY_MISMATCH')
            audit._need(all(type(policy[k]) is int and policy[k] == n for k, n in (
                ('history_ruleset_id', history_id), ('writer_ruleset_id', writer_id),
                ('writer_integration_id', integration_id))), 'AUDIT_RUNTIME_POLICY_IDENTITIES_MISMATCH')
            evidence = observation.load(project, policy, default_branch=policy.get('default_branch', 'ci-upstream-refresh'),
                governance_sha256=self.config['governance_sha256'], operation=operation)
            def read(number):
                status, rule = self.request('GET', self._prefix + '/rulesets/' + str(number))
                audit._need(status == 200, 'AUDIT_GOVERNANCE_UNAVAILABLE')
                return rule
            return observation.observe(evidence, read,
                update_read=lambda node, number: observation.live_update(self._token, node, number))
        rulesets = []
        for number in (history_id, writer_id):
            status, rule = self.request('GET', self._prefix + '/rulesets/' + str(number))
            audit._need(status == 200 and isinstance(rule, dict), 'AUDIT_GOVERNANCE_UNAVAILABLE')
            rulesets.append({k: rule.get(k) for k in ('id', 'target', 'enforcement',
                'conditions', 'bypass_actors', 'rules')})
        history, writer = rulesets
        target = {'ref_name': {'include': ['refs/heads/ci-v2-authority-audit/*'], 'exclude': []}}
        audit._need(all(r['target'] == 'branch' and r['enforcement'] == 'active'
            and r['conditions'] == target for r in rulesets), 'AUDIT_GOVERNANCE_SCOPE_MISMATCH')
        audit._need(history['id'] == history_id and writer['id'] == writer_id
            and history['bypass_actors'] == []
            and {x['type'] for x in history['rules']} == {
                'deletion', 'non_fast_forward', 'required_linear_history'}
            and writer['bypass_actors'] == [{'actor_id': integration_id,
                'actor_type': 'Integration', 'bypass_mode': 'always'}]
            and writer['rules'] == [{'type': 'creation'}, {'type': 'update',
                'parameters': {'update_allows_fetch_and_merge': False}}],
            'AUDIT_WRITER_OR_HISTORY_RULES_MISMATCH')
        audit._need(digest({'schema_version': 1, 'rulesets': rulesets})
                    == self.config['governance_sha256'], 'AUDIT_GOVERNANCE_PIN_MISMATCH')
        return {'status': 'PINNED_RULESETS_OBSERVED', 'ruleset_ids': [history_id, writer_id],
            'writer_integration_id': integration_id, 'authorization': 'NOT_GRANTED',
            'writer_credential_isolation': 'NOT_VERIFIED',
            'independent_governance': 'NOT_VERIFIED',
            'rollback_between_observations': 'NOT_DETECTABLE_FROM_CURRENT_RULESETS_ALONE'}
