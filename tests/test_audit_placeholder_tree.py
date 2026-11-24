"""Focused local Git/REST compatibility checks; no hosted writes or approval."""
from copy import deepcopy
import hashlib
import io
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
import urllib.error
from unittest.mock import patch

import test_parent_authority_github_transport as fixtures
import test_parent_authority_git_audit as protocol_fixtures
import test_automatic_lifecycle as automatic_fixtures
from src import parent_authority_github_transport as transport
from src import parent_authority_git_audit as audit
from src import automatic_writer
from src.corpus_snapshot import digest
from scripts import parent_authority_writer_bootstrap as layout


class PlaceholderTests(unittest.TestCase):
    def setUp(self):
        self.f = fixtures.GitHubTransportTests(); self.f.setUp(); self.addCleanup(self.f.doCleanups)
        self.f.config['tree_sha'] = layout.TREE
        self.f.server = fixtures.Server(self.f.config, self.f.binding)
        self.f.server.repo.update(private=False, visibility='public')

    def test_native_git_independently_computes_zero_blob_and_single_file_tree(self):
        with tempfile.TemporaryDirectory() as directory:
            subprocess.run(['git', 'init', '-q', directory], check=True, capture_output=True)
            blob = subprocess.check_output(['git', '-C', directory, 'hash-object', '-w', '--stdin'], input=b'').decode().strip()
            tree = subprocess.check_output(['git', '-C', directory, 'mktree'],
                input=('100644 blob '+blob+'\t'+layout.PLACEHOLDER+'\n').encode()).decode().strip()
            self.assertEqual(blob, layout.EMPTY_BLOB)
            self.assertEqual(tree, layout.TREE)
            self.assertNotEqual(tree, transport.EMPTY_TREE)
            self.assertEqual(subprocess.check_output(['git', '-C', directory, 'cat-file', 'blob', blob]), b'')

    def test_placeholder_readback_includes_fixed_blob_content(self):
        t = self.f.transport(); t.verify_tree()
        self.assertEqual([url.rsplit('/', 2)[-2] for method, url, _ in self.f.server.http], ['trees', 'blobs'])
        self.assertTrue(all(method == 'GET' for method, _, _ in self.f.server.http))

    def test_creation_allowlist_is_exact_no_base_tree_or_arbitrary_content(self):
        request = layout.tree_request(layout.TREE)
        variants = [{'tree': []}, {**request, 'base_tree': layout.TREE}]
        for field, value in [('content', 'x'), ('path', 'other'), ('mode', '100755'), ('type', 'tree')]:
            changed = deepcopy(request); changed['tree'][0][field] = value; variants.append(changed)
        variants.append({'tree': request['tree']*2})
        for body in variants:
            with self.subTest(body=body), self.assertRaises(audit.AuditError):
                self.f.transport('INITIALIZE').request('POST', 'repos/'+fixtures.NAME+'/git/trees', body)
        self.assertEqual(self.f.server.http, [])

    def test_nonzero_executable_symlink_extra_truncated_or_wrong_tree_rejected(self):
        self.f.transport().verify_tree()
        row = {'path': layout.PLACEHOLDER, 'mode': '100644', 'type': 'blob', 'sha': layout.EMPTY_BLOB, 'size': 0}
        good = {'sha': layout.TREE, 'truncated': False, 'tree': [row]}
        cases = []
        for key, value in [('path', 'other'), ('mode', '100755'), ('mode', '120000'),
                           ('type', 'tree'), ('sha', 'f'*40), ('size', 1), ('size', False)]:
            bad = deepcopy(good); bad['tree'][0][key] = value; cases.append(bad)
        cases += [{**good, 'tree': [row, row]}, {**good, 'tree': []},
                  {**good, 'truncated': True}, {**good, 'sha': transport.EMPTY_TREE}]
        for bad in cases:
            self.f.server.override = lambda req, value=bad: fixtures.Response(200, value, req.full_url)
            with self.subTest(bad=bad), self.assertRaisesRegex(audit.AuditError, 'CONTENT_FREE_TREE_REQUIRED'):
                self.f.transport().verify_tree()

    def test_tree_metadata_does_not_replace_zero_byte_blob_verification(self):
        base = {'sha': layout.EMPTY_BLOB, 'encoding': 'base64', 'size': 0, 'content': ''}
        for key, value in [('content', 'eA=='), ('content', 'credential'), ('size', False),
                           ('size', 1), ('encoding', 'utf-8'), ('sha', 'f'*40)]:
            bad = {**base, key: value}
            self.f.server.override = lambda req, body=bad: fixtures.Response(200, body, req.full_url) if '/git/blobs/' in req.full_url else None
            with self.subTest(key=key, value=value), self.assertRaisesRegex(audit.AuditError, 'ZERO_BYTE_BLOB_REQUIRED'):
                self.f.transport().verify_tree()

    def test_blob_access_is_fixed_read_only_and_not_a_generic_proxy(self):
        for method, suffix, body in [('GET', '/git/blobs/'+'f'*40, None), ('POST', '/git/blobs', {'content': ''})]:
            with self.assertRaises(audit.AuditError):
                self.f.transport('INITIALIZE').request(method, 'repos/'+fixtures.NAME+suffix, body)
        self.assertEqual(self.f.server.http, [])

    def test_http_diagnostics_are_bounded_closed_and_never_echo_secrets(self):
        secret = 'SYNTHETIC_TOKEN_PRIVATE_KEY_RESPONSE_MUST_NOT_LEAK'
        bodies = [json.dumps({'message': 'Not Found', 'secret': secret, 'documentation_url': secret}).encode(),
                  json.dumps({'message': secret}).encode(), secret.encode(),
                  b'{"message":"Not Found","message":"'+secret.encode()+b'"}',
                  b'x'*(transport.MAX_ERROR_BODY+1)]
        expected = ['NOT_FOUND', 'UNCLASSIFIED_API_ERROR', 'INVALID_ERROR_BODY', 'INVALID_ERROR_BODY', 'ERROR_BODY_TOO_LARGE']
        t = self.f.transport('INITIALIZE')
        for raw, code in zip(bodies, expected):
            def fail(req, data=raw):
                raise urllib.error.HTTPError(req.full_url, 422, secret, {'Authorization': secret}, io.BytesIO(data))
            self.f.server.override = fail
            # Read-only HTTP fixtures do not consume mutation authority.
            self.assertEqual(t.request('GET', 'repos/'+fixtures.NAME), (422, {}))
            last = t.http_diagnostics()[-1]
            self.assertEqual(last['http_status'], 422)
            self.assertEqual(last['api_error_code'], code)
            self.assertNotIn(secret, json.dumps(last))
        self.f.server.override = None
        for _ in range(12): t.request('GET', 'repos/'+fixtures.NAME)
        self.assertEqual(len(t.http_diagnostics()), transport.MAX_DIAGNOSTICS)
        self.assertNotIn(secret, json.dumps(t.http_diagnostics()))

    def test_timeout_preserves_uncertainty_without_exception_text_or_status_invention(self):
        def fail(req): raise TimeoutError('sensitive transport text')
        self.f.server.override = fail
        t = self.f.transport()
        with self.assertRaises(audit.AuditError) as caught:
            t.request('GET', 'repos/'+fixtures.NAME)
        self.assertEqual(str(caught.exception), 'AUDIT_API_OUTCOME_UNCERTAIN')
        self.assertIsNone(caught.exception.api_diagnostics[-1]['http_status'])
        self.assertNotIn('sensitive', json.dumps(caught.exception.api_diagnostics))

    def test_success_http_status_with_wrong_created_tree_is_still_rejected(self):
        self.f.server.override = lambda req: fixtures.Response(201, {'sha': 'f'*40}, req.full_url) if (
            req.method == 'POST' and req.full_url.endswith('/git/trees')) else None
        t = self.f.transport('INITIALIZE')
        with self.assertRaisesRegex(audit.AuditError, 'AUDIT_TREE_CREATION_FAILED') as caught:
            t.create_genesis(layout.PERSON)
        self.assertEqual(caught.exception.api_diagnostics[-1]['http_status'], 201)
        self.assertFalse(any(m == 'POST' and url.endswith('/git/commits') for m, url, _ in self.f.server.http))
        with self.assertRaises(audit.AuditError): t.create_genesis(layout.PERSON)

    def test_existing_append_protocol_keeps_each_explicit_tree_pin(self):
        for tree in (transport.EMPTY_TREE, layout.TREE):
            f = protocol_fixtures.DurableAuditTests(); f.setUp(); self.addCleanup(f.doCleanups)
            config = {**f.config, 'tree_sha': tree}; server = fixtures.Server(config, f.binding)
            t = transport.GitHubAuditTransport(config, f.binding, 'synthetic', write_scope='APPEND'); t._opener = server
            t.verify_tree(); protocol = audit._IsolatedGitProtocol(t, config, f.binding)
            self.assertEqual(protocol.reserve()['status'], 'RESERVED')
            self.assertEqual(protocol.consume()['status'], 'CONSUMED_OFFLINE')
            result = f.f.apply(); raw = (f.f.work/'registry.json').read_bytes()
            self.assertEqual(protocol.complete(raw, result)['status'], 'COMPLETED_OFFLINE')
            self.assertEqual(f.f.authoritative.read_bytes(), f.f.old)
            self.assertTrue(all(b['tree'] == tree for m, ep, b in server.calls if m == 'POST' and ep.endswith('/git/commits')))
            self.assertFalse(any(m == 'POST' and ep.endswith('/git/trees') for m, ep, _ in server.calls))

    def test_automatic_writer_hashes_the_same_placeholder_tree_with_native_git(self):
        f = automatic_fixtures.LifecycleTests(); f.setUp(); self.addCleanup(f.doCleanups)
        view = f.view(); entry = {'reference': {'node_id': 'sha256-'+digest('next')}, 'expected_reference_sha256': 'd'*64}
        _, config, binding, person = automatic_writer.transaction(f.policy, f.config, view, 'next', entry,
            f.release, {'actor': f.actor, 'origin': {'run_id': 1}})
        self.assertEqual(config['tree_sha'], layout.TREE)
        identity = person['name']+' <'+person['email']+'> 946684800 +0000'
        raw = ('tree '+layout.TREE+'\nauthor '+identity+'\ncommitter '+identity+'\n\n'+audit._message(audit._genesis(config, binding))).encode()
        native = subprocess.check_output(['git', 'hash-object', '-t', 'commit', '--stdin'], input=raw).decode().strip()
        self.assertEqual(config['genesis_sha'], native)

    def test_automatic_cli_preserves_safe_diagnostics_and_does_not_retry(self):
        from scripts import automatic_lifecycle as cli
        from contextlib import redirect_stdout
        error = audit.AuditError('AUDIT_TREE_CREATION_FAILED')
        error.api_diagnostics = [{'method': 'POST', 'operation': 'GIT_TREES',
            'http_status': 422, 'outcome': 'HTTP_ERROR', 'api_error_code': 'VALIDATION_FAILED'}]
        output = io.StringIO()
        with tempfile.TemporaryDirectory() as directory, redirect_stdout(output), \
             patch.object(cli.lifecycle, 'publish_and_advance', side_effect=error) as action:
            code = cli.main(['advance', '--work', directory])
        result = json.loads(output.getvalue())
        self.assertEqual(code, 1); action.assert_called_once()
        self.assertFalse(result['retry'])
        self.assertEqual(result['api_diagnostics'], error.api_diagnostics)


if __name__ == '__main__': unittest.main()
