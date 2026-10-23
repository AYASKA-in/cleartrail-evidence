"""Approved-version packages, tenant/period selection and hostile archive checks."""
import hashlib
import io
import json
import subprocess
import sys
from pathlib import Path
import zipfile
from datetime import datetime, timezone, timedelta

import pytest

from cleartrail.audit_packages import verify_audit_package
from cleartrail.validation import canonical
from test_hosted import setup as setup, login, finish_run
from test_documents import upload, review, add_reviewers


def selection(version=None, run_id=None):
    now = datetime.now(timezone.utc)
    return {"run_id":run_id,"version_ids":[version] if version else [],
            "period_start":(now-timedelta(days=30)).isoformat(),"period_end":(now+timedelta(seconds=15)).isoformat()}


def exported(setup):
    add_reviewers(setup)
    doc = upload(setup)
    assert review(setup,doc["version_id"]).status_code == 200
    run = finish_run(setup[1],setup[2],"alice")
    response = setup[4].post("/api/audit-packages",json=selection(doc["version_id"],run["id"]),headers=login(setup))
    assert response.status_code == 200, response.text
    return response,doc


def test_document_inclusive_export_verifies_with_snapshot_and_trusted_manifest(setup,tmp_path):
    response,doc = exported(setup)
    path=tmp_path/'audit.zip';path.write_bytes(response.content)
    result=verify_audit_package(path,response.headers['x-cleartrail-manifest-sha256'])
    assert result['valid'] and result['documents']==1 and result['snapshot_included'] and result['trusted_manifest_matched']
    with zipfile.ZipFile(path) as archive:
        index=json.loads(archive.read('index.json'))
        assert index['documents'][0]['version']['id']==doc['version_id']
        assert index['documents'][0]['reviews'][-1]['decision']=='approved'
        assert 'scan' in index['documents'][0]['version']
        assert b'Control inventory' in archive.read('report.html')
    with pytest.raises(ValueError):
        verify_audit_package(path,'0'*64)


def test_offline_audit_verifier_needs_only_the_standard_library(setup,tmp_path):
    response,doc=exported(setup)
    path=tmp_path/'offline.zip';path.write_bytes(response.content)
    source=str(Path(__file__).resolve().parents[1])
    program="import sys;sys.path.insert(0,sys.argv[1]);from cleartrail.audit_packages import verify_audit_package;assert verify_audit_package(sys.argv[2])['valid'];print('verified without site packages')"
    result=subprocess.run([sys.executable,'-I','-S','-c',program,source,str(path)],capture_output=True,text=True,timeout=15)
    assert result.returncode==0,result.stderr
    assert 'verified without site packages' in result.stdout


def test_unapproved_expired_withdrawn_and_foreign_versions_are_not_exportable(setup):
    add_reviewers(setup)
    doc=upload(setup)
    client=setup[4]
    assert client.post('/api/audit-packages',json=selection(doc['version_id']),headers=login(setup)).status_code==404
    approved=review(setup,doc['version_id']).json()
    assert client.post('/api/audit-packages',json=selection(doc['version_id']),headers=login(setup,'bob')).status_code==404
    assert client.post('/api/audit-packages',json=selection(doc['version_id']),headers=login(setup,'auditor')).status_code==200
    assert review(setup,doc['version_id'],decision='withdrawn',expected=approved['id'],subject='alice').status_code==200
    assert client.post('/api/audit-packages',json=selection(doc['version_id']),headers=login(setup,'auditor')).status_code==404


def test_invalid_empty_duplicate_and_outside_period_selections_are_rejected(setup):
    response,doc=exported(setup)
    client=setup[4]
    assert client.post('/api/audit-packages',json=selection(),headers=login(setup)).status_code==400
    value=selection(doc['version_id']);value['version_ids']*=2
    assert client.post('/api/audit-packages',json=value,headers=login(setup)).status_code==400
    run=finish_run(setup[1],setup[2],'alice')
    value=selection(run_id=run['id']);value.update(period_start='2020-01-01T00:00:00Z',period_end='2020-02-01T00:00:00Z')
    assert client.post('/api/audit-packages',json=value,headers=login(setup)).status_code==400
    assert client.post('/api/audit-packages',json=selection(doc['version_id']),headers={**login(setup),'X-ClearTrail-Workspace':setup[3]}).status_code==409


@pytest.mark.parametrize('attack',['path','duplicate','html','approval','scan','content'])
def test_rehashed_forged_views_and_graphs_do_not_pass_verification(setup,tmp_path,attack):
    response,doc=exported(setup)
    with zipfile.ZipFile(io.BytesIO(response.content)) as archive:
        files={name:archive.read(name) for name in archive.namelist()}
    index=json.loads(files['index.json'])
    if attack=='html':files['report.html']=b'<script>unsafe()</script>'
    elif attack=='approval':
        index['documents'][0]['reviews'][-1]['reviewer']='alice';files['index.json']=canonical(index)
    elif attack=='content':files[index['documents'][0]['path']]=b'changed evidence'
    elif attack=='scan':
        index['control_inventory']=[];files['index.json']=canonical(index)
    manifest=json.loads(files['manifest.json'])
    manifest['files']={name:hashlib.sha256(raw).hexdigest() for name,raw in files.items() if name!='manifest.json'}
    files['manifest.json']=canonical(manifest)
    path=tmp_path/'forged.zip'
    with zipfile.ZipFile(path,'w') as archive:
        for name,raw in files.items():archive.writestr(name,raw)
        if attack=='path':archive.writestr('../outside.txt',b'bad')
        if attack=='duplicate':archive.writestr('index.json',files['index.json'])
    with pytest.raises(ValueError):verify_audit_package(path)


def test_invalid_deflate_stream_is_a_validation_error(setup,tmp_path):
    response,doc=exported(setup)
    with zipfile.ZipFile(io.BytesIO(response.content)) as archive:
        files={name:archive.read(name) for name in archive.namelist()}
    output=io.BytesIO()
    with zipfile.ZipFile(output,'w',zipfile.ZIP_DEFLATED) as archive:
        for name,raw in files.items():archive.writestr(name,raw)
    raw=bytearray(output.getvalue())
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        info=archive.getinfo('index.json')
        offset=info.header_offset+30+len(info.filename.encode())+len(info.extra)
    raw[offset]=(raw[offset]&~7)|7  # reserved DEFLATE block type
    path=tmp_path/'invalid-deflate.zip';path.write_bytes(raw)
    with pytest.raises(ValueError):verify_audit_package(path)
