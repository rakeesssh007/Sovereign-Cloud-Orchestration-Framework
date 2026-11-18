#!/usr/bin/env python3
"""Run all Phase 2D smoke rows through OPA and Conftest and compare results."""
import csv, re, subprocess, sys
from datetime import datetime
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
MANIFEST=ROOT/'tests'/'smoke'/'phase2d_batch_manifest.csv'
CLI=ROOT/'cli'/'compliance-linter'/'scof_lint.py'
REPORT_DIR=ROOT/'tests'/'smoke'/'results'
CONTROLS={'REGION-RESTRICTION','DATA-ENCRYPTION','KEY-OWNERSHIP','KEY-ROTATION',
          'IAM-NO-WILDCARD-ADMIN','LOG-RETENTION','ACCESS-EXPOSURE',
          'BACKUP-RESILIENCE','CONTROL-SET'}

def parse_controls(text):
    return {x for x in re.findall(r'\[([A-Z][A-Z0-9-]+)\]',text) if x in CONTROLS}

def run(plan,context,engine):
    cmd=[sys.executable,str(CLI),'--plan',str(plan),'--context',context,'--engine',engine,'--format','text']
    p=subprocess.run(cmd,cwd=ROOT,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,
                     text=True,encoding='utf-8',errors='replace')
    return p.returncode,parse_controls(p.stdout or ''),p.stdout or ''

def status(code):
    return 'PASS' if code==0 else ('POLICY_FAIL' if code==1 else f'TOOL_ERROR_{code}')

def main():
    if not MANIFEST.is_file(): raise FileNotFoundError(f'{MANIFEST}; run phase2d_create_batch.py first')
    if not CLI.is_file(): raise FileNotFoundError(CLI)
    with MANIFEST.open(newline='',encoding='utf-8-sig') as h: cases=list(csv.DictReader(h))
    if not cases: raise RuntimeError('Manifest has no rows')
    REPORT_DIR.mkdir(parents=True,exist_ok=True)
    report=REPORT_DIR/'phase2d_batch_results.csv'
    if report.exists(): report=REPORT_DIR/f"phase2d_batch_results_{datetime.now():%Y%m%d_%H%M%S}.csv"
    if report.exists(): raise FileExistsError(report)
    output_rows=[]; parity=[]; expected_mismatches=[]; errors=0
    for i,c in enumerate(cases,1):
        plan=ROOT/c['plan_file']
        if not plan.is_file(): raise FileNotFoundError(plan)
        expected={x for x in c['expected_controls'].split(';') if x}
        results={}
        print(f"[{i}/{len(cases)}] {c['case_id']} | {c['context']} | {c['group']}")
        for engine in ('opa','conftest'):
            code,actual,text=run(plan,c['context'],engine); results[engine]=(code,actual,text)
            match=actual==expected
            print(f"  {engine:8} {status(code):14} findings={','.join(sorted(actual)) or '(none)'} expected_match={match}")
            if code>=2:
                errors+=1; print('  TOOL OUTPUT:\n'+text.rstrip())
            if not match: expected_mismatches.append((c['case_id'],c['context'],engine,sorted(expected),sorted(actual),status(code)))
            output_rows.append({
                'case_id':c['case_id'],'group':c['group'],'plan_file':c['plan_file'],
                'context':c['context'],'engine':engine,'exit_code':code,'status':status(code),
                'expected_controls':';'.join(sorted(expected)),'actual_controls':';'.join(sorted(actual)),
                'expected_match':str(match),'notes':c['notes'],'output':text.replace('\r','').strip()
            })
        a,b=results['opa'],results['conftest']
        if status(a[0])!=status(b[0]) or a[1]!=b[1]:
            parity.append((c['case_id'],c['context'],status(a[0]),sorted(a[1]),status(b[0]),sorted(b[1])))
    cols=['case_id','group','plan_file','context','engine','exit_code','status','expected_controls',
          'actual_controls','expected_match','notes','output']
    with report.open('x',newline='',encoding='utf-8') as h:
        w=csv.DictWriter(h,fieldnames=cols); w.writeheader(); w.writerows(output_rows)
    print('\n'+'='*72+'\nPHASE 2D SIX-GROUP SMOKE SUMMARY\n'+'='*72)
    print(f'Manifest rows: {len(cases)} | Engine runs: {len(output_rows)}')
    print(f'OPA/Conftest parity mismatches: {len(parity)}')
    print(f'Expected-result mismatches: {len(expected_mismatches)}')
    print(f'Tooling errors (exit >= 2): {errors}')
    print(f'Results CSV: {report.relative_to(ROOT)}')
    if parity:
        print('\nPARITY MISMATCHES:')
        for x in parity: print(' ',x)
    if expected_mismatches:
        print('\nEXPECTED-RESULT MISMATCHES:')
        for x in expected_mismatches: print(' ',x)
    if not parity and not expected_mismatches and not errors:
        print('\nAll cases matched declared expectations and both engines agreed.')
        return 0
    print('\nReview all mismatches/tool errors before accepting this batch.')
    return 1

if __name__=='__main__':
    try: raise SystemExit(main())
    except Exception as e: print(f'ERROR: {e}',file=sys.stderr); raise
