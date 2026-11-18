#!/usr/bin/env python3
"""Create new Phase 2D smoke plans for six groups; never overwrite files."""
import copy, csv, json, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PLANS = ROOT / 'tests' / 'smoke' / 'plans'
MANIFEST = ROOT / 'tests' / 'smoke' / 'phase2d_batch_manifest.csv'
BASE = {
 's3': ROOT/'tests/compliant/s3_kms_cmk_india/plan.json',
 'eu': ROOT/'tests/compliant/s3_kms_cmk_eu/plan.json',
 'rds': ROOT/'tests/compliant/rds_encrypted_cmk_india/plan.json',
 'iam': ROOT/'tests/compliant/iam_least_privilege_india/plan.json',
 'kms': ROOT/'tests/compliant/kms_rotation_enabled_india/plan.json',
}
FIELDS = ['case_id','group','plan_file','context','expected_controls','notes']
rows, plans = [], {}

def load(key):
 p=BASE[key]
 if not p.is_file(): raise FileNotFoundError(p)
 return json.loads(p.read_text(encoding='utf-8-sig'))
def rc(plan, typ, address=None):
 for x in plan.get('resource_changes',[]):
  if x.get('type')==typ and (address is None or x.get('address')==address): return x
 raise KeyError(f'{typ} {address or ""}')
def cfg(plan,address):
 for x in plan['configuration']['root_module']['resources']:
  if x.get('address')==address: return x
 raise KeyError(address)
def region(plan,value,key='aws'):
 pc=plan.setdefault('configuration',{}).setdefault('provider_config',{})
 pc.setdefault(key,{'name':'aws','full_name':'registry.terraform.io/hashicorp/aws','version_constraint':'~> 6.0','expressions':{}})
 pc[key].setdefault('expressions',{})['region']=value if isinstance(value,dict) else {'constant_value':value}
def clean_rds():
 p=load('rds'); x=rc(p,'aws_db_instance'); x['change']['after']['backup_retention_period']=7; x['change']['after']['publicly_accessible']=False
 u=x['change'].setdefault('after_unknown',{}); u.pop('backup_retention_period',None); u.pop('publicly_accessible',None)
 return p
def rds_value(p,key,v):
 x=rc(p,'aws_db_instance'); a=x['change']['after']; u=x['change'].setdefault('after_unknown',{}); u.pop(key,None)
 if v=='ABSENT': a.pop(key,None)
 elif v=='UNKNOWN': a.pop(key,None); u[key]=True
 else: a[key]=v
def iam_doc(action='s3:GetObject',resource='arn:aws:s3:::scof-finance-data/*',scalar_statement=False):
 st={'Effect':'Allow','Action':action,'Resource':resource}
 return json.dumps({'Version':'2012-10-17','Statement':st if scalar_statement else [st]},separators=(',',':'))
def pab(flags,unknown=None):
 p=load('s3'); p['resource_changes'].append({'address':'aws_s3_bucket_public_access_block.smoke','mode':'managed','type':'aws_s3_bucket_public_access_block','name':'smoke','provider_name':'registry.terraform.io/hashicorp/aws','change':{'actions':['create'],'before':None,'after':flags,'after_unknown':unknown or {}}}); return p
def log_plan(days):
 p=load('s3'); p['resource_changes']=[{'address':'aws_cloudwatch_log_group.smoke','mode':'managed','type':'aws_cloudwatch_log_group','name':'smoke','provider_name':'registry.terraform.io/hashicorp/aws','change':{'actions':['create'],'before':None,'after':{} if days=='UNKNOWN' else {'retention_in_days':days},'after_unknown':{'retention_in_days':True} if days=='UNKNOWN' else {}}}]; p['configuration']['root_module']['resources']=[]; return p
def add(case,group,p,contexts,expected,note):
 filename=f'phase2d_batch_{case}.json'; plans[filename]=p
 for context in contexts: rows.append({'case_id':case,'group':group,'plan_file':f'tests/smoke/plans/{filename}','context':context,'expected_controls':';'.join(expected),'notes':note})
def s3_algorithm(p,alg): rc(p,'aws_s3_bucket_server_side_encryption_configuration')['change']['after']['rule'][0]['apply_server_side_encryption_by_default'][0]['sse_algorithm']=alg
def s3_key(p,kind):
 d=cfg(p,'aws_s3_bucket_server_side_encryption_configuration.data')['expressions']['rule'][0]['apply_server_side_encryption_by_default'][0]
 vals={'MISSING':None,'NULL':{'constant_value':None},'AWS_ALIAS':{'constant_value':'alias/aws/s3'},'UNKNOWN':{'references':['var.s3_kms_key_arn']},'MALFORMED':{'constant_value':'not-a-valid-key'}}
 if kind=='MISSING': d.pop('kms_master_key_id',None)
 else: d['kms_master_key_id']=vals[kind]

def main():
 if not PLANS.is_dir(): raise FileNotFoundError(PLANS)
 # Build all plans in memory first, then check every target before writing anything.
 # GROUP 1: default, alias, multiple, missing/null/nonliteral provider regions.
 p=load('s3'); region(p,'ap-south-1'); add('region_default_allowed','1-region',p,['india-finance'],[],'Default provider; allowed India region.')
 p=load('s3'); region(p,'us-east-1'); add('region_default_disallowed','1-region',p,['india-finance'],['REGION-RESTRICTION'],'Default provider; disallowed region.')
 for suffix,val in [('alias_allowed','ap-south-2'),('alias_disallowed','us-east-1')]:
  p=load('s3'); p['configuration']['provider_config']={'aws.replica':{'name':'aws','full_name':'registry.terraform.io/hashicorp/aws','version_constraint':'~> 6.0','expressions':{'region':{'constant_value':val}}}}
  add('region_'+suffix,'1-region',p,['india-finance'],[] if suffix.endswith('allowed') else ['REGION-RESTRICTION'],'Aliased AWS provider region.')
 p=load('s3'); p['configuration']['provider_config']['aws.replica']={'name':'aws','full_name':'registry.terraform.io/hashicorp/aws','version_constraint':'~> 6.0','expressions':{'region':{'constant_value':'eu-central-1'}}}
 add('region_two_providers_one_bad','1-region',p,['india-finance'],['REGION-RESTRICTION'],'Default allowed plus disallowed replica provider.')
 for suffix,expr in [('missing',None),('null',{'constant_value':None}),('unknown',{'references':['var.aws_region']})]:
  p=load('s3'); p['configuration']['provider_config']['aws']['expressions'].pop('region',None)
  if expr is not None: p['configuration']['provider_config']['aws']['expressions']['region']=expr
  add('region_'+suffix,'1-region',p,['india-finance'],['REGION-RESTRICTION'],'Region expression absent/null/non-literal.')
 p=load('eu'); region(p,'eu-central-1'); add('region_eu_allowed','1-region',p,['eu'],[],'EU provider; allowed EU region.')
 p=load('s3'); p['configuration'].pop('provider_config',None); add('region_provider_config_absent','1-region',p,['india-finance'],[],'No provider_config; characterises current fail-open behaviour.')
 # GROUP 2: IAM document forms, missing/null/unknown/malformed and admin attachment.
 cases=[('least_privilege',iam_doc(),[]),('wildcard_list',iam_doc(['*'],['*']),['IAM-NO-WILDCARD-ADMIN']),('wildcard_scalar',iam_doc('*','*'),['IAM-NO-WILDCARD-ADMIN']),('wildcard_action_scoped_resource',iam_doc('*','arn:aws:s3:::bucket/*'),[]),('scoped_action_wildcard_resource',iam_doc('s3:GetObject','*'),[]),('wildcard_statement_scalar',iam_doc('*','*',True),['IAM-NO-WILDCARD-ADMIN'])]
 for name,doc,exp in cases:
  p=load('iam'); rc(p,'aws_iam_policy')['change']['after']['policy']=doc; add('iam_'+name,'2-iam',p,['india-finance'],exp,'IAM policy document shape.')
 for name,state in [('policy_missing','missing'),('policy_null','null'),('policy_unknown','unknown'),('policy_malformed_json','malformed')]:
  p=load('iam'); x=rc(p,'aws_iam_policy')['change']
  if state in ('missing','unknown'): x['after'].pop('policy',None)
  elif state=='null': x['after']['policy']=None
  else: x['after']['policy']='{not-json'
  if state=='unknown': x.setdefault('after_unknown',{})['policy']=True
  add('iam_'+name,'2-iam',p,['india-finance'],[],'IAM policy absent/null/unknown/malformed; observe actual result.')
 p=load('iam'); p['resource_changes'].append({'address':'aws_iam_role_policy_attachment.admin','mode':'managed','type':'aws_iam_role_policy_attachment','name':'admin','provider_name':'registry.terraform.io/hashicorp/aws','change':{'actions':['create'],'before':None,'after':{'policy_arn':'arn:aws:iam::aws:policy/AdministratorAccess'},'after_unknown':{}}})
 add('iam_administrator_access_attachment','2-iam',p,['india-finance'],['IAM-NO-WILDCARD-ADMIN'],'AdministratorAccess managed-policy attachment.')
 # GROUP 3: S3 PAB and RDS public accessibility.
 flags={'block_public_acls':True,'block_public_policy':True,'ignore_public_acls':True,'restrict_public_buckets':True}
 add('access_s3_all_true','3-access',pab(flags),['india-finance'],[],'All four S3 public-access protections true.')
 f=dict(flags,block_public_policy=False); add('access_s3_one_false','3-access',pab(f),['india-finance'],['ACCESS-EXPOSURE'],'One S3 public-access flag false.')
 add('access_s3_all_false','3-access',pab({k:False for k in flags}),['india-finance'],['ACCESS-EXPOSURE'],'All four S3 public-access flags false.')
 for name,f,u in [('s3_flag_absent',{k:v for k,v in flags.items() if k!='block_public_acls'},{}),('s3_flag_null',dict(flags,block_public_acls=None),{}),('s3_flag_unknown',{k:v for k,v in flags.items() if k!='block_public_acls'},{'block_public_acls':True})]:
  add('access_'+name,'3-access',pab(f,u),['india-finance'],['ACCESS-EXPOSURE'] if u else [],'S3 PAB flag absent/null/unknown.')
 for name,v,exp in [('rds_public',True,['ACCESS-EXPOSURE']),('rds_private',False,[]),('rds_null',None,[]),('rds_absent','ABSENT',[]),('rds_unknown','UNKNOWN',['ACCESS-EXPOSURE'])]:
  p=clean_rds(); rds_value(p,'publicly_accessible',v); add('access_'+name,'3-access',p,['india-finance'],exp,'RDS public accessibility value state.')
 # GROUP 4: backup retention boundaries.
 for name,v,exp in [('one_day',1,[]),('zero_days',0,['BACKUP-RESILIENCE']),('negative_days',-1,['BACKUP-RESILIENCE']),('thirty_five_days',35,[]),('null',None,[]),('absent','ABSENT',[]),('unknown','UNKNOWN',['BACKUP-RESILIENCE'])]:
  p=clean_rds(); rds_value(p,'backup_retention_period',v); add('backup_'+name,'4-backup',p,['india-finance'],exp,'RDS backup retention boundary/state.')
 # GROUP 5: KMS rotation and synthetic imported-origin probe.
 rot=[('symmetric_enabled',{'key_spec':'SYMMETRIC_DEFAULT','enable_key_rotation':True},{},[]),('symmetric_disabled',{'key_spec':'SYMMETRIC_DEFAULT','enable_key_rotation':False},{},['KEY-ROTATION']),('asymmetric_disabled',{'key_spec':'RSA_2048','enable_key_rotation':False},{},[]),('key_spec_missing',{'enable_key_rotation':False},{},['KEY-ROTATION']),('key_spec_null',{'key_spec':None,'enable_key_rotation':False},{},['KEY-ROTATION']),('imported_origin_synthetic',{'key_spec':'SYMMETRIC_DEFAULT','origin':'EXTERNAL','enable_key_rotation':False},{},['KEY-ROTATION']),('key_spec_unknown',{'enable_key_rotation':False},{'key_spec':True},['KEY-ROTATION'])]
 for name,after,unknown,exp in rot:
  p=load('kms'); k=rc(p,'aws_kms_key'); k['change']['after']=after; k['change']['after_unknown']=unknown
  add('rotation_'+name,'5-rotation',p,['india-finance'],exp,'KMS rotation; EXTERNAL origin case is synthetic, plan-schema visibility unverified.' if name=='imported_origin_synthetic' else 'KMS key-spec/rotation state.')
 # GROUP 6: one isolated failing plan per control, exercised in all contexts.
 contexts=['india-finance','eu','india-healthcare','india']
 p=load('s3'); region(p,'us-east-1'); add('coverage_region','6-context-coverage',p,contexts,['REGION-RESTRICTION'],'Region control dispatch across contexts.')
 p=load('s3'); s3_algorithm(p,'AES256'); add('coverage_encryption','6-context-coverage',p,contexts,['DATA-ENCRYPTION'],'Encryption control dispatch across contexts.')
 p=load('s3'); s3_key(p,'AWS_ALIAS'); add('coverage_key_ownership','6-context-coverage',p,contexts,['KEY-OWNERSHIP'],'Key ownership control dispatch across contexts.')
 p=load('kms'); rc(p,'aws_kms_key')['change']['after']['enable_key_rotation']=False; add('coverage_key_rotation','6-context-coverage',p,contexts,['KEY-ROTATION'],'Key rotation control dispatch across contexts.')
 p=load('iam'); rc(p,'aws_iam_policy')['change']['after']['policy']=iam_doc('*','*'); add('coverage_iam','6-context-coverage',p,contexts,['IAM-NO-WILDCARD-ADMIN'],'IAM control dispatch across contexts.')
 add('coverage_log_retention','6-context-coverage',log_plan(30),contexts,['LOG-RETENTION'],'Log retention control dispatch across contexts.')
 add('coverage_access_exposure','6-context-coverage',pab(dict(flags,block_public_policy=False)),contexts,['ACCESS-EXPOSURE'],'Access exposure control dispatch across contexts.')
 p=clean_rds(); rds_value(p,'backup_retention_period',0); add('coverage_backup_resilience','6-context-coverage',p,contexts,['BACKUP-RESILIENCE'],'Backup resilience control dispatch across contexts.')
 enabled={'REGION-RESTRICTION':{'india-finance','eu'},'LOG-RETENTION':{'india-finance','india-healthcare','india'}}
 # Other six controls are enabled in all four listed contexts. Give each context
 # its own plan copy so an EU run of a non-region test does not accidentally
 # acquire an unrelated India-region violation.
 for row in rows:
  if row['group']=='6-context-coverage':
   control=row['expected_controls']
   if control in enabled and row['context'] not in enabled[control]: row['expected_controls']=''
   if row['case_id']!='coverage_region':
    original_name=Path(row['plan_file']).name
    original=plans[original_name]
    context_name=row['context'].replace('-','_')
    variant_name=f"{Path(original_name).stem}_{context_name}.json"
    variant=copy.deepcopy(original)
    region(variant, 'eu-central-1' if row['context']=='eu' else 'ap-south-1')
    plans[variant_name]=variant
    row['plan_file']=f'tests/smoke/plans/{variant_name}'
 # Remove shared base plans used only as templates for context-specific copies.
 for case in ['coverage_encryption','coverage_key_ownership','coverage_key_rotation',
              'coverage_iam','coverage_log_retention','coverage_access_exposure',
              'coverage_backup_resilience']:
  plans.pop(f'phase2d_batch_{case}.json',None)
 # Preflight all destinations before writing anything.
 targets=[PLANS/f for f in plans]
 if MANIFEST.exists(): raise FileExistsError(f'Refusing to overwrite {MANIFEST}')
 existing=[str(x) for x in targets if x.exists()]
 if existing: raise FileExistsError('Refusing to overwrite existing plans:\n'+'\n'.join(existing))
 for filename,obj in plans.items(): (PLANS/filename).write_text(json.dumps(obj,indent=2)+'\n',encoding='utf-8')
 with MANIFEST.open('x',newline='',encoding='utf-8') as h:
  w=csv.DictWriter(h,fieldnames=FIELDS); w.writeheader(); w.writerows(rows)
 print('Phase 2D six-group batch created.')
 print(f'New plan files: {len(plans)}')
 print(f'Plan/context manifest rows: {len(rows)}')
 print(f'Manifest: {MANIFEST.relative_to(ROOT)}')
 print('Only new phase2d_batch_* smoke files were created; no existing files or policies changed.')

if __name__=='__main__':
 try: main()
 except Exception as e: print(f'ERROR: {e}',file=sys.stderr); raise
