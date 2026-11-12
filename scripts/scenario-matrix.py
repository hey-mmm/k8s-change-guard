#!/usr/bin/env python3
"""Reproducible risk matrix using synthetic evidence and explicit AI stubs.

This is regression evidence, not a claim of 25 live cluster/model experiments.
Live GitHub, Kubernetes and DeepSeek proofs are recorded separately.
"""
from pathlib import Path
import argparse,copy,json,sys,time
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tests'))
from test_core_support import base_resources,base_config,base_evidence,base_context,ai_ok
from change_guard.engine import evaluate


def scenarios():
    return [
      ('normal-digest','PASS','image',None),
      ('zero-replicas','BLOCK','replicas',0),
      ('readiness-deleted','BLOCK','readiness',None),
      ('startup-failure','BLOCK','env',('DEMO_STARTUP_FAIL','true')),
      ('error-injection','BLOCK','env',('DEMO_ERROR_RATE','1')),
      ('latency-injection','BLOCK','env',('DEMO_LATENCY_MS','3000')),
      ('unapproved-image','BLOCK','bad_image',None),
      ('mutable-tag','BLOCK','tag',None),
      ('memory-below-measured-use','BLOCK','memory','64Mi'),
      ('large-cpu-reduction','REVIEW','cpu','100m'),
      ('current-error-rate','REVIEW','metric',('error_ratio',0.2)),
      ('current-slow-service','REVIEW','metric',('p95_seconds',2)),
      ('rolling-capacity-shortage','REVIEW','capacity',None),
      ('replica-capacity-growth','REVIEW','replicas',100),
      ('metrics-unavailable','ERROR','metric',('memory_working_set_bytes',None)),
      ('stale-raw-sample','ERROR','stale',None),
      ('missing-counter-series','ERROR','series',None),
      ('nonfinite-memory','ERROR','metric',('memory_working_set_bytes',float('nan'))),
      ('model-timeout','ERROR','ai_error',None),
      ('model-error-cannot-lower-block','BLOCK','block_ai_error',None),
      ('model-new-risk','REVIEW','ai_risk',None),
      ('unexpected-sidecar','BLOCK','sidecar',None),
      ('envfrom-fault-reference','BLOCK','envfrom',None),
      ('deployment-deleted','BLOCK','delete',None),
      ('privileged-container','BLOCK','privileged',None),
    ]


def run():
    now=int(time.time());records=[]
    for name,expected,operation,value in scenarios():
        old=base_resources();new=copy.deepcopy(old)
        deployment=new[0];container=deployment['spec']['template']['spec']['containers'][0]
        evidence=base_evidence(now=now);ai=ai_ok();config=base_config(ai_required=True)
        if operation=='image':container['image']='ghcr.io/hey-mmm/observability-demo@sha256:'+'b'*64
        elif operation=='replicas':deployment['spec']['replicas']=value
        elif operation=='readiness':container.pop('readinessProbe')
        elif operation=='env':
            next(e for e in container['env'] if e['name']==value[0])['value']=value[1]
        elif operation=='bad_image':container['image']='ghcr.io/evil/app@sha256:'+'a'*64
        elif operation=='tag':container['image']='ghcr.io/hey-mmm/observability-demo:latest'
        elif operation=='memory':container['resources']['limits']['memory']=value
        elif operation=='cpu':container['resources']['limits']['cpu']=value
        elif operation=='metric':evidence['metrics'][value[0]]=value[1]
        elif operation=='capacity':evidence['capacity']['available_cpu_millicores']=10
        elif operation=='stale':evidence['metrics']['source_timestamps']['memory_working_set_bytes']=now-600
        elif operation=='series':evidence['metrics']['series_presence']['requests_total']=False
        elif operation=='ai_error':ai={'status':'error','model':'deepseek-chat','error':'simulated timeout'}
        elif operation=='block_ai_error':
            deployment['spec']['replicas']=0;ai={'status':'error','model':'deepseek-chat','error':'simulated timeout'}
        elif operation=='ai_risk':
            ai=ai_ok(risks=[{'title':'Additional rollout concern','detail':'Synthetic model-risk test'}])
        elif operation=='sidecar':
            sidecar=copy.deepcopy(container);sidecar['name']='sidecar';sidecar['command']=['/bin/sh','-c','id']
            deployment['spec']['template']['spec']['containers'].append(sidecar)
        elif operation=='envfrom':container['envFrom']=[{'configMapRef':{'name':'faults'}}]
        elif operation=='delete':new=[r for r in new if r['kind']!='Deployment']
        elif operation=='privileged':container['securityContext']['privileged']=True
        rule=evaluate(old,new,evidence,{**config,'ai_required':False},base_context(now=now))
        final=evaluate(old,new,evidence,config,base_context(now=now),ai)
        records.append({'scenario':name,'expected':expected,'rule_decision':rule['decision'],
            'ai_status':ai['status'],'ai_risks':ai.get('additional_risks',[]),
            'actual':final['decision'],'passed':final['decision']==expected,
            'findings':[{'rule_id':f['rule_id'],'severity':f['severity'],'field':f['field']} for f in final['findings']]})
    return {'generated_at':now,'evidence_kind':'synthetic regression; AI stubs are intentional',
            'total':len(records),'passed':sum(x['passed'] for x in records),'scenarios':records}


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--output',required=True)
    args=parser.parse_args();result=run();Path(args.output).parent.mkdir(parents=True,exist_ok=True)
    Path(args.output).write_text(json.dumps(result,indent=2,ensure_ascii=False),encoding='utf-8')
    print(json.dumps({'total':result['total'],'passed':result['passed']}))
    raise SystemExit(0 if result['total']==result['passed'] else 1)
