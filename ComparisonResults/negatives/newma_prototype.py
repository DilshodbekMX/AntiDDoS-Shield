"""NEWMA dual-EWMA moving-reference prototype (author's lightweight-baseline idea) vs B0 static z-path.
Training-free A/B on CIC-IDS-2017 cross-day (Monday train -> Friday test), α=0.15 world.
Both thresholds calibrated on Monday-benign only (no attack labels in any fit). Episode dedup = 30 s cooldown.
Bar to beat (prior work): online-conformal 26.3% cross-day at episode level."""
import os, sys, json, math
sys.path.insert(0, '/home/detector/Projects/antiddos/experiment')
os.chdir('/home/detector/Projects/antiddos/experiment')
import numpy as np
from feature_filter import filter_active, PRODUCTION_39_FEATURES
from baselines import ThreeTierBaseline, LOG_TRANSFORM_FEATURES
from datetime import datetime, timezone

CACHE='cache'
MON=json.load(open(f'{CACHE}/cicids2017_pcap_monday.json'))['per_ip_windows']
FRI=json.load(open(f'{CACHE}/cicids2017_pcap_friday.json'))['per_ip_windows']
COOLDOWN=30.0; TARGET_FPR=0.01; THETA_INIT=4.0

# active features on monday benign sample
samp=[];
for ip,rows in MON.items():
    samp.extend(rows[:50])
    if len(samp)>=5000: break
USED,inert=filter_active(PRODUCTION_39_FEATURES, samp)

def logx(f,x): return math.log(x+1.0) if f in LOG_TRANSFORM_FEATURES else float(x)

def episodes(alarm_times):
    """collapse alarm window timestamps (sorted) into episodes via 30s cooldown."""
    if not alarm_times: return 0
    at=sorted(alarm_times); ep=1
    for i in range(1,len(at)):
        if at[i]-at[i-1] > COOLDOWN: ep+=1
    return ep

# ---- B0: static three-tier z-path (fit Monday benign, frozen on Friday) ----
def b0_scores(train_rows, test_rows):
    bl=ThreeTierBaseline(USED)
    for r in train_rows:
        bl.update(r, datetime.fromtimestamp(r['_dt'], tz=timezone.utc))
    out=[]
    for r in test_rows:
        t=r['_dt']
        dt=datetime.fromtimestamp(t, tz=timezone.utc)
        z=bl.z_scores(r, dt)
        mx=0.0
        for tier in ('t1','t2','t3'):
            d=z.get(tier)
            if d:
                for f,v in d.items():
                    if v is not None and abs(v)>mx: mx=abs(v)
        out.append((t, mx))
    return out

# ---- NEWMA: per-feature dual EWMA (fast/slow), both update every window (moving reference) ----
AF, ASL = 0.15, 0.01   # fast = tier-1 alpha; slow = tier-3 alpha
def newma_scores(train_rows, test_rows):
    feats=USED
    fast={f:None for f in feats}; slow={f:None for f in feats}
    # warm on monday, collect benign |fast-slow| per feature for scaling
    devs={f:[] for f in feats}
    def step(r, collect):
        for f in feats:
            x=logx(f, r.get(f,0.0))
            fast[f]= x if fast[f] is None else fast[f]+AF*(x-fast[f])
            slow[f]= x if slow[f] is None else slow[f]+ASL*(x-slow[f])
            if collect: devs[f].append(abs(fast[f]-slow[f]))
    for r in train_rows: step(r, True)
    scale={f:(np.std(devs[f]) if len(devs[f])>10 and np.std(devs[f])>1e-9 else 1.0) for f in feats}
    out=[]
    for r in test_rows:
        step(r, False)
        t=r['_dt']
        mx=max(abs(fast[f]-slow[f])/scale[f] for f in feats)
        out.append((t, mx))
    return out

def eval_pool(scorer):
    # collect per-IP scores; victim=192.168.10.50; calibrate theta on monday-benign max-scores
    victim='192.168.10.50'
    # calibration scores: monday-benign of all common IPs (score each monday window with a fresh baseline is heavy;
    # instead calibrate on the FRIDAY-benign-equivalent? no -> use monday tail). We calibrate on the victim+uninvolved monday.
    calib=[]
    perip_test={}
    common=[ip for ip in FRI if ip in MON and len(MON[ip])>=60 and len(FRI[ip])>=60]
    for ip in common[:400]:
        tr=MON[ip]; te=FRI[ip]
        sc=scorer(tr, te)
        perip_test[ip]=(te, sc)
        # monday self-calibration: score monday's own held-out tail with the monday-fit model
        n=len(tr); ho=tr[int(n*0.8):]
        sc_ho=scorer(tr[:int(n*0.8)], ho)
        calib.extend(s for _,s in sc_ho)
    theta=float(np.quantile(calib, 1-TARGET_FPR)) if calib else THETA_INIT
    theta=max(theta, 1e-6)
    # measure friday: victim DR (attack windows), uninvolved FPR (benign windows), episode-level
    v_tp=v_n=0; u_fp=u_n=0; u_ep=[]; u_ips=0; v_ip_hit=0; v_ips=0
    for ip,(te,sc) in perip_test.items():
        atk=[i for i,r in enumerate(te) if r.get('_is_attack')]
        is_victim = ip==victim or len(atk)>=30
        alarm_t=[t for (t,s) in sc if s>=theta]
        if is_victim:
            v_ips+=1
            for i,(t,s) in enumerate(sc):
                if i in set(atk):
                    v_n+=1; v_tp+= (1 if s>=theta else 0)
            if any(s>=theta for i,(t,s) in enumerate(sc) if i in set(atk)): v_ip_hit+=1
        else:
            u_ips+=1
            ben=[(t,s) for (t,s) in sc]
            for t,s in ben:
                u_n+=1; u_fp+= (1 if s>=theta else 0)
            u_ep.append(episodes([t for t,s in ben if s>=theta]))
    return dict(theta=round(theta,3),
        victim_DR=round(100*v_tp/max(v_n,1),1),
        uninvolved_FPR=round(100*u_fp/max(u_n,1),1),
        mean_episodes_per_uninvolved_IP=round(np.mean(u_ep) if u_ep else 0,2),
        frac_uninvolved_IPs_with_any_alarm=round(100*sum(1 for e in u_ep if e>0)/max(len(u_ep),1),1),
        n_uninvolved=u_ips, n_victim=v_ips)

print("features:", len(USED))
print("B0  (static z-path):", json.dumps(eval_pool(b0_scores)))
print("NEWMA (moving dual-EWMA):", json.dumps(eval_pool(newma_scores)))
