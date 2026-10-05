"""Run with: streamlit run app.py. See README.md before deployment."""
import io
import json
import os
import time
import zipfile
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

import pandas as pd
import plotly.express as px
import streamlit as st
from core import SCHEMAS, ROLES, PERMISSIONS, Store, derive, alerts_for, risk_class

st.set_page_config(page_title='Khwezi Mine Monitor', page_icon='⛏️', layout='wide')
st.markdown('''<style>
[data-testid="stAppViewContainer"] {background-color:#f5f7fb;}
[data-testid="stMetric"] {background:white;padding:16px;border-radius:12px;border:1px solid #dde5ef;}
h1,h2,h3 {color:#15344b;}
</style>''', unsafe_allow_html=True)

def setting(key, default):
    try:
        return st.secrets.get(key, os.environ.get(key, default))
    except FileNotFoundError:
        return os.environ.get(key, default)

def frame(entity, rows):
    if not rows:
        return pd.DataFrame(columns=list(SCHEMAS[entity]))
    return pd.DataFrame([derive(entity, r) for r in rows])

def csv_bytes(df):
    # Avoid spreadsheet formula execution when exported user text is opened in Excel.
    safe = df.copy()
    for c in safe.select_dtypes(include=['object', 'string']).columns:
        safe[c] = safe[c].map(lambda v: "'" + v if isinstance(v, str) and v.lstrip().startswith(('=', '+', '-', '@')) else v)
    return safe.to_csv(index=False).encode('utf-8-sig')

def table(df):
    st.dataframe(df, width='stretch', hide_index=True)

def show_chart(df, x, y, title, color=None):
    if df.empty:
        st.info('No records match these filters.')
        return
    fig = px.bar(df, x=x, y=y, color=color, title=title, template='plotly_white')
    fig.update_layout(margin=dict(l=20,r=20,t=55,b=20))
    st.plotly_chart(fig, width='stretch')

def group_count(df, column):
    return df.groupby(column).size().reset_index(name='count')

def record_editor(store, role, entity, rows):
    if role == 'Manager':
        st.caption('Manager access is read-only. Reports and exports are available.')
        return
    with st.expander('Add or edit a record'):
        mode = st.radio('Action', ['Add new record', 'Edit existing record'], horizontal=True, key=f'{entity}_mode')
        current = {}
        editing = mode == 'Edit existing record'
        if editing:
            if not rows:
                st.info('Add a record first.')
                return
            chosen = st.selectbox('Record to edit', [r['id'] for r in rows], key=f'{entity}_chosen')
            current = next(r for r in rows if r['id'] == chosen)
        if entity == 'equipment':
            st.info('Use operating hours and downtime for the SAME reporting period across all equipment. Every save records a new monitoring observation. To complete maintenance, set Operational, enter the next due date and explain the work in maintenance notes.')
        form_key = entity + '_' + str(current.get('id', 'new'))
        with st.form(form_key):
            values = {}
            cols = st.columns(2)
            for i, (name, spec) in enumerate(SCHEMAS[entity].items()):
                with cols[i % 2]:
                    label = name.replace('_', ' ').replace('pct', '%').title()
                    key = form_key + '_' + name
                    default = current.get(name)
                    if spec[0] == 'choice':
                        values[name] = st.selectbox(label, spec[1], index=spec[1].index(default) if default in spec[1] else 0, key=key)
                    elif spec[0] in ('number', 'integer'):
                        cast = int if spec[0] == 'integer' else float
                        values[name] = st.number_input(label, min_value=cast(spec[1]), max_value=cast(spec[2]), value=cast(default if default is not None else spec[3]), step=cast(1), key=key)
                    elif spec[0] == 'date':
                        values[name] = st.date_input(label, value=date.fromisoformat(default) if default else date.today(), key=key).isoformat()
                    elif spec[0] == 'time':
                        values[name] = st.time_input(label, value=datetime.strptime(default or '08:00', '%H:%M').time(), key=key).strftime('%H:%M')
                    else:
                        values[name] = st.text_input(label, value=default or '', disabled=editing and name=='id', key=key)
            submitted = st.form_submit_button('Save record', type='primary')
        if submitted:
            try:
                store.save(role, entity, values, update=editing)
                st.session_state['notice'] = 'Record saved. Dashboard and alerts have been updated.'
                st.rerun()
            except (ValueError, PermissionError) as exc:
                st.error(str(exc))


def main():
    demo = str(setting('DEMO_MODE', 'true')).lower() == 'true'
    store = Store(os.environ.get('KHWEZI_DB', str(Path(__file__).parent / 'data' / 'khwezi.sqlite3')))
    try:
        store.bootstrap(demo=demo, admin_password=setting('ADMIN_PASSWORD', None))
    except ValueError as exc:
        st.error(str(exc))
        st.stop()
    st.title('Khwezi Mine Monitor')
    st.caption('MINN2020A · Health, safety and equipment monitoring · Educational prototype')
    if demo:
        st.warning('DEMONSTRATION MODE · Fictional records and shared demo logins. Do not enter real worker or mine data.')
    st.caption('Thresholds are educational only. Data are manually entered; alerts are in-app and update when the page reruns. This is not a live sensor or emergency notification system.')
    if 'username' not in st.session_state:
        st.subheader('Sign in')
        with st.form('login'):
            username = st.text_input('Username')
            password = st.text_input('Password', type='password')
            submitted = st.form_submit_button('Sign in', type='primary')
        if demo:
            st.info('Demo users: admin, safety, mining, maintenance, manager. Password for all: MineDemo2026!')
        if submitted:
            if time.time() < st.session_state.get('login_wait_until', 0):
                st.error('Too many attempts. Wait one minute and try again.')
            else:
                role = store.login(username.strip(), password)
                if role:
                    st.session_state['username'] = username.strip()
                    st.session_state['login_failures'] = 0
                    st.rerun()
                else:
                    failures = st.session_state.get('login_failures', 0) + 1
                    st.session_state['login_failures'] = failures
                    if failures % 5 == 0:
                        st.session_state['login_wait_until'] = time.time() + 60
                    st.error('Incorrect username or password.')
        st.stop()
    # Look up current role on EVERY rerun, including after an administrator changes it.
    role = store.role_for(st.session_state['username'])
    if role not in ROLES:
        st.session_state.clear()
        st.rerun()
    st.sidebar.title('Mine operations')
    st.sidebar.write(f"{st.session_state['username']} · {role}")
    if st.sidebar.button('Sign out'):
        st.session_state.clear()
        st.rerun()
    allowed = PERMISSIONS[role]
    pages = ['Dashboard']
    pages += [label for entity,label in [('workers','Workers'),('incidents','Incidents'),('equipment','Equipment'),('equipment','Maintenance'),('risks','Risk assessment')] if entity in allowed]
    pages += ['Alerts', 'Analysis', 'Reports']
    if role == 'Administrator':
        pages += ['Manage users', 'Backup and restore']
    page = st.sidebar.radio('Navigate', pages)
    st.sidebar.caption('Local SQLite storage. Download backups before stopping or redeploying the app. Free cloud storage is not guaranteed to persist.')
    if st.sidebar.button('Refresh current data'):
        st.rerun()
    if 'notice' in st.session_state:
        st.success(st.session_state.pop('notice'))
    raw = {entity: store.rows(role, entity) for entity in allowed}
    data = {entity: frame(entity, rows) for entity,rows in raw.items()}
    active = [a for entity,rows in raw.items() for r in rows for a in alerts_for(entity,r)]
    history = store.history(role) if 'equipment' in allowed else []
    cutoff = datetime.now(timezone.utc) - timedelta(days=30)
    repeated = {}
    for event in history:
        if datetime.fromisoformat(event['timestamp']) >= cutoff and event['alerts']:
            repeated[event['equipment_id']] = repeated.get(event['equipment_id'],0) + 1
    for equipment_id, count in repeated.items():
        if count >= 3:
            eq = next((r for r in raw['equipment'] if r['id'] == equipment_id), None)
            if eq:
                active.append(dict(source='equipment', record_id=equipment_id, department=eq['department'], level='Warning', parameter='Repeated alert observations (30 days)', value=str(count), recommended_action='Review repeated abnormal observations and maintenance history.'))
    alert_df = pd.DataFrame(active, columns=['source','record_id','department','level','parameter','value','recommended_action'])
    st.subheader(page)

    if page == 'Dashboard':
        st.caption('All current records in your permitted datasets. Incident totals are all-time; use Analysis to select dates.')
        metrics = []
        if 'workers' in data:
            w = data['workers']
            metrics += [('Workers',len(w)),('Fully PPE compliant',f"{(w.ppe_compliance_pct.eq(100).mean()*100 if len(w) else 0):.1f}%")]
        if 'incidents' in data:
            inc = data['incidents']
            metrics += [('Safety incidents',len(inc)),('Near-miss incident records',int(inc.incident_type.eq('Near miss').sum()))]
        if 'risks' in data:
            r = data['risks']
            metrics += [('Open high / critical observations',int(((r.risk_score>=10)&r.status.ne('Closed')).sum()) if len(r) else 0)]
        if 'equipment' in data:
            eq = data['equipment']
            available = int(((eq.maintenance_status=='Operational')&(eq.condition=='Normal')&eq.due_status.ne('Overdue')).sum()) if len(eq) else 0
            avg = eq.availability_pct.mean() if len(eq) else float('nan')
            metrics += [('Equipment',len(eq)),('Available (prototype rule)', available),('Under maintenance',int(eq.maintenance_status.eq('Under maintenance').sum())),('Mean availability',f'{avg:.1f}%' if pd.notna(avg) else 'N/A'),('Equipment alerts',int(alert_df.source.eq('equipment').sum())),('Critical equipment alerts',int(((alert_df.source=='equipment')&(alert_df.level=='Critical')).sum()))]
        metrics += [('Active alerts',len(active)),('Critical alerts',int(alert_df.level.eq('Critical').sum()))]
        for start in range(0,len(metrics),4):
            for col,(name,value) in zip(st.columns(4),metrics[start:start+4]):
                col.metric(name,value)
        if 'incidents' in data and not data['incidents'].empty:
            show_chart(group_count(data['incidents'],'department'),'department','count','Incidents by department')
        if 'equipment' in data and not data['equipment'].empty:
            show_chart(data['equipment'],'id','availability_pct','Equipment availability (%)','condition')
        st.markdown('**Conditions requiring attention**')
        table(alert_df)

    elif page in ['Workers','Incidents','Equipment','Risk assessment']:
        entity = {'Workers':'workers','Incidents':'incidents','Equipment':'equipment','Risk assessment':'risks'}[page]
        if entity == 'risks':
            st.write('Risk score = likelihood × consequence. Low: 1–4; Medium: 5–9; High: 10–16; Critical: 17–25.')
            c1,c2 = st.columns(2)
            likelihood = c1.slider('Try likelihood',1,5,3)
            consequence = c2.slider('Try consequence',1,5,3)
            score = likelihood*consequence
            level = risk_class(score)
            (st.error if score>=10 else st.info)(f'Risk score {score}: {level}. ' + ('Apply and review controls.' if score>=10 else 'Continue monitoring.'))
        record_editor(store, role, entity, raw[entity])
        df = data[entity].copy()
        query = st.text_input('Search records (literal text)')
        if query and len(df):
            df = df[df.astype(str).apply(lambda c:c.str.contains(query,case=False,regex=False)).any(axis=1)]
        department = st.selectbox('Department', ['All']+sorted(set(r['department'] for r in raw[entity])))
        if department != 'All':
            df = df[df.department==department]
        if entity == 'incidents':
            severity = st.multiselect('Severity',SCHEMAS[entity]['severity'][1],default=SCHEMAS[entity]['severity'][1])
            status = st.multiselect('Status',SCHEMAS[entity]['status'][1],default=SCHEMAS[entity]['status'][1])
            df = df[df.severity.isin(severity)&df.status.isin(status)]
        st.write(f'{len(df)} matching records')
        table(df)
        st.download_button('Download filtered CSV', csv_bytes(df), file_name=entity+'_filtered.csv', mime='text/csv')

    elif page == 'Maintenance':
        eq = data['equipment'].copy()
        st.info('Availability = operating hours ÷ (operating hours + downtime hours) × 100. Zero total hours is N/A. Additional prototype rules: downtime >24 hours, availability <85%, maintenance due within 7 days, and 3+ abnormal saved observations in 30 days.')
        if len(eq):
            eq['abnormal_observations_30d'] = eq.id.map(repeated).fillna(0).astype(int)
            needs = (eq.due_status!='Not due') | (eq.condition!='Normal') | (eq.maintenance_status!='Operational') | (eq.downtime_hours>24) | (eq.availability_pct<85) | (eq.abnormal_observations_30d>=3)
            st.metric('Equipment requiring attention',int(needs.sum()))
            table(eq[needs].sort_values(['maintenance_priority','availability_pct'],ascending=[True,True]))
            show_chart(eq.sort_values('downtime_hours',ascending=False),'id','downtime_hours','Downtime ranking')
        else:
            st.info('No equipment records yet.')
        st.caption('Update status, due date and maintenance notes on the Equipment page. Each equipment save records a timestamped observation.')
        if history:
            table(pd.DataFrame([{'timestamp':h['timestamp'],'equipment_id':h['equipment_id'],'alerts_in_observation':len(h['alerts'])} for h in history]))
        else:
            st.info('No saved monitoring history yet. Seed records are current snapshots; history starts when you save equipment observations.')

    elif page == 'Alerts':
        levels = st.multiselect('Alert levels',['Warning','High','Critical'],default=['Warning','High','Critical'])
        selected = alert_df[alert_df.level.isin(levels)]
        st.metric('Matching active alerts',len(selected))
        table(selected)
        st.caption('Counts measure individual conditions, not unique equipment. Repeated-alert counts measure distinct equipment saves with at least one alert. Resolved current conditions disappear after an update; historical observations remain.')

    elif page == 'Analysis':
        if 'incidents' in data:
            inc = data['incidents'].copy()
            c1,c2 = st.columns(2)
            start = c1.date_input('Incident period starts', date.today()-timedelta(days=60))
            end = c2.date_input('Incident period ends',date.today())
            if start>end:
                st.error('Start date must be on or before end date.')
                return
            inc = inc[(inc.date>=start.isoformat())&(inc.date<=end.isoformat())]
            st.metric('Incidents in selected period',len(inc))
            if not inc.empty:
                group = st.selectbox('Compare incident counts by',['department','shift','incident_type','severity','cause'])
                summary = group_count(inc,group).sort_values('count',ascending=False)
                show_chart(summary,group,'count','Incident comparison')
                table(summary)
                trend = group_count(inc,'date').set_index('date')
                trend.index = pd.to_datetime(trend.index)
                trend = trend.reindex(pd.date_range(start,end),fill_value=0)
                st.plotly_chart(px.line(trend,x=trend.index,y='count',title='Daily incidents (including zero-incident days)',markers=True),width='stretch')
                st.write(f"Near misses: {int(inc.incident_type.eq('Near miss').sum())} · High / critical incidents: {int(inc.severity.isin(['High','Critical']).sum())}")
            else:
                st.info('No incidents in this period.')
        if 'workers' in data and len(data['workers']):
            w=data['workers']
            st.write(f"Fully PPE-compliant workers: {w.ppe_compliance_pct.eq(100).mean()*100:.1f}%. Average individual PPE compliance: {w.ppe_compliance_pct.mean():.1f}%.")
            st.caption('Worker-reported historical near misses are not added to incident-register near misses, because that could double count events.')
        if 'equipment' in data and len(data['equipment']):
            eq = data['equipment'].copy()
            metric = st.selectbox('Rank equipment by',['downtime_hours','availability_pct','vibration_mm_s','temperature_c'])
            eq = eq.sort_values(metric,ascending=metric=='availability_pct',na_position='last')
            show_chart(eq,'id',metric,'Equipment ranking','equipment_type')
            by_type = eq.groupby('equipment_type',as_index=False).downtime_hours.sum()
            show_chart(by_type,'equipment_type','downtime_hours','Total downtime by equipment type')
            st.write(f"Equipment with normal monitored condition: {eq.condition.eq('Normal').mean()*100:.1f}%")
            counts = alert_df[alert_df.source=='equipment'].groupby('record_id').size().reindex(eq.id,fill_value=0).reset_index(name='active_alerts')
            counts.columns=['equipment_id','active_alerts']
            show_chart(counts,'equipment_id','active_alerts','Active alerts by equipment')
            if 'risks' in data:
                risks=data['risks']
                high = risks[(risks.risk_score>=10)&(risks.status!='Closed')] if len(risks) else risks
                combined = eq.groupby('department').downtime_hours.sum().to_frame().join(high.groupby('department').size().rename('open_high_critical_risks'),how='outer').fillna(0).reset_index()
                st.markdown('**Departments: current safety risk and equipment downtime**')
                table(combined)
                st.caption('This comparison uses current snapshots, not the incident date filter. Co-occurrence does not establish causation. Shift incident counts are not exposure-adjusted risk rates.')
        st.markdown('**Recommendations from current monitoring results**')
        table(alert_df[['department','record_id','level','recommended_action']].drop_duplicates())

    elif page == 'Reports':
        st.write('Export permitted datasets, current alerts and a summary. Restricted data are excluded from all report files.')
        summary = {'generated_utc':datetime.now(timezone.utc).isoformat(),'role':role,'dataset_counts':{k:len(v) for k,v in data.items()},'active_alerts':len(active),'critical_alerts':int(alert_df.level.eq('Critical').sum()),'notes':'Educational thresholds; fictional demo data if demo mode enabled. Counts are current/all-time, not date-filtered.'}
        st.json(summary)
        buffer=io.BytesIO()
        with zipfile.ZipFile(buffer,'w',zipfile.ZIP_DEFLATED) as archive:
            archive.writestr('summary.json',json.dumps(summary,indent=2))
            archive.writestr('current_alerts.csv',csv_bytes(alert_df))
            for entity,df in data.items():
                archive.writestr(entity+'.csv',csv_bytes(df))
            if 'equipment' in allowed:
                archive.writestr('monitoring_history.json',json.dumps(history,indent=2))
        st.download_button('Download report ZIP',buffer.getvalue(),'khwezi_report.zip','application/zip')
        for entity,df in data.items():
            st.download_button(f'Download {entity} CSV',csv_bytes(df),entity+'.csv','text/csv',key='export_'+entity)

    elif page == 'Manage users':
        table(pd.DataFrame(store.users(role),columns=['username','role']))
        st.caption('Administrator-only account creation and password/role updates. At least one administrator must remain.')
        with st.form('user_form'):
            action=st.selectbox('Account action',['Create','Update'])
            username=st.text_input('Account username')
            password=st.text_input('New password (at least 12 characters)',type='password')
            new_role=st.selectbox('Account role',ROLES)
            submitted=st.form_submit_button('Save account')
        if submitted:
            try:
                store.set_user(role,username.strip(),password,new_role,replace=action=='Update')
                st.session_state['notice']='Account saved.'
                st.rerun()
            except (ValueError,PermissionError) as exc:
                st.error(str(exc))

    elif page == 'Backup and restore':
        st.info('This JSON backup contains operational records only. It excludes passwords and monitoring history. Download the report ZIP separately for history. Restore replaces all operational records and clears history; accounts remain unchanged.')
        backup={'version':1,'records':raw}
        st.download_button('Download operational backup',json.dumps(backup,indent=2),'khwezi_backup.json','application/json')
        uploaded=st.file_uploader('Restore operational JSON backup',type=['json'])
        confirmed=st.checkbox('I understand restore replaces all operational records and clears monitoring history.')
        if st.button('Restore backup',disabled=not(uploaded and confirmed)):
            try:
                if uploaded.size>10*1024*1024:
                    raise ValueError('Maximum backup size is 10 MB.')
                store.restore(role,json.loads(uploaded.getvalue()))
                st.session_state['notice']='Operational records restored. Monitoring history starts again from new saves.'
                st.rerun()
            except (ValueError,TypeError,KeyError,AttributeError,PermissionError) as exc:
                st.error('Backup could not be restored: '+str(exc))

if __name__ == '__main__':
    main()
