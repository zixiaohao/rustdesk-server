//! ---------------------------------------------------------------------------
//!  hbbs 入网审批网关（Enrollment Gate）
//! ---------------------------------------------------------------------------
//!  设计目标（对应需求）：
//!    1. 新设备接入私有服务端前必须经过审批，默认【拒绝】
//!    2. 审批通过后，设备才能完成注册、才能被控制端连接
//!    3. 控制端实时看到"待审批设备"提示，可一键同意/拒绝
//!    4. 可选：只允许指定 IP/网段的控制端发起连接（防客户横向滥用）
//!
//!  存储：独立 JSON 文件（enroll.json），不侵入原有 sqlite 表结构，
//!        避免 sqlx::query! 编译期校验带来的额外构建复杂度。
//!
//!  管理接口：内嵌 HTTP 服务，默认只监听 127.0.0.1:21120，需 Token。
//! ---------------------------------------------------------------------------

use hbb_common::log;
use lazy_static::lazy_static;
// 注意：本工程 serde 未开启 derive feature，必须用 serde_derive（与 peer.rs 一致）
use serde_derive::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    net::IpAddr,
    sync::RwLock,
};

/// 设备准入状态
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    Pending,
    Approved,
    Rejected,
}

/// 一条准入记录
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Entry {
    pub id: String,
    pub status: Status,
    pub ip: String,
    pub first_seen: i64,
    pub last_seen: i64,
    /// 被拦截的尝试次数
    pub hits: u64,
    pub note: String,
}

lazy_static! {
    static ref STORE: RwLock<HashMap<String, Entry>> = RwLock::new(HashMap::new());
    static ref LAST_SAVE: RwLock<i64> = RwLock::new(0);
}

fn cfg(key: &str) -> String {
    crate::common::get_arg_or(key, String::new())
}

fn data_file() -> String {
    let f = cfg("ENROLL_FILE");
    if f.is_empty() {
        "enroll.json".to_owned()
    } else {
        f
    }
}

fn now() -> i64 {
    chrono::Local::now().timestamp()
}

/// 进程启动时加载
/// ⚠️ 账本文件是「数组」格式（save_now 写出 Vec<Entry>），必须按数组解析。
pub fn load() {
    let f = data_file();
    if let Ok(s) = std::fs::read_to_string(&f) {
        if let Ok(v) = serde_json::from_str::<Vec<Entry>>(&s) {
            let n = v.len();
            let mut st = STORE.write().unwrap();
            st.clear();
            for e in v {
                st.insert(e.id.clone(), e);
            }
            drop(st);
            log::info!("[enroll] loaded {} entries from {}", n, f);
            return;
        }
        log::error!("[enroll] {} 解析失败，从空账本开始", f);
    }
    log::info!("[enroll] 未发现账本，从空开始 ({})", f);
}

/// hbbs 启动自检会注册一个伪设备 ID，不进账本也不拦截
fn ignorable(id: &str) -> bool {
    id.contains("test_hbbs")
}

/// 限频保存：心跳路径每 30 秒最多落盘一次
fn save() {
    let n = now();
    let last = *LAST_SAVE.read().unwrap();
    if n - last < 30 {
        return;
    }
    save_now();
}

/// 立即保存：审批 / 移除等关键动作用
fn save_now() {
    let f = data_file();
    let v: Vec<Entry> = {
        let g = STORE.read().unwrap();
        let mut v: Vec<Entry> = g.values().cloned().collect();
        v.sort_by(|a, b| b.first_seen.cmp(&a.first_seen));
        v
    };
    match serde_json::to_string_pretty(&v) {
        Ok(s) => {
            if let Err(e) = std::fs::write(&f, s) {
                log::error!("[enroll] 写入 {} 失败: {}", f, e);
            }
        }
        Err(e) => log::error!("[enroll] 序列化失败: {}", e),
    }
    *LAST_SAVE.write().unwrap() = now();
}

// ---------------------------------------------------------------- 判定入口

/// 控制端来源 IP 是否被允许
/// ENROLL_CONTROLLER_IPS 未配置 => 不限制控制端（仅靠审批门）
/// 例：ENROLL_CONTROLLER_IPS=203.0.113.10,198.51.100.0/24
pub fn controller_ip_ok(ip: &IpAddr) -> bool {
    let list = cfg("ENROLL_CONTROLLER_IPS");
    let list = list.trim();
    if list.is_empty() {
        return true;
    }
    for item in list.split(',') {
        let item = item.trim();
        if item.is_empty() {
            continue;
        }
        if let Ok(net) = item.parse::<ipnetwork::IpNetwork>() {
            if net.contains(*ip) {
                return true;
            }
        } else if let Ok(single) = item.parse::<IpAddr>() {
            if single == *ip {
                return true;
            }
        } else {
            log::warn!("[enroll] 忽略非法网段配置: {}", item);
        }
    }
    false
}

/// 仅记录设备（不判准入），用于控制端/未知 ID 的留痕
pub fn touch(id: &str, ip: &str) -> Status {
    if id.is_empty() {
        return Status::Rejected;
    }
    if ignorable(id) {
        return Status::Approved;
    }
    let auto = cfg("ENROLL_AUTO_APPROVE_PREFIX");
    if !auto.is_empty() && id.starts_with(&auto) {
        return Status::Approved;
    }
    let is_new;
    let status;
    {
        let mut st = STORE.write().unwrap();
        is_new = !st.contains_key(id);
        let e = st.entry(id.to_owned()).or_insert_with(|| Entry {
            id: id.to_owned(),
            status: Status::Pending,
            ip: ip.to_owned(),
            first_seen: now(),
            last_seen: now(),
            hits: 0,
            note: String::new(),
        });
        e.last_seen = now();
        if !ip.is_empty() {
            e.ip = ip.to_owned();
        }
        status = e.status;
    }
    if is_new {
        save();
        log::warn!("[enroll] 新设备待审批: {} @ {}", id, ip);
    }
    status
}

/// 是否处于强制拦截模式
///   monitor（默认）：只记录设备清单，不拦截 —— 用于安全上线，先看清有哪些设备
///   enforce        ：真正拦截，未审批设备一律拒绝
pub fn enforcing() -> bool {
    cfg("ENROLL_MODE").eq_ignore_ascii_case("enforce")
}

/// 准入判定：设备是否允许注册 / 被连接
/// 内部已包含 mode 判断：monitor 模式恒为 true（但会记录）
pub fn allowed(id: &str, ip: &str) -> bool {
    if id.is_empty() {
        return false;
    }
    if ignorable(id) {
        return true;
    }
    let auto = cfg("ENROLL_AUTO_APPROVE_PREFIX");
    if !auto.is_empty() && id.starts_with(&auto) {
        return true;
    }

    let is_new;
    let status;
    {
        let mut st = STORE.write().unwrap();
        is_new = !st.contains_key(id);
        {
            // 用 entry API 规避 match st.get_mut() 后再 st.insert() 的借用冲突
            let e = st.entry(id.to_owned()).or_insert_with(|| Entry {
                id: id.to_owned(),
                status: Status::Pending,
                ip: ip.to_owned(),
                first_seen: now(),
                last_seen: now(),
                hits: 0,
                note: String::new(),
            });
            e.last_seen = now();
            if !ip.is_empty() {
                e.ip = ip.to_owned();
            }
            e.hits += 1;
            status = e.status;
        }
    }
    if is_new {
        save();
        log::warn!("[enroll] 新设备待审批: {} @ {}", id, ip);
    }

    if !enforcing() {
        return true;
    }
    status == Status::Approved
}

/// 目标设备是否已审批（用于拦截"连接已入网设备"）
/// monitor 模式下只拦"明确被拒绝"的
pub fn is_approved(id: &str) -> bool {
    if ignorable(id) {
        return true;
    }
    let auto = cfg("ENROLL_AUTO_APPROVE_PREFIX");
    if !auto.is_empty() && id.starts_with(&auto) {
        return true;
    }
    let st = STORE.read().unwrap();
    let cur = st.get(id).map(|e| e.status);
    drop(st);
    if enforcing() {
        cur == Some(Status::Approved)
    } else {
        !matches!(cur, Some(Status::Rejected))
    }
}

// ---------------------------------------------------------------- 管理动作

pub fn set_status(id: &str, st: Status, note: &str) -> bool {
    {
        let mut g = STORE.write().unwrap();
        let e = g.entry(id.to_owned()).or_insert_with(|| Entry {
            id: id.to_owned(),
            status: st,
            ip: String::new(),
            first_seen: now(),
            last_seen: now(),
            hits: 0,
            note: String::new(),
        });
        e.status = st;
        e.note = note.to_owned();
    }
    save_now();
    log::info!("[enroll] {} -> {:?} ({})", id, st, note);
    true
}

pub fn remove(id: &str) -> bool {
    let ok = STORE.write().unwrap().remove(id).is_some();
    if ok {
        save_now();
    }
    ok
}

pub fn list() -> Vec<Entry> {
    let g = STORE.read().unwrap();
    let mut v: Vec<Entry> = g.values().cloned().collect();
    v.sort_by(|a, b| b.last_seen.cmp(&a.last_seen));
    v
}

// ---------------------------------------------------------------- 管理接口

fn need_token() -> String {
    cfg("ENROLL_ADMIN_TOKEN")
}

fn token_ok(q: &HashMap<String, String>, headers: &axum::http::HeaderMap) -> bool {
    let want = need_token();
    if want.is_empty() {
        return true; // 未配置则不校验（仅建议在本机隧道下使用）
    }
    if let Some(t) = q.get("token") {
        if t == &want {
            return true;
        }
    }
    if let Some(v) = headers.get("x-admin-token") {
        if v.to_str().unwrap_or("") == want {
            return true;
        }
    }
    false
}

async fn api_list(
    axum::extract::Query(q): axum::extract::Query<HashMap<String, String>>,
    headers: axum::http::HeaderMap,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    if !token_ok(&q, &headers) {
        return (axum::http::StatusCode::UNAUTHORIZED, "bad token").into_response();
    }
    axum::Json(list()).into_response()
}

async fn api_decide(
    st: Status,
    q: HashMap<String, String>,
    headers: axum::http::HeaderMap,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    if !token_ok(&q, &headers) {
        return (axum::http::StatusCode::UNAUTHORIZED, "bad token").into_response();
    }
    let id = q.get("id").cloned().unwrap_or_default();
    if id.is_empty() {
        return (axum::http::StatusCode::BAD_REQUEST, "missing id").into_response();
    }
    let note = q.get("note").cloned().unwrap_or_default();
    set_status(&id, st, &note);
    axum::Json(serde_json::json!({"ok": true, "id": id, "status": st})).into_response()
}

async fn api_approve(
    axum::extract::Query(q): axum::extract::Query<HashMap<String, String>>,
    headers: axum::http::HeaderMap,
) -> axum::response::Response {
    api_decide(Status::Approved, q, headers).await
}

async fn api_reject(
    axum::extract::Query(q): axum::extract::Query<HashMap<String, String>>,
    headers: axum::http::HeaderMap,
) -> axum::response::Response {
    api_decide(Status::Rejected, q, headers).await
}

async fn api_delete(
    axum::extract::Query(q): axum::extract::Query<HashMap<String, String>>,
    headers: axum::http::HeaderMap,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    if !token_ok(&q, &headers) {
        return (axum::http::StatusCode::UNAUTHORIZED, "bad token").into_response();
    }
    let id = q.get("id").cloned().unwrap_or_default();
    let ok = remove(&id);
    axum::Json(serde_json::json!({"ok": ok, "id": id})).into_response()
}

async fn page() -> axum::response::Html<&'static str> {
    axum::response::Html(PAGE)
}

/// 审批控制台（自动轮询，新设备弹提示）
const PAGE: &str = r#"<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="utf-8">
<title>RustDesk 入网审批台</title>
<style>
body{font-family:system-ui,-apple-system,"Microsoft YaHei",sans-serif;margin:0;padding:24px;background:#f5f6f8;color:#1a1a1a}
h1{font-size:18px;font-weight:600;margin:0 0 4px}
.sub{color:#666;font-size:13px;margin-bottom:16px}
.card{background:#fff;border:1px solid #e3e5e8;border-radius:10px;margin-bottom:18px;overflow:hidden}
.card h2{font-size:14px;font-weight:600;margin:0;padding:12px 16px;border-bottom:1px solid #eee}
table{width:100%;border-collapse:collapse;font-size:13px}
th,td{text-align:left;padding:9px 16px;border-bottom:1px solid #f0f0f0}
th{color:#888;font-weight:500;background:#fafbfc}
tr:last-child td{border-bottom:none}
button{font:inherit;font-size:12px;padding:4px 12px;border-radius:6px;border:1px solid #d0d3d8;background:#fff;cursor:pointer;margin-right:6px}
button.ok{border-color:#2e9e5b;color:#2e9e5b}button.ok:hover{background:#eefaf2}
button.no{border-color:#d24b4b;color:#d24b4b}button.no:hover{background:#fdeeee}
.pill{display:inline-block;padding:1px 8px;border-radius:20px;font-size:11px}
.p-pending{background:#fff5e0;color:#9a6b00}
.p-approved{background:#e8f7ee;color:#1f7a45}
.p-rejected{background:#fdecec;color:#a32d2d}
.empty{padding:16px;color:#999;font-size:13px}
#fresh{font-size:12px;color:#888}
</style></head><body>
<h1>RustDesk 入网审批台</h1>
<div class="sub">未审批的设备无法注册到本服务端，也无法被连接。<span id="fresh"></span></div>

<div class="card"><h2>待审批 <span id="cnt-pending">0</span></h2>
<table><thead><tr><th>设备 ID</th><th>来源 IP</th><th>首次出现</th><th>尝试</th><th>操作</th></tr></thead>
<tbody id="tb-pending"></tbody></table>
<div class="empty" id="em-pending">暂无待审批设备</div></div>

<div class="card"><h2>已入网 <span id="cnt-approved">0</span></h2>
<table><thead><tr><th>设备 ID</th><th>来源 IP</th><th>最近活动</th><th>操作</th></tr></thead>
<tbody id="tb-approved"></tbody></table>
<div class="empty" id="em-approved">暂无已入网设备</div></div>

<div class="card"><h2>已拒绝 <span id="cnt-rejected">0</span></h2>
<table><thead><tr><th>设备 ID</th><th>来源 IP</th><th>最近活动</th><th>操作</th></tr></thead>
<tbody id="tb-rejected"></tbody></table>
<div class="empty" id="em-rejected">暂无已拒绝设备</div></div>

<script>
const T = new URLSearchParams(location.search).get('token') || '';
const qs = T ? ('?token=' + encodeURIComponent(T)) : '';
let lastPending = -1;

function ts(t){ if(!t) return '-'; const d=new Date(t*1000);
  return d.toLocaleString('zh-CN',{hour12:false}); }

function act(id, kind, cls, label){
  return '<button class="'+cls+'" onclick="decide(\''+id+'\',\''+kind+'\')">'+label+'</button>';
}

async function decide(id, kind){
  await fetch('/enroll/api/'+kind+qs+(qs?'&':'?')+'id='+encodeURIComponent(id), {method:'POST'});
  load();
}

function render(rows){
  const g = {pending:[], approved:[], rejected:[]};
  rows.forEach(r => (g[r.status]||g.pending).push(r));

  for (const k of ['pending','approved','rejected']){
    document.getElementById('cnt-'+k).textContent = g[k].length;
    document.getElementById('em-'+k).style.display = g[k].length ? 'none' : 'block';
    let h = '';
    for (const r of g[k]){
      const when = (k === 'pending') ? ts(r.first_seen) : ts(r.last_seen);
      const extra = (k === 'pending') ? ('<td>'+r.hits+'</td>') : '';
      let ops = '';
      if (k === 'pending'){
        ops = act(r.id,'approve','ok','同意') + act(r.id,'reject','no','拒绝');
      } else if (k === 'approved'){
        ops = act(r.id,'reject','no','移出') + act(r.id,'delete','','删除');
      } else {
        ops = act(r.id,'approve','ok','恢复') + act(r.id,'delete','','删除');
      }
      h += '<tr><td><b>'+r.id+'</b></td><td>'+(r.ip||'-')+'</td><td>'+when+'</td>'+extra+'<td>'+ops+'</td></tr>';
    }
    document.getElementById('tb-'+k).innerHTML = h;
  }

  // 新设备提醒
  const n = g.pending.length;
  if (lastPending >= 0 && n > lastPending){
    try{
      new Notification('有新的设备请求接入', {body: n + ' 台设备待审批'});
    }catch(e){}
    document.title = '【' + n + ' 待审批】RustDesk 入网审批台';
  } else if (n === 0){
    document.title = 'RustDesk 入网审批台';
  }
  lastPending = n;
  document.getElementById('fresh').textContent = ' 最后刷新 ' + new Date().toLocaleTimeString('zh-CN',{hour12:false});
}

async function load(){
  try{
    const r = await fetch('/enroll/api/list'+qs);
    if(!r.ok){ document.getElementById('fresh').textContent = ' 鉴权失败，请带 ?token=... '; return; }
    render(await r.json());
  }catch(e){}
}

if (window.Notification && Notification.permission === 'default'){
  Notification.requestPermission();
}
load();
setInterval(load, 3000);
</script></body></html>"#;

/// 启动内嵌管理服务
pub async fn start_admin_server() -> hbb_common::ResultType<()> {
    let port: u16 = cfg("ENROLL_ADMIN_PORT").parse().unwrap_or(21120);
    if port == 0 {
        log::info!("[enroll] 管理接口已禁用 (ENROLL_ADMIN_PORT=0)");
        return Ok(());
    }
    let bind = cfg("ENROLL_ADMIN_BIND");
    let bind = if bind.trim().is_empty() { "127.0.0.1".to_owned() } else { bind };

    let app = axum::Router::new()
        .route("/enroll", axum::routing::get(page))
        .route("/enroll/api/list", axum::routing::get(api_list))
        .route("/enroll/api/approve", axum::routing::post(api_approve))
        .route("/enroll/api/reject", axum::routing::post(api_reject))
        .route("/enroll/api/delete", axum::routing::post(api_delete));

    let addr: std::net::SocketAddr = format!("{}:{}", bind, port).parse()?;
    log::info!("[enroll] 审批台: http://{}/enroll", addr);
    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await?;
    Ok(())
}
