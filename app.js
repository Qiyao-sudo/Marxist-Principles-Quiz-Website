/* ===== 马原答题系统 —— 前端逻辑（进度持久化于 localStorage） ===== */
(function(){
"use strict";

var ALL = [];        // 解密后由 setQuestions() 原地填充
var BY_ID = {};
function setQuestions(arr){
  ALL.length = 0;
  for (var i=0;i<arr.length;i++) ALL.push(arr[i]);
  Object.keys(BY_ID).forEach(function(k){ delete BY_ID[k]; });
  arr.forEach(function(q){ BY_ID[q.id] = q; });
}

var STORAGE_KEY = "mayuan_quiz_v1";

/* ---------- 登录 / Supabase 进度同步 ----------
   认证用 Supabase Auth：每个学生一个账号（email = 学号@mayuan.local）。
   会话由 supabase-js 持久化（localStorage），浏览器重启自动恢复，无需重登。
   进度表 progress(user_id) 由 RLS 绑定 auth.uid()，每账号只能读写自己的行。
*/
var currentUser = null;              // { id, xh, name } 或 null（id=auth.users 的 uuid）

/* ---------- 题库解密（AES-256-GCM，密钥托管在数据库 quiz_key 表） ---------- */
var KEY_STORAGE = "mayuan_key_v1"; // 离线兜底缓存：在线取到密钥后存此，断网时复用；退出登录时清除

function b64ToBytes(b64){
  var bin = atob(b64);
  var out = new Uint8Array(bin.length);
  for (var i=0;i<bin.length;i++) out[i] = bin.charCodeAt(i);
  return out;
}
function importKeyFromBytes(rawBytes){
  return crypto.subtle.importKey("raw", rawBytes, { name:"AES-GCM" }, false, ["decrypt"]);
}
function decryptQuestions(keyObj){
  var cipher = window.QUIZ_CIPHER;
  if (!cipher || cipher.v !== 1 || cipher.alg !== "AES-GCM")
    { return Promise.reject(new Error("题库密文格式不正确。")); }
  var blob = b64ToBytes(cipher.data);
  var iv = blob.slice(0, 12);
  var ctTag = blob.slice(12);
  return crypto.subtle.decrypt({ name:"AES-GCM", iv: iv }, keyObj, ctTag)
    .then(function(buf){
      var json = new TextDecoder().decode(new Uint8Array(buf));
      return JSON.parse(json);
    });
}

/* ---------- 持久化状态 ---------- */
function defaultState(){
  return { answered:{}, wrongSet:{}, seqCursor:0, shuf:null }; // wrongSet 用对象当集合存；shuf={order,idx} 持久化乱序进度
}
function loadState(){
  try{
    var s = JSON.parse(localStorage.getItem(STORAGE_KEY) || "null");
    if(!s) return defaultState();
    s.answered = s.answered || {};
    s.wrongSet = s.wrongSet || {};
    s.seqCursor = typeof s.seqCursor==="number" ? s.seqCursor : 0;
    s.shuf = (s.shuf && Array.isArray(s.shuf.order)) ? {order:s.shuf.order, idx:(typeof s.shuf.idx==="number"?s.shuf.idx:0)} : null;
    return s;
  }catch(e){ return defaultState(); }
}
function saveState(){ try{ localStorage.setItem(STORAGE_KEY, JSON.stringify(STATE)); }catch(e){} }

var STATE = loadState();

/* ---------- 工具 ---------- */
function el(html){ var d=document.createElement("div"); d.innerHTML=html.trim(); return d.firstChild; }
function shuffle(a){ a=a.slice(); for(var i=a.length-1;i>0;i--){ var j=Math.floor(Math.random()*(i+1)); var t=a[i];a[i]=a[j];a[j]=t;} return a; }
function escapeHtml(s){ return String(s).replace(/[&<>"']/g,function(c){return {"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c];}); }
function isMultiple(q){ return q.type==="multiple"; }
function typeName(q){ return isMultiple(q)?"多选题":"单选题"; }
function optKeys(q){ return Object.keys(q.options).sort(); }
function fmtAns(letters){ return letters.split("").sort().join(""); }

var app = document.getElementById("app");

/* ---------- 模态框 ---------- */
function confirmDialog(title, body, okText, okClass){
  return new Promise(function(resolve){
    var modal=document.getElementById("modal");
    document.getElementById("modalTitle").textContent=title;
    document.getElementById("modalBody").textContent=body;
    var ok=document.getElementById("modalOk");
    var cancel=document.getElementById("modalCancel");
    ok.textContent=okText||"确定";
    ok.className="btn "+(okClass||"danger");
    modal.classList.remove("hidden");
    function close(v){ modal.classList.add("hidden"); ok.onclick=null; cancel.onclick=null; resolve(v); }
    ok.onclick=function(){ close(true); };
    cancel.onclick=function(){ close(false); };
  });
}
function toast(msg){
  document.getElementById("modalTitle").textContent="提示";
  document.getElementById("modalBody").textContent=msg;
  var ok=document.getElementById("modalOk"), cancel=document.getElementById("modalCancel");
  ok.textContent="知道了"; ok.className="btn";
  cancel.style.display="none";
  var modal=document.getElementById("modal"); modal.classList.remove("hidden");
  ok.onclick=function(){ modal.classList.add("hidden"); cancel.style.display=""; ok.onclick=null; };
}

/* ---------- 会话 ---------- */
var session=null;
var qcardOpen=false; // 答题卡展开状态（跨题目保留）

function startSession(mode, ids, title){
  if(!ids.length){ toast("暂无可答题目。"); return; }
  qcardOpen=false;
  session={ mode:mode, ids:ids, idx:(mode==="seq"?STATE.seqCursor:0), title:title };
  if(session.idx>=ids.length) session.idx=0;
  renderQuestion();
}

/* 乱序答题：持久化 shuffle 顺序与位置，退出后可续答 */
function startShuf(){
  var allIds=ALL.map(function(q){return q.id;});
  var s=STATE.shuf;
  if(s && s.order && s.order.length){
    var order=s.order.filter(function(id){return BY_ID[id];}); // 容错：题库变动后剔除失效 id
    if(order.length){
      qcardOpen=false;
      session={mode:"shuf", ids:order, idx:Math.min(s.idx||0, order.length-1), title:"乱序答题"};
      renderQuestion(); return;
    }
  }
  var order=shuffle(allIds);
  STATE.shuf={order:order, idx:0}; saveState();
  qcardOpen=false;
  session={mode:"shuf", ids:order, idx:0, title:"乱序答题"};
  renderQuestion();
}
function reshuffleShuf(){
  var order=shuffle(ALL.map(function(q){return q.id;}));
  STATE.shuf={order:order, idx:0}; saveState();
  qcardOpen=false;
  session={mode:"shuf", ids:order, idx:0, title:"乱序答题"};
  renderQuestion();
}

/* ---------- 首页 ---------- */
function home(){
  session=null;
  var answeredIds=Object.keys(STATE.answered);
  var correct=0; answeredIds.forEach(function(id){ if(STATE.answered[id].correct) correct++; });
  var wrongCount=Object.keys(STATE.wrongSet).length;
  var rate = answeredIds.length? Math.round(correct/answeredIds.length*100):0;
  var remaining = ALL.length - answeredIds.length;

  var catsHtml = window.CATEGORIES.map(function(c){
    var list=ALL.filter(function(q){return q.category===c;});
    var done=list.filter(function(q){return STATE.answered[q.id];}).length;
    return '<div class="cat-row" data-cat="'+escapeHtml(c)+'">'+
      '<div><div class="name">'+escapeHtml(c)+'</div>'+
      '<div class="meta">共 '+list.length+' 题 · 已答 '+done+' 题</div></div>'+
      '<span class="progress-pill">'+done+'/'+list.length+'</span></div>';
  }).join("");

  app.innerHTML =
    '<div class="card home-hero">'+
      '<div class="user-bar">'+
        '<span class="user-chip">👤 '+(currentUser&&currentUser.name?escapeHtml(currentUser.name):escapeHtml(currentUser?currentUser.xh||'':''))+(currentUser&&currentUser.xh&&!currentUser.name?' · '+escapeHtml(currentUser.xh):'')+'</span>'+
        '<button class="btn ghost small" id="logoutBtn">退出登录</button>'+
      '</div>'+
      '<span class="eyebrow">题库 · 答题训练</span>'+
      '<h1>马克思主义基本原理</h1>'+
      '<p class="sub">共 '+ALL.length+' 道题（单选 + 多选），含答案与解析。红笔判分，进度自动保存于本设备。</p>'+
      '<div class="stats">'+
        '<div class="stat"><div class="num">'+answeredIds.length+'</div><div class="lbl">已答题</div></div>'+
        '<div class="stat ok"><div class="num">'+rate+'%</div><div class="lbl">正确率</div></div>'+
        '<div class="stat warn"><div class="num">'+wrongCount+'</div><div class="lbl">错题本</div></div>'+
        '<div class="stat"><div class="num">'+remaining+'</div><div class="lbl">未答题</div></div>'+
      '</div>'+
    '</div>'+

    '<div class="card">'+
      '<div class="program-head"><h3>答题程序</h3><span class="ph-kicker">PROGRAM 01 — 05</span></div>'+
      '<div class="modes">'+
        modeBtn("01","顺序答题","按题号顺序，自动续答",(STATE.seqCursor>0?("已答到第 "+(STATE.seqCursor+1)+" 题"):""),"seq")+
        modeBtn("02","乱序答题","随机打乱全部题目，进度自动保存",(STATE.shuf&&STATE.shuf.order?("已答 "+(STATE.shuf.idx||0)+" / "+STATE.shuf.order.length):""),"shuf")+
        modeBtn("03","分类答题","按章节分类集中练习","","cat")+
        modeBtn("04","错题答题","只练做错的题，做对自动移出错题本",(wrongCount?("错题本 "+wrongCount+" 题"):""),"wrong")+
        modeBtn("05","错题梳理","回看全部错题、正确答案与解析","","review")+
      '</div>'+
    '</div>'+

    '<div class="card" id="catCard" style="display:none">'+
      '<div class="program-head"><h3>选择分类</h3><span class="ph-kicker">按章节</span></div>'+
      '<div class="cat-list">'+catsHtml+'</div>'+
    '</div>';

  // 绑定
  var lb=$("#logoutBtn");
  if(lb) lb.addEventListener("click",function(){
    confirmDialog("退出登录","将上传当前进度到云端，并清除本机数据。确定退出吗？","退出").then(function(ok){
      if(ok){
        syncProgress();                              // 先把当前进度上传云端
        STATE=defaultState(); saveState();           // 再清除本机数据
        var prevId = currentUser && currentUser.id;
        currentUser=null;
        localStorage.removeItem(KEY_STORAGE);        // 清除离线密钥缓存，下次登录重新从库取
        // 注销 Auth 会话（清除本地持久化的 token）；离线无会话则直接回登录页
        if(prevId && window.sb && window.sb.auth){
          window.sb.auth.signOut().finally(function(){ showLogin(); });
        } else {
          showLogin();
        }
      }
    });
  });
  $$(".mode-btn").forEach(function(b){
    b.addEventListener("click",function(){ onMode(b.dataset.mode); });
  });
  $$(".cat-row").forEach(function(r){
    r.addEventListener("click",function(){
      var c=r.dataset.cat;
      var ids=ALL.filter(function(q){return q.category===c;}).map(function(q){return q.id;});
      startSession("cat", ids, "分类 · "+c);
    });
  });
  updateFoot();
}

function modeBtn(num,t,d,badge,mode){
  return '<button class="mode-btn" data-mode="'+mode+'">'+
    (badge?'<span class="badge">'+escapeHtml(badge)+'</span>':'')+
    '<div class="num">'+num+'</div>'+
    '<div class="body"><div class="t">'+t+'</div>'+
    '<div class="d">'+escapeHtml(d)+'</div></div></button>';
}

function onMode(mode){
  if(mode==="seq"){ startSession("seq", ALL.map(function(q){return q.id;}), "顺序答题"); }
  else if(mode==="shuf"){ startShuf(); }
  else if(mode==="cat"){ var c=$("#catCard"); c.style.display = c.style.display==="block"?"none":"block"; if(c.style.display==="block") c.scrollIntoView({behavior:"smooth"}); }
  else if(mode==="wrong"){
    var ids=Object.keys(STATE.wrongSet);
    if(!ids.length){ toast("错题本是空的，先去做题吧～"); return; }
    startSession("wrong", ids.slice(), "错题练习");
  }
  else if(mode==="review"){ review(); }
}

/* ---------- 答题页 ---------- */
function renderQuestion(){
  var q=BY_ID[session.ids[session.idx]];
  var multi=isMultiple(q);
  var keys=optKeys(q);
  var optsHtml=keys.map(function(k){
    return '<div class="opt" data-k="'+k+'"><div class="mark">'+k+'</div><div class="txt">'+escapeHtml(q.options[k])+'</div></div>';
  }).join("");

  var pct=Math.round((session.idx)/session.ids.length*100);

  app.innerHTML =
    '<div class="card">'+
      '<div class="progress-wrap">'+
        '<div class="progress-meta"><span>'+escapeHtml(session.title)+'</span>'+
        '<span>'+(session.idx+1)+' / '+session.ids.length+'</span></div>'+
        '<div class="progress-bar"><i style="width:'+pct+'%"></i></div>'+
      '</div>'+
      '<span class="q-tag '+(multi?"multi":"")+'">'+typeName(q)+' · '+escapeHtml(q.category)+'</span>'+
      '<p class="q-stem">'+escapeHtml(q.stem)+'</p>'+
      '<div class="options">'+optsHtml+'</div>'+
      '<div class="feedback" id="feedback"></div>'+
      '<div class="toolbar util-row">'+
        '<button class="btn ghost small" id="cardBtn">答题卡</button>'+
        (session.mode==="shuf"?'<button class="btn ghost small" id="reshufBtn" title="重新打乱并从头开始">重新打乱</button>':'')+
        '<span class="spacer"></span>'+
        '<button class="btn ghost small" id="exitBtn">退出</button>'+
      '</div>'+
      '<div class="toolbar nav-row">'+
        '<button class="btn ghost" id="prevBtn"'+(session.idx===0?' disabled':'')+'>← 上一题</button>'+
        (multi?'<button class="btn" id="submitBtn" disabled>提交答案</button>':'')+
        '<span class="spacer"></span>'+
        '<button class="btn" id="nextBtn">'+(session.idx>=session.ids.length-1?'完成 →':'下一题 →')+'</button>'+
      '</div>'+
    '</div>'+
    '<div class="card qcard hidden" id="qcard"></div>';

  var chosenMulti={};
  var submitted=false;

  $$(".opt").forEach(function(o){
    o.addEventListener("click",function(){
      if(submitted) return;
      var k=o.dataset.k;
      if(multi){
        if(chosenMulti[k]){ delete chosenMulti[k]; o.classList.remove("chosen"); }
        else{ chosenMulti[k]=true; o.classList.add("chosen"); }
        $("#submitBtn").disabled = Object.keys(chosenMulti).length===0;
      }else{
        // 单选立即判分
        $$(".opt").forEach(function(x){ x.classList.remove("chosen"); });
        o.classList.add("chosen");
        grade(q,[k]);
      }
    });
  });

  if(multi){
    $("#submitBtn").addEventListener("click",function(){
      if(submitted) return;
      grade(q,Object.keys(chosenMulti));
    });
  }
  $("#nextBtn").addEventListener("click",nextQuestion);
  $("#prevBtn").addEventListener("click",prevQuestion);
  $("#exitBtn").addEventListener("click",function(){
    confirmDialog("退出答题","确定要退出当前答题吗？进度已自动保存。","退出").then(function(ok){ if(ok){ syncProgress(); home(); } });
  });
  var rb=$("#reshufBtn");
  if(rb) rb.addEventListener("click",function(){
    confirmDialog("重新打乱","将丢弃当前乱序进度，重新随机打乱全部题目从头开始，确定吗？","重新打乱").then(function(ok){ if(ok) reshuffleShuf(); });
  });
  $("#cardBtn").addEventListener("click",function(){ qcardOpen=!qcardOpen; renderQCard(); });
  renderQCard();
}

/* ---------- 答题卡 ---------- */
function renderQCard(){
  var card=$("#qcard"); if(!card) return;
  var cells=session.ids.map(function(id,i){
    var a=STATE.answered[id], cls="qcell";
    if(i===session.idx) cls+=" cur";
    else if(a && a.correct) cls+=" ok";
    else if(a && !a.correct) cls+=" bad";
    return '<button class="'+cls+'" data-i="'+i+'">'+(i+1)+'</button>';
  }).join("");
  card.innerHTML=
    '<div class="qcard-head"><span>答题卡 · '+(session.idx+1)+' / '+session.ids.length+'</span>'+
    '<span class="qcard-leg"><i class="ok"></i>已答对 <i class="bad"></i>答错 <i class="cur"></i>当前</span></div>'+
    '<div class="qcard-grid">'+cells+'</div>';
  card.classList.toggle("hidden", !qcardOpen);
  if(qcardOpen){
    $$(".qcell").forEach(function(c){
      c.addEventListener("click",function(){
        session.idx=+c.dataset.i;
        renderQuestion();
        window.scrollTo(0,0);
      });
    });
  }
}

function grade(q, chosenArr){
  var keys=optKeys(q);
  var correctSet={}; q.answer.split("").forEach(function(c){correctSet[c]=true;});
  var chosenArrS=chosenArr.slice().sort();
  var correct = chosenArrS.length===q.answer.length && chosenArrS.every(function(c){return correctSet[c];});

  // 记录
  STATE.answered[q.id]={ correct:correct, chosen:chosenArr.join(""), t:Date.now() };

  // 错题本维护
  if(!correct){
    STATE.wrongSet[q.id]=true;          // 答错 -> 进错题本
  }else if(session.mode==="wrong"){
    delete STATE.wrongSet[q.id];        // 错题练习中答对 -> 移出
  }else{
    delete STATE.wrongSet[q.id];        // 其它模式答对也清掉旧错题记录
  }
  if(session.mode==="seq") STATE.seqCursor=session.idx+1;
  if(session.mode==="shuf" && STATE.shuf) STATE.shuf.idx=session.idx+1;
  saveState();

  // 视觉反馈
  $$(".opt").forEach(function(o){
    o.classList.add("disabled");
    var k=o.dataset.k;
    if(correctSet[k]) o.classList.add("correct");
    else if(o.classList.contains("chosen")) o.classList.add("wrong");
    o.classList.remove("chosen");
  });
  var fb=$("#feedback");
  var chosenStr=chosenArr.join("");
  fb.className="feedback show "+(correct?"ok":"bad");
  fb.innerHTML =
    (correct?"<b>★ 回答正确</b>":"<b>✕ 回答错误</b>")+
    '<div class="ans">正确答案：<b>'+q.answer.split("").join("")+'</b>'+
    (correct?"":"　你的选择："+(chosenStr||"（未选）"))+'</div>'+
    (q.explanation?'<div class="exp">解析：'+escapeHtml(q.explanation)+'</div>':'');

  var sb=$("#submitBtn"); if(sb) sb.style.display="none"; // 多选提交后隐藏，让位给"下一题"
  updateFoot();
  renderQCard(); // 答题卡开着时，当前格立即变色
}

function nextQuestion(){
  session.idx++;
  if(session.idx>=session.ids.length){ doneScreen(); }
  else{ renderQuestion(); window.scrollTo(0,0); }
}
function prevQuestion(){
  if(session.idx>0){ session.idx--; renderQuestion(); window.scrollTo(0,0); }
}

function doneScreen(){
  // 统计本次
  var total=session.ids.length;
  var correct=0;
  session.ids.forEach(function(id){ if(STATE.answered[id]&&STATE.answered[id].correct) correct++; });
  var pct=total?Math.round(correct/total*100):0;
  // 顺序/乱序跑完一轮：清掉对应进度，下次重新开始
  if(session.mode==="shuf" && STATE.shuf){ STATE.shuf=null; saveState(); }
  var msg = pct>=90?"非常棒！":(pct>=70?"不错，继续加油！":"还需多练习，错题记得回顾～");
  app.innerHTML =
    '<div class="card done-card">'+
      '<div class="big">★</div>'+
      '<h2>本轮完成</h2>'+
      '<div class="score">'+pct+'<span style="font-size:18px">%</span></div>'+
      '<p>答对 '+correct+' / '+total+'　·　'+msg+'</p>'+
      '<div class="toolbar" style="justify-content:center">'+
        (session.mode==="wrong"&&Object.keys(STATE.wrongSet).length?'<button class="btn" id="againBtn">再练一遍错题</button>':'')+
        '<button class="btn ghost" id="homeBtn2">返回首页</button>'+
      '</div>'+
    '</div>';
  var ab=$("#againBtn"); if(ab) ab.addEventListener("click",function(){ startSession("wrong",Object.keys(STATE.wrongSet).slice(),"错题练习"); });
  $("#homeBtn2").addEventListener("click",function(){ syncProgress(); home(); });
  updateFoot();
}

/* ---------- 错题梳理 ---------- */
var REVIEW_PAGE_SIZE = 10;
var reviewPage = 0;

function reviewItemHtml(id){
  var q=BY_ID[id]; if(!q) return "";
  var chosen=STATE.answered[id]?STATE.answered[id].chosen:"";
  var chosenSet={}; chosen.split("").forEach(function(c){chosenSet[c]=true;});
  var keys=optKeys(q);
  var correctSet={}; q.answer.split("").forEach(function(c){correctSet[c]=true;});
  var lis=keys.map(function(k){
    var cls=[];
    if(correctSet[k]) cls.push("is-correct");
    else if(chosenSet[k]) cls.push("is-wrong");
    return '<li class="'+cls.join(" ")+'">'+k+'. '+escapeHtml(q.options[k])+
      (correctSet[k]?' <b>★ 正确</b>':'')+
      (chosenSet[k]&&!correctSet[k]?' <b>（你的选择）</b>':'')+'</li>';
  }).join("");
  return '<div class="review-item">'+
    '<div class="r-qtag">'+typeName(q)+' · '+escapeHtml(q.category)+' · '+escapeHtml(q.id)+'</div>'+
    '<div class="r-stem">'+escapeHtml(q.stem)+'</div>'+
    '<ul>'+lis+'</ul>'+
    '<div class="r-foot"><span class="r-ans">正确答案：'+q.answer.split("").join("")+'</span>'+
    (q.explanation?'<br>解析：'+escapeHtml(q.explanation):'')+'</div>'+
  '</div>';
}

function review(){
  var ids=Object.keys(STATE.wrongSet);
  if(!ids.length){
    app.innerHTML='<div class="card review-empty">★ 错题本是空的。<br>去做题，答错的题会自动收集到这里。</div>';
    session=null; updateFoot(); return;
  }
  var pages=Math.ceil(ids.length/REVIEW_PAGE_SIZE);
  if(reviewPage>pages-1) reviewPage=pages-1;
  if(reviewPage<0) reviewPage=0;
  var start=reviewPage*REVIEW_PAGE_SIZE;
  var slice=ids.slice(start, start+REVIEW_PAGE_SIZE);

  var html='<div class="card">'+
    '<div style="display:flex;align-items:center;justify-content:space-between">'+
    '<h3 style="margin:0">错题梳理 · '+ids.length+' 题</h3>'+
    '<button class="btn danger small" id="clearWrong">清空错题本</button></div>'+
    '<p style="color:var(--ink-soft);font-size:13px;margin:6px 0 0">红色为正确答案'+(ids.some(function(id){return STATE.answered[id];})?'，灰色删除线为你上次选错的项':'')+'。每页 '+REVIEW_PAGE_SIZE+' 题。</p>'+
    '</div>';

  slice.forEach(function(id){ html+=reviewItemHtml(id); });

  html+='<div class="card pager">'+
    '<button class="btn small" id="prevPage"'+(reviewPage===0?' disabled':'')+'>← 上一页</button>'+
    '<span class="pager-info">第 '+(reviewPage+1)+' / '+pages+' 页　（'+(start+1)+'-'+(start+slice.length)+' / '+ids.length+'）</span>'+
    '<button class="btn small" id="nextPage"'+(reviewPage>=pages-1?' disabled':'')+'>下一页 →</button>'+
  '</div>';

  html+='<div class="card"><button class="btn block" id="practiceWrong">▶ 进入错题练习</button></div>';
  app.innerHTML=html;

  $("#clearWrong").addEventListener("click",function(){
    confirmDialog("清空错题本","将删除全部 "+ids.length+" 道错题记录，确定吗？","清空").then(function(ok){
      if(ok){ STATE.wrongSet={}; reviewPage=0; saveState(); review(); }
    });
  });
  $("#practiceWrong").addEventListener("click",function(){
    startSession("wrong",Object.keys(STATE.wrongSet).slice(),"错题练习");
  });
  var pp=$("#prevPage"); if(pp) pp.addEventListener("click",function(){ reviewPage--; review(); window.scrollTo(0,0); });
  var np=$("#nextPage"); if(np) np.addEventListener("click",function(){ reviewPage++; review(); window.scrollTo(0,0); });

  session=null;
  updateFoot();
}

/* ---------- 顶部按钮 ---------- */
document.getElementById("homeBtn").addEventListener("click",function(){
  syncProgress();
  if(!currentUser){ showLogin(); return; } // 登录态前点标题：回登录页，不绕过登录
  home();
});
document.getElementById("resetBtn").addEventListener("click",function(){
  if(!currentUser) return; // 仅登录后可用
  confirmDialog("重置全部进度","将清空本机所有答题记录、错题本与进度（云端进度也会被清空态覆盖），且不可恢复。确定吗？","重置").then(function(ok){
    if(ok){
      STATE=defaultState();
      saveState();
      syncProgress(); // 同步清空态，避免下次登录被远程旧数据复活
      home();
    }
  });
});

// 根据登录态显示/隐藏顶栏「重置进度」按钮（仅登录后可用）
function toggleResetBtn(){
  var r=document.getElementById("resetBtn");
  if(r) r.style.display = currentUser ? "" : "none";
}

/* 键盘：← 上一题，→ 下一题（仅在答题页生效；避开 Enter 以防按钮聚焦时双触发） */
document.addEventListener("keydown",function(e){
  if(!session) return;
  if(e.key==="ArrowLeft" && session.idx>0){ prevQuestion(); }
  else if(e.key==="ArrowRight"){
    var nb=$("#nextBtn");
    if(nb && !nb.disabled){ nextQuestion(); }
  }
});

/* ---------- 底部统计 ---------- */
function updateFoot(){
  var a=Object.keys(STATE.answered).length;
  document.getElementById("footStat").textContent="已答 "+a+" / "+ALL.length+"　·　错题本 "+Object.keys(STATE.wrongSet).length+" 题";
  toggleResetBtn(); // 仅登录后显示「重置进度」
}

/* ---------- 小工具选择器 ---------- */
function $(s){ return app.querySelector(s) || document.querySelector(s); }
function $$(s){ return Array.prototype.slice.call(app.querySelectorAll(s)); }

/* ---------- 题库解锁：密钥存数据库，登录后自动取 ---------- */
// KEY_STORAGE 现在仅作"离线兜底缓存"：首次在线取到密钥后缓存，断网时复用，退出登录时清除。
function showUnlockError(msg){
  app.innerHTML =
    '<div class="card key-gate">'+
      '<div class="key-icon">🔒</div>'+
      '<h2>无法解锁题库</h2>'+
      '<p class="sub">'+escapeHtml(msg||'无法从服务器读取题库密钥，请检查网络后刷新重试。')+'</p>'+
      '<p class="sub" style="font-size:12px;margin-top:14px">密钥已托管在数据库，登录后自动解锁，无需手动输入。</p>'+
      '<div style="margin-top:14px"><button class="btn" id="retryUnlockBtn">重试</button>'+
      '<button class="btn ghost" id="backLoginBtn" style="margin-left:8px">重新登录</button></div>'+
    '</div>';
  updateFoot();
  var r=$("#retryUnlockBtn"); if(r) r.addEventListener("click", function(){ fetchKeyAndUnlock(); });
  var b=$("#backLoginBtn"); if(b) b.addEventListener("click", function(){
    currentUser=null;
    if(window.sb && window.sb.auth){ window.sb.auth.signOut().finally(showLogin); } else { showLogin(); }
  });
}

// 用 base64 密钥解密题库并装入；成功 resolve(true)，失败 reject
function unlockWithKey(rawB64){
  var trimmed = String(rawB64==null?"":rawB64).trim();
  var rawBytes = b64ToBytes(trimmed);
  if (rawBytes.length !== 32) throw new Error("密钥长度不对（需要 32 字节）。");
  return importKeyFromBytes(rawBytes)
    .then(function(keyObj){ return decryptQuestions(keyObj); })
    .then(function(questions){
      localStorage.setItem(KEY_STORAGE, trimmed); // 离线兜底缓存
      setQuestions(questions);
      return true;
    });
}

// 登录后调用：从数据库取密钥 → 解锁 → 进首页。失败则尝试离线缓存，仍失败显示错误页。
function fetchKeyAndUnlock(){
  return window.sb.from("quiz_key").select("key").eq("id", 1).limit(1)
    .then(function(res){
      if(res && res.data && res.data.length && res.data[0].key){
        return unlockWithKey(res.data[0].key);
      }
      // 拿不到（RLS 拒绝 / 表空）→ 退回缓存
      var cached = localStorage.getItem(KEY_STORAGE);
      if (cached) return unlockWithKey(cached);
      throw new Error("未取到题库密钥。");
    })
    .catch(function(err){
      // 网络/RLS 错误：尝试离线缓存，否则报错
      var cached = localStorage.getItem(KEY_STORAGE);
      if (cached){
        return unlockWithKey(cached).catch(function(){ showUnlockError(err && err.message); throw err; });
      }
      showUnlockError(err && err.message);
      throw err;
    });
}

/* ---------- 登录门控：解密成功后、进首页前 ---------- */
// 把 auth.users 行映射为 currentUser（id=uuid, xh/name 取自 user_metadata）
function userFromAuth(u){
  var m = (u && u.user_metadata) || {};
  return { id: u.id, xh: m.xh || "", name: m.name || "" };
}

// 每次进入页面：尝试恢复会话；有会话则取密钥解锁 + 拉本人进度（合并），进首页。
function enterApp(){
  window.sb.auth.getSession().then(function(res){
    var s = res && res.data && res.data.session;
    if (s && s.user){
      currentUser = userFromAuth(s.user);
      unlockAndHome();
    } else {
      showLogin();
    }
  }).catch(function(){ showLogin(); });
}

// 解锁题库 + 合并远程进度 + 进首页（登录/恢复会话后统一入口）
function unlockAndHome(){
  app.innerHTML = '<div class="card" style="max-width:420px;margin:60px auto;text-align:center;color:var(--ink-soft)">正在解锁题库…</div>';
  fetchKeyAndUnlock()
    .then(function(){ return loadAndMergeRemoteProgress(currentUser.id); })
    .then(function(){ home(); })
    .catch(function(){ /* fetchKeyAndUnlock 已展示错误页 */ });
}

function showLogin(errMsg){
  app.innerHTML =
    '<div class="card key-gate">'+
      '<div class="key-icon">👤</div>'+
      '<h2>登录</h2>'+
      '<p class="sub">请输入学号与密码。首次登录使用统一初始密码，登录后请尽快修改。</p>'+
      '<div class="login-form">'+
        '<input type="text" id="loginXh" placeholder="学号" autocomplete="username" inputmode="numeric" spellcheck="false">'+
        '<input type="password" id="loginPwd" placeholder="密码" autocomplete="current-password">'+
        '<button class="btn" id="loginGo">登录</button>'+
      '</div>'+
      '<p id="loginErr" class="key-err"></p>'+
    '</div>';
  updateFoot();
  if (errMsg){ document.getElementById("loginErr").textContent = errMsg; }
  var xhInput = document.getElementById("loginXh");
  var pwdInput = document.getElementById("loginPwd");
  xhInput.focus();
  var go = function(){ attemptLogin(xhInput.value, pwdInput.value); };
  document.getElementById("loginGo").addEventListener("click", go);
  var onEnter = function(e){ if(e.key==="Enter"){ e.preventDefault(); go(); } };
  xhInput.addEventListener("keydown", onEnter);
  pwdInput.addEventListener("keydown", onEnter);
}

function attemptLogin(xh, pwd){
  xh = String(xh==null?"":xh).trim();
  pwd = String(pwd==null?"":pwd);
  var errEl = document.getElementById("loginErr");
  if(!/^\d{6,}$/.test(xh)){ if(errEl) errEl.textContent = "学号格式不正确。"; return; }
  if(!pwd){ if(errEl) errEl.textContent = "请输入密码。"; return; }
  if(errEl) errEl.textContent = "验证中…";
  window.sb.auth.signInWithPassword({ email: xh + "@mayuan.local", password: pwd })
    .then(function(res){
      var err = res && res.error;
      if(err){
        var msg = err.message || "";
        if(/Invalid login credentials|invalid/i.test(msg)) msg = "学号或密码不正确。";
        else if(/not confirmed/i.test(msg)) msg = "账号未确认，请联系管理员。";
        if(errEl) errEl.textContent = "登录失败：" + msg;
        return;
      }
      if(!res.data || !res.data.user){ if(errEl) errEl.textContent = "登录失败：未返回用户信息。"; return; }
      finishLogin(res.data.user);
    })
    .catch(function(){
      // 离线/Supabase 不可达：密钥现托管在库中，未登录无法解锁，提示重试
      if(errEl) errEl.textContent = "无法连接服务器，请检查网络后重试。";
    });
}

function finishLogin(authUser){
  currentUser = userFromAuth(authUser);
  unlockAndHome();
}

/* ---------- 进度同步 ---------- */
// 把远程进度合并进本地 STATE（answered 按 t 取新、wrongSet 并集、seqCursor 取大、shuf 保留本地）
function mergeStates(local, remote){
  var out = defaultState();
  var a = (local && local.answered) || {}, ra = (remote && remote.answered) || {};
  var w = (local && local.wrongSet) || {}, rw = (remote && remote.wrongSet) || {};
  var ids = {};
  Object.keys(a).forEach(function(k){ ids[k]=1; });
  Object.keys(ra).forEach(function(k){ ids[k]=1; });
  for(var id in ids){
    var A = a[id], B = ra[id];
    if(!A) out.answered[id] = B;
    else if(!B) out.answered[id] = A;
    else out.answered[id] = (B.t||0) > (A.t||0) ? B : A;
  }
  for(var k in w) out.wrongSet[k] = true;
  for(var kk in rw){ if(!(kk in out.wrongSet)) out.wrongSet[kk] = true; }
  // 清理：已答对的题不应留在错题本
  for(var id2 in out.answered){ if(out.answered[id2].correct) delete out.wrongSet[id2]; }
  out.seqCursor = Math.max((local && local.seqCursor)||0, (remote && remote.seqCursor)||0);
  out.shuf = (local && local.shuf && local.shuf.order) ? { order: local.shuf.order.slice(), idx: local.shuf.idx||0 } : null;
  return out;
}

function loadAndMergeRemoteProgress(userId){
  if(!userId) return Promise.resolve();
  return window.sb.from("progress").select("state").eq("user_id", userId).limit(1)
    .then(function(res){
      if(res.error || !res.data || !res.data.length) return;
      var remote = res.data[0].state;
      if(!remote || typeof remote !== "object") return;
      STATE = mergeStates(STATE, remote);
      saveState();
    })
    .catch(function(){ /* 离线：忽略 */ });
}

function syncProgress(){
  if(!currentUser || !currentUser.id) return;
  window.sb.from("progress").upsert(
    { user_id: currentUser.id, xh: currentUser.xh || null, state: STATE },
    { onConflict: "user_id" }
  )
    .then(function(){ /* ok */ })
    .catch(function(){ /* 静默；离线时下次退出会重试 */ });
}

function init(){
  // 旧版明文兼容：data.js 仍直接给出 window.QUESTIONS 时直接用
  if (Object.prototype.hasOwnProperty.call(window, "QUESTIONS") && window.QUESTIONS){
    setQuestions(window.QUESTIONS);
    enterApp();
    return;
  }
  // 安全上下文守卫：file:// 或非 localhost 的 http:// 下 crypto.subtle 不可用
  if (!window.crypto || !window.crypto.subtle){
    app.innerHTML =
      '<div class="card key-gate">'+
        '<h2>不支持的运行环境</h2>'+
        '<p class="sub">Web Crypto API 需要安全上下文。请通过 https:// 或 http://localhost 访问本站，'+
        '不要直接用 file:// 打开 index.html（本地可用 <code>python -m http.server</code>）。</p>'+
      '</div>';
    updateFoot();
    return;
  }
  // 密钥现托管在数据库：直接进入登录门控，登录后自动取密钥解锁
  enterApp();
}

/* ---------- 数据加载：优先远端存储桶，失败回退本地 data.js ---------- */
var REMOTE_DATA_URL = "https://quiz-1312685057.cos.ap-nanjing.myqcloud.com/data.js";

function bootstrap(){
  // index.html 已同步加载本地 data.js（兜底基线，window.QUIZ_CIPHER 已就绪）。
  // 再注入远端 <script> 覆盖拿最新数据；失败则沿用本地。
  app.innerHTML = '<div class="card" style="max-width:420px;margin:60px auto;text-align:center;color:var(--ink-soft)">加载题库中…</div>';
  var s = document.createElement("script");
  s.src = REMOTE_DATA_URL;
  s.onload = function(){ init(); };              // 远端已执行，覆盖了 window.QUIZ_CIPHER
  s.onerror = function(){                        // 远端不可达：移除节点，沿用本地 data.js
    if(s.parentNode) s.parentNode.removeChild(s);
    init();
  };
  document.head.appendChild(s);
}

/* ---------- 启动 ---------- */
bootstrap();

})();
