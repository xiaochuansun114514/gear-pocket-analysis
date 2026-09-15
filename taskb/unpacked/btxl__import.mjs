
function fn(name)
{
var oHead = document.getElementsByTagName('HEAD').item(0);
var oScript = document.createElement("script");
oScript.language = "javascript";
oScript.type = "text/javascript";
oScript.defer = true; 
oScript.text = I.getjs(name); 
oHead.appendChild(oScript);
}
function syso(o)
{
if(o != null)
I.syso(o.toString());
else
I.syso("null");
}
function tw(o, o2)
{
var o3 = 1;
if(o2 != null)
	o3 = parseInt(o2);
if(o != null)
I.tw(o.toString(), o3);
else
I.tw("null", o3);
}
function ss(o, o2)
{
if(o2 == null)
return I.ss(o);
var type = typeof(o2);
if(type == "number")
I.ssNumber(o, o2);
else if(type == "boolean")
I.ssBoolean(o, o2);
else
I.ss(o, o2);
}
function sss(o, o2)
{
if(o2 == null)
return I.sss(o);
var type = typeof(o2);
if(type == "number")
I.sssNumber(o, o2);
else if(type == "boolean")
I.sssBoolean(o, o2);
else
I.sss(o, o2);
}
function $_FN(o)
{
if(o == null || typeof(o) == "function")
return true;
else
return false;
}
function $_FNULL(o)
{
if(o == null) 
return null;
else
return o.toString();
}
function $_RNSZ(o)
{
if(o == null) return null;
return o.split("\n\\\r");
}
function $_GETZS(o)
{
if(o == null) return null;
return o.join('\n\\\r');
}
function eval(o)
{
}
var activity = "^_activity_";

var i = {
'ss' : function(o,o2){ I.ss(o,o2); },
'sss' : function(o,o2){ I.sss(o,o2); },
'syso' : function(o){ I.syso(o); },
'tw' : function(o,o2){
if(o2 == null) 
o2 = 1;
I.tw(o,o2); 
},
'fd' : function(o){ return I.fd(o); },
'fe' : function(o){ return I.fe(o); },
'fs' : function(o){ return I.fs(o); },
'fr' : function(o,o2){
if(o2 == null)
return I.fr(o);
else
return I.fr(o,o2);
},
'fc' : function(o,o2,o3){
if(o3 == null)
return I.fc(o,o2);
else
return I.fc(o,o2,o3);
},
'fw' : function(o,o2,o3){
if(o3 == null)
return I.fw(o,o2);
else
return I.fw(o,o2,o3);
},
'fl' : function(o,o2){
if(o2 == null)
return $_RNSZ(I.fl(o));
else
return $_RNSZ(I.fl(o,o2));
},
'ft' : function(o,o2){ return I.ft(o,o2); },
'fdir' : function(o){
if(o == null)
return I.fdir();
else
return I.fdir(o);
},
'fuz' : function(o,o2,o3,o4){
if(o4 == null)
return I.fuz(o,o2,o3);
else
return I.fuz(o,o2,o3,o4);
},
'fuzs' : function(o,o2,o3){
if(o3 == null)
return I.fuzs(o,o2);
else
return I.fuzs(o,o2,o3);
},
'fo' : function(o){ I.fo(o); },
'fj' : function(o,o2,o3){
if(o3 == null)
return I.fj(o,o2);
else
return I.fj(o,o2,o3);
},
'sr' : function(o,o2,o3,o4){
if(o4 == null)
return I.sr(o,o2,o3);
else
return I.sr(o,o2,o3,o4);
},
'sj' : function(o,o2,o3){ return I.sj(o,o2,o3); },
'sl' : function(o,o2,o3){
if(o3 == null)
return $_RNSZ(I.sl(o,o2));
else
return $_RNSZ(I.sl(o,o2,o3));
},
'siof' : function(o,o2,o3){
if(o3 == null)
return I.siof(o,o2);
else
return I.siof(o,o2,o3);
},
'slof' : function(o,o2,o3){
if(o3 == null)
return I.slof(o,o2);
else
return I.slof(o,o2,o3);
},
'ssg' : function(o,o2,o3){
if(o3 == null)
return I.ssg(o,o2);
else
return I.ssg(o,o2,o3);
},
'slg' : function(o){ return I.slg(o); },
'strim' : function(o){ return I.strim(o); },
'slower' : function(o){ return I.slower(o); },
'supper' : function(o){ return I.supper(o); },
'stop' : function(o){ return I.stop(o); },
'sran' : function(o,o2){ return I.sran(o,o2); },
'nsz' : function(o){
if(typeof(o) == "number")
return new Array(o);
else
return o;
},
'hs' : function(o,o2,o3,o4,o5,o6,o7,o8,o9){
if(o7 != null && o8 != null)
return I.hs(o,o2,o3,o4,o5,o6,o7,o8,o9);
else if(o6 != null)
return I.hs(o,o2,o3,o4,o5,o6);
else if(o5 != null)
return I.hs(o,o2,o3,o4,o5);
else if(o4 != null)
return I.hs(o,o2,o3,o4);
else if(o3 != null)
return I.hs(o,o2,o3);
else
return I.hs(o);
},
'hd' : function(o,o2,o3,o4,o5,o6,o7,o8){
if(o7 != null)
return I.hd(o,o2,o3,o4,o5,o6,o7,o8);
else if(o3 != null)
return I.hd(o,o2,o3);
else
return I.hd(o,o2);
},
'hw' : function(o,o2,o3){
if(o3 == null)
I.hw(o);
else
I.hw(o,o2,o3);
},
'hws' : function(o){ I.hws(o); },
'ug' : function(o,o2,o3){
if(o3 == null)
return I.ug(o,o2);
else
return I.ug(o,o2,o3);
},
'us' : function(o,o2,o3,o4,o5,o6){
if(o6 != null)
return I.us(o,o2,o3,o4,o5,o6);
else if(o5 != null)
return I.us(o,o2,o3,o4,o5);
else if(o4 != null)
return I.us(o,o2,o3,o4);
else
return I.us(o,o2,o3);
},
'uigo' : function(o,o2){
if(o2 == null)
I.uigo(o);
else
I.uigo(o,o2);
},
'utw' : function(o,o2,o3,o4,o5,o6,o7,o8,o9,o10){
if(o9 != null || o10 != null){
if($_FN(o8) && $_FN(o9) && $_FN(o10))
return I.utw(o,o2,o3,o4,o5,o6,o7,$_FNULL(o8),$_FNULL(o9),$_FNULL(o10));
}
else if(o7 != null || o8 != null){
if($_FN(o7) && $_FN(o8))
return I.utw(o,o2,o3,o4,o5,o6,$_FNULL(o7),$_FNULL(o8));
}
else if(o5 != null || o6 != null){
if($_FN(o6))
return I.utw(o,o2,o3,o4,o5,$_FNULL(o6));
}
else
return I.utw(o,o2,o3,o4);
},
'endutw' : function(){ I.endutw(); },
'end' : function(){ I.end(); },
'ends' : function(){ I.ends(); },
'bfm' : function(o){ return I.bfm(o); },
'bfms' : function(o,o2,o3,o4){
if(o4 != null)
return I.bfms(o,o2,o3,o4);
else if(o3 != null)
return I.bfms(o,o2,o3);
else
return I.bfms(o,o2);
},
'ula' : function(o,o2,o3){
if(o == undefined) o = null;
if(o3 != null)
return I.ula(o,$_GETZS(o2),$_GETZS(o3));
else if(o2 != null)
return I.ula(o,o2);
else
return I.ula(o);
},
'uls' : function(o,o2,o3,o4,o5){
if(o4 != null || o5 != null)
return I.uls(o,o2,o3,o4,o5);
else if(o3 != null)
return I.uls(o,o2,o3);
else{
if(Object.prototype.toString.call(o2) == "[object Array]")
return I.uls(o,$_GETZS(o2));
else
return I.uls(o,o2);
}
},
'ulas' : function(o,o2,o3,o4){
if(o4 != null)
I.ulas(o,o2,o3,o4);
else
I.ulas(o,o2,o3);
},
'ulag' : function(o,o2,o3){
if(o3 != null)
return I.ulag(o,o2,o3);
else
return I.ulag(o,o2);
},
'usms' : function(o,o2){ I.usms(o,o2); },
'ucall' : function(o){ I.ucall(o); },
'time' : function(o){ return I.time(o); },
'fi' : function(o){ return I.fi(o); },
'stobm' : function(o,o2){ return I.stobm(o,o2); },
'sutf8to' : function(o){ return I.sutf8to(o); },
'uycl' : function(o,o2){
if(o2 != null)
I.uycl(o,o2);
else
I.uycl(o);
},
'ushsp' : function(o){ I.ushsp(o); },
'bfv' : function(o,o2){
if(o2 != null)
I.bfv(o,o2);
else
I.bfv(o);
},
'bfvs' : function(o,o2){ I.bfvs(o,o2); },
'bfvss' : function(o,o2,o3){
if(o3 != null)
return I.bfvss(o,o2,o3);
else
return I.bfvss(o,o2);
},
'ftz' : function(o,o2,o3,o4,o5){
if($_FN(o5))
I.ftz(o,o2,o3,o4,$_FNULL(o5));
},
'uapp' : function(o,o2){
if(o2 != null)
return I.uapp(o,o2);
else
return I.uapp(o);
},
'uapplist' : function(o){ return $_RNSZ(I.uapplist(o)); },
'uninapp' : function(o){ I.uninapp(o); },
'huf' : function(o,o2,o3,o4,o5){
if(o5 != null)
return I.huf(o,o2,o3,o4,o5);
else
return I.huf(o,o2,o3,o4);
},
'nvw' : function(o,o2,o3,o4){
if(o4 != null)
return I.nvw(o,o2,o3,o4);
else if(o3 != null)
I.nvw(o,o2,o3);
else
I.nvw(o,o2);
},
'uall' : function(o,o2){ return I.uall(o,o2); },
'urvw' : function(o){ I.urvw(o); },
'sbp' : function(o,o2,o3,o4,o5,o6){
if(o6 != null)
return I.sbp(o,o2,o3,o4,o5,o6);
else if(o5 != null)
return I.sbp(o,o2,o3,o4,o5);
else
return I.sbp(o);
},
'sdeg' : function(o){ I.sdeg(o); },
'bfs' : function(o,o2,o3){
if(o3 != null)
I.bfs(o,o2,o3);
else
I.bfs(o,o2);
},
'tot' : function(o){ return I.tot(o); },
'tzz' : function(o,o2){ return I.tzz(o,o2); },
'tsf' : function(o,o2,o3){
if(o3 != null)
return I.tsf(o,o2,o3);
else
return I.tsf(o,o2);
},
'tfz' : function(o,o2){ return I.tfz(o,o2); },
'sxb' : function(o){ I.sxb(o); },
'shb' : function(){ return I.shb(); },
'tcc' : function(o,o2){ return I.tcc(o,o2); },
'usjxm' : function(o){ I.usjxm(o); },
'addv' : function(o,o2){ return I.addv(o,o2); },
'gvs' : function(o,o2){
if(o2 != null)
return I.gvs(o,o2);
else
return I.gvs(o);
},
'aslist' : function(o,o2,o3){
if(o == undefined) o = null;
if(o3 != null)
return I.aslist(o,$_GETZS(o2),o3);
else
return I.aslist(o,$_GETZS(o2));
},
'sslist' : function(o,o2,o3){ I.sslist(o,o2,o3); },
'gslist' : function(o,o2){ return I.gslist(o,o2); },
'gslistl' : function(o){ return I.gslistl(o); },
'dslist' : function(o,o2){ I.dslist(o,o2); },
'gslistsz' : function(o){ return $_RNSZ(I.gslistsz(o)); },
'gslistis' : function(o,o2){ return I.gslistis(o,o2); },
'gslistiof' : function(o,o2){ return I.gslistiof(o,o2); },
'gslistlof' : function(o,o2){ return I.gslistlof(o,o2); },
'nuibs' : function(o,o2,o3){ return I.nuibs(o,o2,o3); },
'ngde' : function(o,o2,o3,o4,o5){
if(o5 != null)
return I.ngde(o,o2,o3,o4,o5);
else if(o4 != null)
return I.ngde(o,o2,o3,o4);
else if(o3 != null)
return I.ngde(o,o2,o3);
else
return I.ngde(o,o2);
},
'sit' : function(o,o2,o3,o4){
if(o == undefined) o = null;
if(o4 != null){
if(Object.prototype.toString.call(o4) == "[object Array]")
return I.sit(o,o2,o3,$_GETZS(o4));
else
return I.sit(o,o2,o3,o4);
}else
return I.sit(o,o2,o3);
},
'uit' : function(o,o2,o3){
if(o2 != null || o3 != null)
return I.uit(o,o2,o3);
else
return I.uit(o);
},
'git' : function(o,o2,o3){
if(o3 != null)
return I.git(o,o2,o3);
else
return I.git(o,o2);
},
'uqr' : function(o,o2){
if(o2 != null)
return I.uqr(o,o2);
else if(o != null)
return I.uqr(o);
else
return I.uqr();
},
'zdp' : function(o){ return I.zdp(o); },
'zpd' : function(o){ return I.zpd(o); },
'zps' : function(o){ return I.zps(o); },
'zsp' : function(o){ return I.zsp(o); },
'lan' : function(o){ return I.lan(o); },
'sjxx' : function(){ return $_RNSZ(I.sjxx()); },
'simsi' : function(){ return I.simsi(); },
'simei' : function(){ return I.simei(); },
'endkeyboard' : function(){ return I.endkeyboard(); },
'hdfl' : function(o,o2,o3,o4,o5,o6,o7){
if(o5 != null){
if($_FN(o6) && $_FN(o7))
return I.hdfl(o,o2,o3,o4,o5,$_FNULL(o6),$_FNULL(o7));
}else if(o4 != null){
if($_FN(o3) && $_FN(o4))
return I.hdfl(o,o2,$_FNULL(o3),$_FNULL(o4));
}else{
if($_FN(o2) && $_FN(o3))
return I.hdfl(o,$_FNULL(o2),$_FNULL(o3));
}
},
't' : function(o){
if($_FN(o))
I.t($_FNULL(o));
},
'hdfla' : function(o,o2,o3,o4,o5){
if(o5 != null)
return I.hdfla(o,o2,o3,o4,o5);
else
return I.hdfla(o,o2,o3,o4);
},
'hdd' : function(o,o2,o3,o4,o5,o6,o7){ I.hdd(o,o2,o3,o4,o5,o6,o7); },
'hdda' : function(o,o2,o3,o4,o5,o6,o7){
if(o6 != null)
return I.hdda(o,o2,o3,o4,o5,o6,o7);
else if(o5 != null)
return I.hdda(o,o2,o3,o4,o5);
else if(o4 != null)
return I.hdda(o,o2,o3,o4);
else
return I.hdda(o,o2,o3);
},
'hddgl' : function(){ return I.hddgl(); },
'hddg' : function(o,o2){ return I.hddg(o,o2); },
'hdds' : function(o,o2,o3){ I.hdds(o,o2,o3); },
'hdduigo' : function(o,o2){
if(o != null || o2 != null)
I.hdduigo(o,o2);
else
I.hdduigo();
},
'swh' : function(o){ return I.swh(o); },
'ufnsui' : function(o){
if($_FN(o))
I.ufnsui($_FNULL(o));
},
'se' : function(o,o2,o3){
if(o3 != null)
I.se(o,o2,o3);
else
I.se(o,o2);
},
'usg' : function(o,o2){
if(o == undefined) o = null;
return I.usg(o,o2);
},
'uzd' : function(o,o2,o3){
if(o == undefined) o = null;
if(o3 != null)
return I.uzd(o,$_GETZS(o2),o3);
else
return I.uzd(o,o2);
},
'usxq' : function(o,o2,o3,o4,o5){
if(o5 != null)
return I.usxq(o,o2,o3,o4,o5);
else
return I.usxq(o,o2,o3);
},
'usxh' : function(o,o2,o3,o4,o5){
if(o5 != null)
return I.usxh(o,o2,o3,o4,o5);
else
return I.usxh(o,o2,o3);
},
'usx' : function(o,o2,o3,o4,o5){
if(o5 != null)
I.usx(o,o2,o3,o4,o5);
else if(o3 != null)
I.usx(o,o2,o3);
else
return I.usx(o,o2);
},
'ujp' : function(o,o2){ I.ujp(o,o2); },
'bly' : function(o,o2){ return I.bly(o,o2); },
'sqlite' : function(o,o2){ return I.sqlite(o,o2); },
'sql' : function(o,o2,o3,o4,o5){
if(o5 != null)
return I.sql(o,o2,o3,o4,o5);
else if(o4 != null)
return I.sql(o,o2,o3,o4);
else if(o3 != null)
return I.sql(o,o2,o3);
else
return I.sql(o,o2);
},
'sqlsele' : function(o,o2,o3){
if(o3 != null)
I.sqlsele(o,o2,o3);
else
return I.sqlsele(o,o2);
},
'dha' : function(o,o2){ return I.dha(o,o2); },
'dhs' : function(o,o2,o3,o4,o5,o6,o7,o8){
if(o5 != null)
return I.dhs(o,o2,o3,o4,o5,o6,o7,o8);
else
return I.dhs(o,o2,o3,o4);
},
'dht' : function(o,o2,o3,o4){ return I.dht(o,o2,o3,o4); },
'dhr' : function(o,o2,o3,o4,o5,o6){
if(o3 != null)
return I.dhr(o,o2,o3,o4,o5,o6);
else
return I.dhr(o,o2);
},
'dhset' : function(o,o2){ return I.dhset(o,$_GETZS(o2)); },
'dhas' : function(o,o2,o3){ return I.dhas(o,o2,$_GETZS(o3)); },
'dhast' : function(o,o2){ return I.dhast(o,$_GETZS(o2)); },
'dh' : function(o,o2,o3){
if(o3 != null)
return I.dh(o,o2,o3);
else
return I.dh(o,o2);
},
'dhon' : function(o,o2,o3,o4,o5){
if(o5 != null){
if($_FN(o2) && $_FN(o3) && $_FN(o4) && $_FN(o5))
return I.dhon(o,$_FNULL(o2),$_FNULL(o3),$_FNULL(o4),$_FNULL(o5));
}else{
if($_FN(o2) && $_FN(o3) && $_FN(o4))
return I.dhon(o,$_FNULL(o2),$_FNULL(o3),$_FNULL(o4));
}
},
'dhb' : function(o,o2,o3){
if(o3 != null)
I.dhb(o,o2,o3);
else if(o2 != null)
return I.dhb(o,o2);
else
return I.dhb(o);
},
'hsas' : function(o,o2){ I.hsas(o,o2); },
'has' : function(o,o2){ I.has(o,o2); },
'uxf' : function(o,o2,o3,o4,o5,o6,o7,o8,o9,o10){
if(o10 != null)
I.uxf(o,o2,o3,o4,o5,o6,o7,o8,o9,o10);
else if(o9 != null)
return I.uxf(o,o2,o3,o4,o5,o6,o7,o8,o9);
else if(o7 != null)
I.uxf(o,o2,o3,o4,o5,o6,o7);
else if(o4 != null)
return I.uxf(o,o2,o3,o4);
else if(o2 != null)
I.uxf(o,o2);
else
I.uxf(o);
},
'uyoumi' : function(){ syso("no"); },
'esl' : function(){ syso("no"); },
'tts' : function(o,o2,o3,o4){
if(o4 != null)
return I.tts(o,o2,o3,o4);
else if(o3 != null)
I.tts(o,o2,o3);
else if(o2 != null)
return I.tts(o,o2);
else
return I.tts();
},
'blp' : function(o,o2,o3,o4,o5){
if(o5 != null)
return I.blp(o,o2,o3,o4,o5);
else
return I.blp(o);
},
'sota' : function(o,o2,o3){
if(o3 != null)
I.sota(o,o2,o3);
else
return I.sota(o,o2);
},
'sot' : function(o,o2,o3,o4,o5,o6){
if(o6 != null){
if($_FN(o6))
return I.sot(o,o2,o3,o4,o5,$_FNULL(o6));
}
else if(o5 != null){
if($_FN(o5))
return I.sot(o,o2,o3,o4,$_FNULL(o5));
}
else if(o3 != null)
return I.sot(o,o2,o3);
else
return I.sot(o,o2);
},
'otob' : function(o,o2){
if(o2 != null)
return I.otob(o,o2);
else
return I.otob(o);
},
'btoo' : function(o,o2,o3){
if(o3 != null)
return I.btoo(o,o2,o3);
else
return I.btoo(o,o2);
},
'clssm' : function(o,o2){
return I.clssm(o,o2);
},
'res' : function(o,o2,o3,o4){
if(o4 != null)
return I.res(o,o2,o3,o4);
else if(o3 != null)
return I.res(o,o2,o3);
else if(o2 != null)
return I.res(o,o2);
else if(o != null)
return I.res(o);
else
return I.res();
},
'javass' : function(o,o2,o3){
return I.javass(o,o2,o3);
},
'javags' : function(o,o2){
return I.javags(o,o2);
},
'javax' : function(o,o2,o3,o4,o5){
if(o5 != null){
if($_FN(o5))
return I.javax(o,o2,o3,$_GETZS(o4),$_FNULL(o5));
}else if(o4 != null)
return I.javax(o,o2,o3,$_GETZS(o4));
else
return I.javax(o,o2,o3);
},
'java' : function(o,o2,o3,o4){
if(o4 != null){
if($_FN(o4))
return I.java(o,o2,$_GETZS(o3),$_FNULL(o4));
}else if(o3 != null)
return I.java(o,o2,$_GETZS(o3));
else
return I.java(o,o2);
},
'javanew' : function(o,o2,o3){
if(o3 != null){
if($_FN(o3))
return I.javanew(o,$_GETZS(o2),$_FNULL(o3));
}
else if(o2 != null)
return I.javanew(o,$_GETZS(o2));
else
return I.javanew(o);
},
'javacb' : function(o,o2){
return I.javacb(o,$_FNULL(o2));
},
'cls' : function(o,o2){
if(o2 != null)
return I.cls(o,o2);
else
return I.cls(o);
},
'loadjar' : function(o,o2){
if(o2 != null)
return I.loadjar(o,o2);
else
return I.loadjar(o);
},
'loadso' : function(o){
I.loadso(o);
},
'src' : function(o,o2){
I.src(o,o2);
},
'zj' : function(o,o2){
if(o2 != null)
return I.zj(o,$_GETZS(o2));
else
return I.zj(o);
},
'call' : function(o,o2,o3){
if(o3 != null)
return I.call(o,o2,$_GETZS(o3));
else
return I.call(o,o2);
}

};


ÂÓÃ