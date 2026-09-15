// hook_abcdstr.js — 钩盈安壳的字符串解密器 abcdstr(int)，把关键索引的明文打出来
// 目标索引: 7902(算法名AES) 8121/8122(变换) 8242/8243/8244(AES密钥) 1661
//
// 这个脚本最后没跑起来。attach 上去进程当场就没了，一行日志都没输出。
// 后来才搞明白盈安壳的反调试里有一条是拿 svc 系统调用直接自杀的，
// 走的是内联 svc，根本不经过 libc，所以 hook exit/kill 这类函数一点用没有。
// 留着当记录：这条路是死的，别在它上面耗时间。
//
// 索引是我从壳的 run 方法反汇编里一个个抠出来的，本来指望 hook 完就能把密钥拿到。
var TARGETS = { 1661:1, 7902:1, 8121:1, 8122:1, 8242:1, 8243:1, 8244:1 };

function tryHook() {
    Java.perform(function () {
        var p = Java.use("v.m.p");
        p.abcdstr.overload('int').implementation = function (idx) {
            var r = this.abcdstr(idx);
            if (TARGETS[idx]) {
                console.log("[KEY] abcdstr(" + idx + ") = \"" + r + "\"");
            }
            return r;
        };
        console.log("[*] abcdstr hooked OK");
    });
}

// 当时想的是类可能加载得晚，所以加了个延时再试。
// 现在回头看，v.m.p 在壳自己的 dex 里，dump 出来已经损坏了，就算挂上也拿不到东西。
setTimeout(function () {
    try { tryHook(); }
    catch (e) {
        console.log("[*] v.m.p 未加载，等待类加载器...");
        Java.perform(function () {
            Java.enumerateClassLoaders({
                onMatch: function (loader) {
                    try {
                        var p = Java.use("v.m.p");
                        p.abcdstr.overload('int').implementation = function (idx) {
                            var r = this.abcdstr(idx);
                            if (TARGETS[idx]) console.log("[KEY] abcdstr(" + idx + ") = \"" + r + "\"");
                            return r;
                        };
                        console.log("[*] abcdstr hooked via loader");
                    } catch (e2) {}
                },
                onComplete: function () {}
            });
        });
    }
}, 1000);
