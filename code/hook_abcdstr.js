// hook_abcdstr.js — 钩住盈安壳的字符串解密器 abcdstr(int)，打印关键索引的明文
// 目标索引: 7902(算法名AES) 8121/8122(变换) 8242/8243/8244(AES密钥) 1661
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

// 等待类加载后挂钩
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
