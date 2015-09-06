/*
 * A JavaScript implementation of the RSA Data Security, Inc. MD5 Message
 * Digest Algorithm, as defined in RFC 1321.
 * Version 2.1 Copyright (C) Paul Johnston 1999 - 2002.
 * Other contributors: Greg Holt, Andrew Kepert, Ydnar, Lostinet
 * Distributed under the BSD License
 * See http://pajhome.org.uk/crypt/md5 for more info.
 */

/*
 * Configurable variables. You may need to tweak these to be compatible with
 * the server-side, but the defaults work in most cases.
 */
var hexcase = 0;  /* hex output format. 0 - lowercase; 1 - uppercase        */
var b64pad  = ""; /* base-64 pad character. "=" for strict RFC compliance   */
var chrsz   = 8;  /* bits per input character. 8 - ASCII; 16 - Unicode      */

/*
 * These are the functions you'll usually want to call
 * They take string arguments and return either hex or base-64 encoded strings
 */
function hex_md5(s){ return binl2hex(core_md5(str2binl(s), s.length * chrsz));}
function b64_md5(s){ return binl2b64(core_md5(str2binl(s), s.length * chrsz));}
function str_md5(s){ return binl2str(core_md5(str2binl(s), s.length * chrsz));}
function hex_hmac_md5(key, data) { return binl2hex(core_hmac_md5(key, data)); }
function b64_hmac_md5(key, data) { return binl2b64(core_hmac_md5(key, data)); }
function str_hmac_md5(key, data) { return binl2str(core_hmac_md5(key, data)); }

/*
 * Perform a simple self-test to see if the VM is working
 */
function md5_vm_test()
{
    return hex_md5("abc") == "900150983cd24fb0d6963f7d28e17f72";
}

/*
 * Calculate the MD5 of an array of little-endian words, and a bit length
 */
function core_md5(x, len)
{
    /* append padding */
    x[len >> 5] |= 0x80 << ((len) % 32);
    x[(((len + 64) >>> 9) << 4) + 14] = len;

    var a =  1732584193;
    var b = -271733879;
    var c = -1732584194;
    var d =  271733878;

    for(var i = 0; i < x.length; i += 16)
    {
        var olda = a;
        var oldb = b;
        var oldc = c;
        var oldd = d;

        a = md5_ff(a, b, c, d, x[i+ 0], 7 , -680876936);
        d = md5_ff(d, a, b, c, x[i+ 1], 12, -389564586);
        c = md5_ff(c, d, a, b, x[i+ 2], 17,  606105819);
        b = md5_ff(b, c, d, a, x[i+ 3], 22, -1044525330);
        a = md5_ff(a, b, c, d, x[i+ 4], 7 , -176418897);
        d = md5_ff(d, a, b, c, x[i+ 5], 12,  1200080426);
        c = md5_ff(c, d, a, b, x[i+ 6], 17, -1473231341);
        b = md5_ff(b, c, d, a, x[i+ 7], 22, -45705983);
        a = md5_ff(a, b, c, d, x[i+ 8], 7 ,  1770035416);
        d = md5_ff(d, a, b, c, x[i+ 9], 12, -1958414417);
        c = md5_ff(c, d, a, b, x[i+10], 17, -42063);
        b = md5_ff(b, c, d, a, x[i+11], 22, -1990404162);
        a = md5_ff(a, b, c, d, x[i+12], 7 ,  1804603682);
        d = md5_ff(d, a, b, c, x[i+13], 12, -40341101);
        c = md5_ff(c, d, a, b, x[i+14], 17, -1502002290);
        b = md5_ff(b, c, d, a, x[i+15], 22,  1236535329);

        a = md5_gg(a, b, c, d, x[i+ 1], 5 , -165796510);
        d = md5_gg(d, a, b, c, x[i+ 6], 9 , -1069501632);
        c = md5_gg(c, d, a, b, x[i+11], 14,  643717713);
        b = md5_gg(b, c, d, a, x[i+ 0], 20, -373897302);
        a = md5_gg(a, b, c, d, x[i+ 5], 5 , -701558691);
        d = md5_gg(d, a, b, c, x[i+10], 9 ,  38016083);
        c = md5_gg(c, d, a, b, x[i+15], 14, -660478335);
        b = md5_gg(b, c, d, a, x[i+ 4], 20, -405537848);
        a = md5_gg(a, b, c, d, x[i+ 9], 5 ,  568446438);
        d = md5_gg(d, a, b, c, x[i+14], 9 , -1019803690);
        c = md5_gg(c, d, a, b, x[i+ 3], 14, -187363961);
        b = md5_gg(b, c, d, a, x[i+ 8], 20,  1163531501);
        a = md5_gg(a, b, c, d, x[i+13], 5 , -1444681467);
        d = md5_gg(d, a, b, c, x[i+ 2], 9 , -51403784);
        c = md5_gg(c, d, a, b, x[i+ 7], 14,  1735328473);
        b = md5_gg(b, c, d, a, x[i+12], 20, -1926607734);

        a = md5_hh(a, b, c, d, x[i+ 5], 4 , -378558);
        d = md5_hh(d, a, b, c, x[i+ 8], 11, -2022574463);
        c = md5_hh(c, d, a, b, x[i+11], 16,  1839030562);
        b = md5_hh(b, c, d, a, x[i+14], 23, -35309556);
        a = md5_hh(a, b, c, d, x[i+ 1], 4 , -1530992060);
        d = md5_hh(d, a, b, c, x[i+ 4], 11,  1272893353);
        c = md5_hh(c, d, a, b, x[i+ 7], 16, -155497632);
        b = md5_hh(b, c, d, a, x[i+10], 23, -1094730640);
        a = md5_hh(a, b, c, d, x[i+13], 4 ,  681279174);
        d = md5_hh(d, a, b, c, x[i+ 0], 11, -358537222);
        c = md5_hh(c, d, a, b, x[i+ 3], 16, -722521979);
        b = md5_hh(b, c, d, a, x[i+ 6], 23,  76029189);
        a = md5_hh(a, b, c, d, x[i+ 9], 4 , -640364487);
        d = md5_hh(d, a, b, c, x[i+12], 11, -421815835);
        c = md5_hh(c, d, a, b, x[i+15], 16,  530742520);
        b = md5_hh(b, c, d, a, x[i+ 2], 23, -995338651);

        a = md5_ii(a, b, c, d, x[i+ 0], 6 , -198630844);
        d = md5_ii(d, a, b, c, x[i+ 7], 10,  1126891415);
        c = md5_ii(c, d, a, b, x[i+14], 15, -1416354905);
        b = md5_ii(b, c, d, a, x[i+ 5], 21, -57434055);
        a = md5_ii(a, b, c, d, x[i+12], 6 ,  1700485571);
        d = md5_ii(d, a, b, c, x[i+ 3], 10, -1894986606);
        c = md5_ii(c, d, a, b, x[i+10], 15, -1051523);
        b = md5_ii(b, c, d, a, x[i+ 1], 21, -2054922799);
        a = md5_ii(a, b, c, d, x[i+ 8], 6 ,  1873313359);
        d = md5_ii(d, a, b, c, x[i+15], 10, -30611744);
        c = md5_ii(c, d, a, b, x[i+ 6], 15, -1560198380);
        b = md5_ii(b, c, d, a, x[i+13], 21,  1309151649);
        a = md5_ii(a, b, c, d, x[i+ 4], 6 , -145523070);
        d = md5_ii(d, a, b, c, x[i+11], 10, -1120210379);
        c = md5_ii(c, d, a, b, x[i+ 2], 15,  718787259);
        b = md5_ii(b, c, d, a, x[i+ 9], 21, -343485551);

        a = safe_add(a, olda);
        b = safe_add(b, oldb);
        c = safe_add(c, oldc);
        d = safe_add(d, oldd);
    }
    return Array(a, b, c, d);

}

/*
 * These functions implement the four basic operations the algorithm uses.
 */
function md5_cmn(q, a, b, x, s, t)
{
    return safe_add(bit_rol(safe_add(safe_add(a, q), safe_add(x, t)), s),b);
}
function md5_ff(a, b, c, d, x, s, t)
{
    return md5_cmn((b & c) | ((~b) & d), a, b, x, s, t);
}
function md5_gg(a, b, c, d, x, s, t)
{
    return md5_cmn((b & d) | (c & (~d)), a, b, x, s, t);
}
function md5_hh(a, b, c, d, x, s, t)
{
    return md5_cmn(b ^ c ^ d, a, b, x, s, t);
}
function md5_ii(a, b, c, d, x, s, t)
{
    return md5_cmn(c ^ (b | (~d)), a, b, x, s, t);
}

/*
 * Calculate the HMAC-MD5, of a key and some data
 */
function core_hmac_md5(key, data)
{
    var bkey = str2binl(key);
    if(bkey.length > 16) bkey = core_md5(bkey, key.length * chrsz);

    var ipad = Array(16), opad = Array(16);
    for(var i = 0; i < 16; i++)
    {
        ipad[i] = bkey[i] ^ 0x36363636;
        opad[i] = bkey[i] ^ 0x5C5C5C5C;
    }

    var hash = core_md5(ipad.concat(str2binl(data)), 512 + data.length * chrsz);
    return core_md5(opad.concat(hash), 512 + 128);
}

/*
 * Add integers, wrapping at 2^32. This uses 16-bit operations internally
 * to work around bugs in some JS interpreters.
 */
function safe_add(x, y)
{
    var lsw = (x & 0xFFFF) + (y & 0xFFFF);
    var msw = (x >> 16) + (y >> 16) + (lsw >> 16);
    return (msw << 16) | (lsw & 0xFFFF);
}

/*
 * Bitwise rotate a 32-bit number to the left.
 */
function bit_rol(num, cnt)
{
    return (num << cnt) | (num >>> (32 - cnt));
}

/*
 * Convert a string to an array of little-endian words
 * If chrsz is ASCII, characters >255 have their hi-byte silently ignored.
 */
function str2binl(str)
{
    var bin = Array();
    var mask = (1 << chrsz) - 1;
    for(var i = 0; i < str.length * chrsz; i += chrsz)
        bin[i>>5] |= (str.charCodeAt(i / chrsz) & mask) << (i%32);
    return bin;
}

/*
 * Convert an array of little-endian words to a string
 */
function binl2str(bin)
{
    var str = "";
    var mask = (1 << chrsz) - 1;
    for(var i = 0; i < bin.length * 32; i += chrsz)
        str += String.fromCharCode((bin[i>>5] >>> (i % 32)) & mask);
    return str;
}

/*
 * Convert an array of little-endian words to a hex string.
 */
function binl2hex(binarray)
{
    var hex_tab = hexcase ? "0123456789ABCDEF" : "0123456789abcdef";
    var str = "";
    for(var i = 0; i < binarray.length * 4; i++)
    {
        str += hex_tab.charAt((binarray[i>>2] >> ((i%4)*8+4)) & 0xF) +
            hex_tab.charAt((binarray[i>>2] >> ((i%4)*8  )) & 0xF);
    }
    return str;
}

/*
 * Convert an array of little-endian words to a base-64 string
 */
function binl2b64(binarray)
{
    var tab = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    var str = "";
    for(var i = 0; i < binarray.length * 4; i += 3)
    {
        var triplet = (((binarray[i   >> 2] >> 8 * ( i   %4)) & 0xFF) << 16)
            | (((binarray[i+1 >> 2] >> 8 * ((i+1)%4)) & 0xFF) << 8 )
            |  ((binarray[i+2 >> 2] >> 8 * ((i+2)%4)) & 0xFF);
        for(var j = 0; j < 4; j++)
        {
            if(i * 8 + j * 6 > binarray.length * 32) str += b64pad;
            else str += tab.charAt((triplet >> 6*(3-j)) & 0x3F);
        }
    }
    return str;
}

/*************************************** Cookie 操作 ***************************************/
/**
 * 获取本机所有cookie
 * @return {Object} cookie键值对集合
 */
function getCookies() {
    var cookie = {};
    var all = document.cookie;
    if (all === '') return cookie;
    var list = all.split('; ');
    for (var i = 0, len = list.length; i < len; i++) {
        var item = list[i];
        var p = item.indexOf('=');
        var name = item.substring(0, p);
        name = decodeURIComponent(name);
        var value = item.substring(p + 1);
        value = decodeURIComponent(value);
        cookie[name] = value;
    }
    return cookie;
}

/**
 * 设置cookie
 * @param {String} name    cookie键
 * @param {String} value   cookie值
 * @param {timestamp} expires 失效时间（可选）
 * @param {String} path    作用路径（可选）
 * @param {String} domain  作用域（可选）
 * @param {boolean} secure  使用https时设置为true（可选）
 */
function setCookie(name, value, expires, path, domain, secure) {
    var cookie = encodeURIComponent(name) + '=' + encodeURIComponent(value);
    if (expires)
        cookie += '; expires=' + expires.toGMTString();
    if (path)
        cookie += '; path=' + path;
    if (domain)
        cookie += '; domain=' + domain;
    if (secure)
        cookie += '; secure=' + secure;
    document.cookie = cookie;
}

/**
 * 移除cookie
 * @param  {String} name   cookie键
 * @param  {String} path   cookie值
 * @param  {String} domain 作用域
 */
function removeCookie(name, path, domain) {
    document.cookie = 'name=' + name + '; path=' + path + '; domain=' + domain + '; max-age=0';
}
/*************************************** /Cookie 操作 ***************************************/


/*************************************** AJAX 操作 ***************************************/
//创建XMLHttpRequest对象
function createXMLHttpRequest()
{
    var xmlHttpReq;
    if(window.XMLHttpRequest)
    {
        // DOM 2浏览器
        xmlHttpReq = new XMLHttpRequest();
    }
    else if (window.ActiveXObject)
    {
        // IE浏览器
        var versions = [ "MSXML2.XMLHttp.5.0",  "MSXML2.XMLHttp.4.0","MSXML2.XMLHttp.3.0", "MSXML2.XMLHttp","Microsoft.XMLHttp"];
        for(var i = 0; i < versions.length; i ) {
            try{
                xmlHttpReq = new ActiveXObject(versions[i]);
                return oXmlHttp;
            } catch (oError) {
                console.log("Can not create XMLHttp Object.");
            }
        }
    }
    return xmlHttpReq;
}

/**
 * 将对象转为参数字符串
 * @param  {Object} data 参数对象
 * @return {String}      参数字符串
 */
function serialize(data) {
    if (!data) return '';
    var pairs = [];
    for (var name in data) {
        if (!data.hasOwnProperty(name)) continue;
        if (typeof data[name] === 'function') continue;
        var value = data[name].toString();
        name = encodeURIComponent(name);
        value = encodeURIComponent(value);
        pairs.push(name + '=' + value);
    }
    return pairs.join('&');
}

/**
 * Ajax封装请求
 * @param  {Object} param 参数对象，支持type,url,data,asyn,success,error
 * @return {[type]}       [description]
 */
function ajax(param){
    var type = param.type;
    var url = param.url;
    var data = param.data;
    var asyn = param.asyn;
    var sucHandler = param.success;
    var errHandler = param.error;

    if(type === "GET" && data != null && data != "undefined"){
        url = url + "?" + serialize(data);
    }

    var xmlHttpReq = createXMLHttpRequest();
    xmlHttpReq.open(type, url, asyn);
    xmlHttpReq.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
    xmlHttpReq.onreadystatechange = function processResponse(){
        if(xmlHttpReq.readyState == 4){
            if(xmlHttpReq.status == 200){
                sucHandler(xmlHttpReq.responseText);
            }else{
                errHandler(xmlHttpReq.responseText);
            }
        }
    };

    if(type.toUpperCase() === "GET"){
        xmlHttpReq.send();
    }else if(type.toUpperCase() === "POST"){
        xmlHttpReq.send(serialize(data));
    }
}
/*************************************** /AJAX 操作 ***************************************/

/************************** 获取元素原始大小 **************************/
/**
 * 获取图片的原始宽度（兼容IE6/7）
 * @param  {[type]} element 元素对象
 * @return {[type]}
 */
function getNaturalWidth(element) {
    if(element.naturalWidth){
        return element.naturalWidth;
    }else{
        var img = new Image();
        img.src = element.src;
        return img.width;
    }
}

/**
 * 获取图片的原始高度（兼容IE6/7）
 * @param  {[type]} element 元素对象
 * @return {[type]}
 */
function getNaturalHeight(element){
    if(element.naturalHeight){
        return element.naturalHeight;
    }else{
        var img = new Image();
        img.src = element.src;
        return img.height;
    }
}
/************************** /获取元素原始大小 **************************/

/****** 事件绑定函数兼容 *******/
/*
 * 兼容addEventListener方法
 */
var addEvent = document.addEventListener ?
    function(elem, type, listener, useCapture){
        elem.addEventListener(type, listener, useCapture);
    } :
    function(elem, type, listener, useCapture){
        elem.attachEvent('on' + type, listener);
    };
/**
 * 兼容removeEventListener方法
 */
var delEvent = document.removeEventListener ?
    function(elem, type, listener, useCapture){
        elem.removeEventListener(type, listener, useCapture);
    } :
    function(elem, type, listener, useCapture){
        elem.detachEvent('on' + type, listener);
    };
/**
 * 兼容dispatchEvent方法
 */
var triggerEvent = function(element, eventType){
    var evtObj;
    if(document.dispatchEvent){
        evtObj = document.createEvent("Event");
        evtObj.initEvent(eventType, true, true);
        element.dispatchEvent(evtObj);
    }else if(document.createEventObject){
        element.fireEvent("on" + eventType);
    }
};
/****** /事件绑定函数兼容 *******/


/****** dataset兼容 *******/
var getDataset = function(element){
    if(element.dataset){
        return element.dataset;
    }else{
        var id = element.getAttribute("data-id");
        var name = element.getAttribute("data-name");
        var learnercount = element.getAttribute("data-learnercount");
        var provider = element.getAttribute("data-provider");
        var categoryname = element.getAttribute("data-categoryname");
        var description = element.getAttribute("data-description");
        var middlephotourl = element.getAttribute("data-middlephotourl");
        return {id:id, name:name, learnercount:learnercount, provider:provider, categoryname:categoryname, description:description, middlephotourl:middlephotourl};
    }
};
/****** /dataset兼容（不具有普适性） *******/

/**
 * 设置元素透明度（兼容IE6-8）
 * @param  {[type]} element [description]
 * @param  {[type]} value   [description]
 * @return {[type]}         [description]
 */
var isIE8Browse = navigator.userAgent.toUpperCase().indexOf("IE 8.0") > 0; //是否是IE8浏览器
var chgOpacity = function(element, value){
    if(isIE8Browse){
        // element.style.filter = "Alpha(opacity=" + value*100 + ")";
        element.style.filter = "progid:DXImageTransform.Microsoft.Alpha(opacity=" + value*100 + ")";
    }else{
        element.style.opacity = value;
    }
}
/**
 * 获取元素透明度（兼容IE6-8）
 * @param  {[type]} element [description]
 * @return {[type]}         [description]
 */
var getOpacity = function(element){
    if(isIE8Browse){
        var filterAttr = element.style.filter;
        if(filterAttr === ""){
            return 0;
        }
        var opacity = filterAttr.substring(filterAttr.indexOf("=") + 1, filterAttr.lastIndexOf(")"));
        return parseFloat(opacity) / 100;
    }else{
        return element.style.opacity;
    }
}

/**
 * 取得样式，包括非行间样式
 * @param  {Object} 节点
 * @param  {String} css名
 * @return {String} 返回样式结果
 */
var getStyle = function (_obj, _name) {
    if(_obj.style[_name]){
        return _obj.style[_name];
    }else{
        if(_obj.currentStyle) {
            return _obj.currentStyle[_name];
        }else{
            return getComputedStyle(_obj,false)[_name];
        }
    }
}

/**
 * 添加类名
 * @param {Object} 节点
 * @param {String} 类名
 * @return {Void}
 */
function addClassName(_node, _className) {
    var _aClass = _node.className.split(' ');
    var _exist = false;
    for (var i = 0; i < _aClass.length; i++) {
        if(_aClass[i] === _className){
            _exist = true;
        }
    };
    if(!_exist){
        _node.className = _node.className + ' ' + _className;
    }
};
/**
 * 删除类名
 * @param {Object} 节点
 * @param {String} 类名
 * @return {Void}
 */
function delClassName(_node, _className) {
    var _aClass = _node.className.split(' ');
    for (var i = 0; i < _aClass.length; i++) {
        if(_aClass[i] === _className){
            _aClass[i] = '';
        }
    };
    _node.className = _aClass.join(' ');
};

/**
 * 1.初始化顶部通知条
 */
var initTip = function(){
    //检测是否显示顶部通知条、是否关注
    var allCookie = getCookies();
    var topbarNotice = allCookie.topbarNotice;
    var followSuc = allCookie.followSuc;
    if(topbarNotice != "undefined" && topbarNotice == "0"){
        document.querySelector(".m-tip").style.display = "none";
    }
    if(followSuc === "1"){
        document.querySelector(".m-header .noFocusOn").style.display = "none";
        document.querySelector(".m-header .hasFocusOn").style.display = "block";
    }

    //添加“取消通知条”事件监听
    document.querySelector(".m-tip .right").onclick = function(){
        setCookie("topbarNotice", "0", new Date(new Date().getMilliseconds() + 60 * 365 * 24 * 60 * 60 * 1000));
        document.querySelector(".m-tip").style.display = "none";
    }
}


/**
 * 2.初始化顶部导航
 */
var initTopNav = function(){
    //绑定“关注”事件监听
    document.querySelector(".m-header .follow").onclick = function(){
        var loginSuc = getCookies().loginSuc;
        if(loginSuc != "1"){
            document.querySelector(".m-login").style.display = "block";
        }
    }


    var username=document.getElementById("username");
    var password=document.getElementById("password");

    //表单验证
    var validateForm = function(){
        var _flag = true;
        if(username.value == ''){
            _flag = false;
            addClassName(username,'u-errorInput');
        }
        if(password.value == ''){
            _flag = false;
            addClassName(password,'u-errorInput');
        }
        return _flag;
    }

    //输入框变化时消除错误
    username.onchange = function(){
        if(this.value != ''){
            delClassName(this,'u-errorInput');
        }
    }
    password.onchange = function(){
        if(this.value != ''){
            delClassName(this,'u-errorInput');
        }
    }

    //绑定登录“关闭”按钮事件
    document.querySelector(".m-login .closeBtn").onclick = function(){
        document.querySelector(".m-login").style.display = "none";
    }

    //绑定用户登录按钮
    document.querySelector(".m-login .loginBtn").onclick = function(){
        var url = "http://study.163.com/webDev/login.htm";

        /*		var username = hex_md5("studyOnline");
         var password = hex_md5("study.163.com");*/
        //表单验证
        if(!validateForm()){
            return ;
        }
        ajax({
            type: "GET",
            url: url,
            asyn: true,
            data: {
                "userName": hex_md5(username.value),
                "password": hex_md5(password.value)
            },
            success: function(resp){
                if(resp === "1"){
                    //登录成功
                    document.querySelector(".m-login").style.display = "none";
                    setCookie("loginSuc", "1", new Date(new Date().getMilliseconds() + 60 * 365 * 24 * 60 * 60 * 1000));
                    //调用关注API
                    ajax({
                        type: "GET",
                        url: "http://study.163.com/webDev/attention.htm",
                        asyn: true,
                        data: null,
                        success: function(resp){
                            if(resp === "1"){
                                setCookie("followSuc", "1", new Date(new Date().getMilliseconds() + 60 * 365 * 24 * 60 * 60 * 1000));
                                document.querySelector(".m-header .noFocusOn").style.display = "none";
                                document.querySelector(".m-header .hasFocusOn").style.display = "block";
                            }
                        },
                        error: function(resp){
                            console.log("调用关注接口API（http://study.163.com/webDev/attention.htm）发生错误！" + resp);
                        }
                    });
                }else if(resp === "0"){
                    alert("帐号或密码错误");
                }
            },
            error: function(resp){
                console.log("调用登录接口API（http://study.163.com/webDev/login.htm）发生错误！" + resp);
            }
        });
        console.log("Over.");
    }
}

/**
 * 3.初始化焦点图轮播
 */
var initSlide = function(){
    var mSlide = document.querySelector('.m-slide');
    var list = document.querySelector('.m-slide .list');
    var imgList = list.querySelectorAll('img');
    var buttons = document.querySelectorAll('.m-slide .buttons span');

    var timer;
    var index = 1;  //当前图片下标
    var animated = false;   //是否正在切换图片
    // console.log(navigator.userAgent.toUpperCase());
    // console.log(isIE8Browse);

    /*********** 修改这里的参数以适应不同业务需求 ***********/
    //必改参数
    var imgAmount = 3;  //图片数量
    //可选参数
    var autoInterval = 5000;    //自动播放图片的切换时间
    var time = 500;     //渐变总时间
    var interval = 100;  //每次渐变时间

    /**
     * 图片切换
     * @param  {[type]} originIndex [description]
     * @param  {[type]} targetIndex [description]
     * @return {[type]}             [description]
     */
    function animate (originIndex, targetIndex) {
        if (originIndex == targetIndex) {
            return;
        }

        animated = true;
        var internlOpacity = 1/(time/interval); //每次渐变的透明度范围

        /**
         * 用JS定时器模拟切换动画
         * @return {[type]} [description]
         */
        var go = function (){
            if (getOpacity(imgList[originIndex - 1]) > 0){
                if(imgList[targetIndex - 1].style.opacity === ''){
                    chgOpacity(imgList[targetIndex - 1], 0);
                }
                //继续切换
                chgOpacity(imgList[originIndex - 1], getOpacity(imgList[originIndex - 1]) - internlOpacity);
                chgOpacity(imgList[targetIndex - 1], parseFloat(getOpacity(imgList[targetIndex - 1])) + parseFloat(internlOpacity));
                setTimeout(go, interval);
            }else{
                chgOpacity(imgList[originIndex - 1], 0);
                chgOpacity(imgList[targetIndex - 1], 1);
                animated = false;
            }
        };
        go();
    }

    //切换按钮样式
    function showButton() {
        for (var i = 0; i < buttons.length ; i++) {
            if( buttons[i].className == 'on'){
                buttons[i].className = '';
                break;
            }
        }
        buttons[index - 1].className = 'on';
    }

    //开始轮播图片
    function play() {
        timer = setTimeout(function () {
            if (animated) {
                return;
            }

            var originIndex;
            var targetIndex;
            if (index == imgAmount) {
                originIndex = imgAmount;
                targetIndex = 1;
            }
            else {
                originIndex = index;
                targetIndex = originIndex + 1;
            }

            animate(originIndex, targetIndex);
            index = targetIndex;
            showButton();
            play();
        }, autoInterval);
    }

    //停止轮播图片
    function stop() {
        clearTimeout(timer);
    }

    //绑定圆点按钮
    for (var i = 0; i < buttons.length; i++) {
        buttons[i].onclick = function () {
            if (animated) {
                return;
            }
            if(this.className == 'on') {
                return;
            }
            var targetIndex = parseInt(this.getAttribute('data-index'));

            animate(index, targetIndex);
            index = targetIndex;
            showButton();
        }
    }

    mSlide.onmouseover = stop;
    mSlide.onmouseout = play;

    play();

    /*	//当窗口大小发生改变时，改变轮播图片大小
     var autoChangeSlide = function(){
     var mSlideNode = document.querySelector(".m-slide");  //轮播DIV
     var mSlideImg = mSlideNode.querySelector("img");  //轮播图片
     var screenWidth = document.body.clientWidth;
     // console.log("window.screen.availWidth:" + window.screen.availWidth);
     // console.log("window.screen.availHeight:" + window.screen.availHeight);
     console.log("document.body.clientWidth:" + document.body.clientWidth);
     // console.log("document.body.clientHeight:" + document.body.clientHeight);


     var imgNaturalWidth = getNaturalWidth(mSlideImg);
     var imgNaturalHeight = getNaturalHeight(mSlideImg);
     if(screenWidth > mSlideImg.naturalWidth){
     //大于图片大小，不再放大
     mSlideNode.style.width = imgNaturalWidth + "px";
     mSlideNode.style.height = imgNaturalHeight + "px";
     }else{
     //按比例缩小
     mSlideNode.style.width = "100%";
     mSlideNode.style.height = screenWidth/(imgNaturalWidth/imgNaturalHeight) + "px";
     }
     }
     window.onresize = autoChangeSlide;
     autoChangeSlide();*/
};


/**
 * 4.初始化课程列表
 */
var initCrsList = function(){
    document.querySelector(".m-prd .m-course").onclick = function(event){
        event = event || window.event;
        var courseAreaNode = document.querySelector(".courseArea");
        var menuList = document.querySelector(".m-course .nav").children;
        var target = event.target || event.srcElement;
        if(target.nodeName.toUpperCase() !== "LI"){
            return ;
        }
        var courseType = target.attributes["courseType"].value;
        //获取数据
        ajax({
            type: "GET",
            url: "http://study.163.com/webDev/couresByCategory.htm",
            asyn: true,
            data: {
                pageNo: 1,
                psize: 20,
                type: courseType
            },
            success: function(resp){
                var courseDataObj = JSON.parse(resp);

                var courseList = courseDataObj.list;
                courseAreaNode.innerHTML = "";

                for(var i = 0; i < courseList.length; i++){
                    courseAreaNode.appendChild(createCourseDiv(i, courseList[i]));
                }

                /**
                 * 创建课程节点
                 * @param  {Object} course 课程数据对象
                 * @return {Object} courseNode 课程节点
                 */
                function createCourseDiv(i, course){
                    var courseNode = document.createElement("a");
                    courseNode.className = "course";
                    //存储dataset
                    courseNode.setAttribute("data-id", course.id);
                    courseNode.setAttribute("data-name", course.name);
                    courseNode.setAttribute("data-provider", course.provider);
                    courseNode.setAttribute("data-learnercount", course.learnerCount);
                    courseNode.setAttribute("data-categoryname", course.categoryName);
                    courseNode.setAttribute("data-middlephotourl", course.middlePhotoUrl);
                    courseNode.setAttribute("data-description", course.description);
                    courseNode.setAttribute("data-number",i+1);
                    var imgNode = document.createElement("img");
                    imgNode.className = "courseImg";
                    imgNode.src = course.middlePhotoUrl;
                    imgNode.alt = course.name;

                    var courseInfoNode = document.createElement("div");
                    courseInfoNode.className = "courseInfo";
                    var titleNode = document.createElement("p"); //MARK
                    titleNode.className = "title";
                    titleNode.appendChild(document.createTextNode(course.name));
                    var providerNode = document.createElement("p");
                    providerNode.className = "provider";
                    providerNode.appendChild(document.createTextNode(course.provider));
                    var countNode = document.createElement("p");
                    countNode.className = "count";
                    countNode.appendChild(document.createTextNode(course.learnerCount));
                    var priceNode = document.createElement("p");
                    priceNode.className= "price";
                    priceNode.appendChild(document.createTextNode("￥" + course.price.toFixed(2)));

                    courseInfoNode.appendChild(titleNode);
                    courseInfoNode.appendChild(providerNode);
                    courseInfoNode.appendChild(countNode);
                    courseInfoNode.appendChild(priceNode);

                    courseNode.appendChild(imgNode);
                    courseNode.appendChild(courseInfoNode);

                    courseNode.onmouseenter = courseMsEnterHandler;
                    courseNode.onmouseleave = courseMsLeaveHandler;

                    return courseNode;
                }
            },
            error: function(resp){
                console.log("调用课程接口API（http://study.163.com/webDev/couresByCategory.htm）发生错误！" + resp);
            }
        });
        //改变按钮样式
        for(var i = 0; i < menuList.length; i++){
            if(menuList[i].className === "selected"){
                menuList[i].className = "";
                break;
            }
        }
        target.className = "selected";
    }

    //自动触发事件，获取课程列表
    triggerEvent(document.querySelector(".m-prd .m-course .nav li"),"click");

    //绑定课程详情悬浮层
    var courseMsEnterHandler = function(event){
        if(this.nodeName.toUpperCase() !== "A"){
            return ;
        }
        var divX = 0;
        var divY = 0;
        event = event || window.event;
        var target = event.target || event.srcElement;
        var courseAreaNode = document.getElementById("courseArea");
        divX = this.offsetLeft + this.clientWidth;
        divY = this.offsetTop;
        var parantWidth=this.offsetParent.clientWidth;

        // console.log("location:" + divX + "," + divY);
        var dataset = getDataset(this);
        var data = {
            id: dataset.id,
            name: dataset.name,
            learnercount: dataset.learnercount,
            provider: dataset.provider,
            categoryname: dataset.categoryname,
            description: dataset.description,
            middlephotourl: dataset.middlephotourl
        };
        var crsDetailNode = createCrsDetail(data);
        var flagProcessingwidth=true;
        console.info(parantWidth);
        if(parantWidth >= 982){
            if(dataset.number % 4 == 0 ){
                crsDetailNode.style.right =(parantWidth-this.offsetLeft+20) + "px";
                flagProcessingwidth=false;
            }
            else if(dataset.number % 4 == 3 ){
                crsDetailNode.style.left =(divX-this.clientWidth-crsDetailNode.width) + "px";
                flagProcessingwidth=false;
            }
        }else if(parantWidth<=735){
            if(dataset.number % 3 == 0 ){
                crsDetailNode.style.left =(divX-this.clientWidth-crsDetailNode.width) + "px";
                flagProcessingwidth=false;
            }
        }

        if(flagProcessingwidth){
            crsDetailNode.style.left = (divX + 20) + "px";
        }
        crsDetailNode.style.top = divY + "px";

        courseAreaNode.appendChild(crsDetailNode);
        isShown = true;

        /**
         * 构造课程详情悬浮层
         * @param  {Object} course 课程信息对象
         * @return {[type]}        [description]
         */
        function createCrsDetail(course){
            var crsDetailNode = document.createElement("div");
            crsDetailNode.id = "crsDetail" + course.id;
            crsDetailNode.className = "crsDetail";

            if(course.categoryname == "null" || !course.categoryname){
                course.categoryname = "无";
            }

            var crsInfoNode = document.createElement("div");
            crsInfoNode.className = "crsInfo";
            var imgNode = document.createElement("img");
            imgNode.src = course.middlephotourl;
            imgNode.alt = course.name;
            var cntNode = document.createElement("div");
            cntNode.className = "cnt";
            var h2Node = document.createElement("h2");
            h2Node.appendChild(document.createTextNode(course.name));
            var peopleNode = document.createElement("span");
            peopleNode.className = "people";
            peopleNode.appendChild(document.createTextNode(course.learnercount + "人在学"));
            var providerNode = document.createElement("span");
            providerNode.className = "provider";
            providerNode.appendChild(document.createTextNode("发布者：" + course.provider));
            var categryNode = document.createElement("span");
            categryNode.appendChild(document.createTextNode("分类：" + course.categoryname));
            cntNode.appendChild(h2Node);
            cntNode.appendChild(peopleNode);
            cntNode.appendChild(providerNode);
            cntNode.appendChild(categryNode);
            crsInfoNode.appendChild(imgNode);
            crsInfoNode.appendChild(cntNode);

            var crsDescNode = document.createElement("div");
            crsDescNode.className = "crsDesc";
            crsDescNode.appendChild(document.createTextNode(course.description));

            crsDetailNode.appendChild(crsInfoNode);
            crsDetailNode.appendChild(crsDescNode);
            return crsDetailNode;
        }
    };

    //移出时删除悬浮层
    var timeoutId;
    var courseMsLeaveHandler= function(event){
        var courseAreaNode = document.getElementById("courseArea");
        var targetNodeId = "crsDetail" + getDataset(this).id;
        var targetNode = document.getElementById(targetNodeId);
        courseAreaNode.removeChild(targetNode);
    }
};

/**
 * 5.初始化视频播放
 */
var initVideo = function(){
    //打开视频播放窗口
    document.querySelector(".m-prd-right .info img").onclick = function(){
        document.querySelector(".m-video").style.display = "block";
        var videoNode = document.querySelector(".m-video .videowrap video");
        videoNode.currentTime = 0;
    };

    //绑定关闭视频窗口事件
    document.querySelector(".m-video .videowrap .closeBtn").onclick = function(){
        document.querySelector(".m-video .videowrap video").pause();
        document.querySelector(".m-video").style.display = "none";
    };
}

/**
 * 6.初始化最热排行
 */
var initTopHotCourse = function(){
    var hotCrsList;
    var hotIntervalId;

    var hotCrsNode = document.getElementById("hotCrs");

    /**
     * 创建课程节点
     * @param  {Object} course 课程数据对象
     * @return {Object} courseNode 课程节点
     */
    function createHotCrs(course){
        var courseNode = document.createElement("a");
        courseNode.className = "course";

        var imgNode = document.createElement("img");
        imgNode.src = course.smallPhotoUrl;
        imgNode.alt = course.name;

        var nameNode = document.createElement("p");
        nameNode.appendChild(document.createTextNode(course.name));

        var peopleNode = document.createElement("span");
        peopleNode.appendChild(document.createTextNode(course.learnerCount));

        courseNode.appendChild(imgNode);
        courseNode.appendChild(nameNode);
        courseNode.appendChild(peopleNode);

        return courseNode;
    }
    //请求数据
    ajax({
        type: "GET",
        url: "http://study.163.com/webDev/hotcouresByCategory.htm",
        asyn: true,
        data: null,
        success: function(resp){
            hotCrsList = JSON.parse(resp);

            for(var i = 0; i < hotCrsList.length; i++){
                hotCrsNode.appendChild(createHotCrs(hotCrsList[i]));
            }

        },
        error: function(resp){
            console.log("调用热点课程接口API（http://study.163.com/webDev/hotcouresByCategory.htm）发生错误！" + resp);
        }
    });

    //每5秒自动更换热点课程
    var circleShowHotCrs = function(){
        //每次滚动的高度
        var _eachHeight=70;
        var _top = 0,
            _end = _top - _eachHeight,
            _timer;

        _timer = setInterval(function(){
            _top -= 3;
            hotCrsNode.style.top = _top + 'px';
            if(_top < _end){
                clearInterval(_timer);
                hotCrsNode.style.top = _end + 'px';


                //上一个结点
                var _onNode = hotCrsNode.children[0]

                //重复滚动
                if(_onNode.nodeType == 1){
                    hotCrsNode.removeChild(_onNode);
                    hotCrsNode.appendChild(_onNode);
                    hotCrsNode.style.top = "0px";
                }

            }
        },30);


    };
    //轮播热点课程
    hotIntervalId = setInterval(circleShowHotCrs, 5000);

    //绑定mouseover事件
    hotCrsNode.onmouseover = function(){
        clearInterval(hotIntervalId);
    };

    //绑定mouseout事件
    hotCrsNode.onmouseout = function(){
        hotIntervalId = setInterval(circleShowHotCrs, 5000);
    }
};

window.onload = function(){
    initTip(); //初始化顶部通知条
    initTopNav();  //初始化顶部导航
    initSlide();  //初始化焦点图轮播
    initCrsList();  //初始化课程列表
    initVideo();  //初始化视频播放
    initTopHotCourse();  //初始化最热排行
};
