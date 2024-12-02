import yaml from 'js-yaml';

  function decodeBase64(str2) {
    const binString = atob(str2);
    const bytes = Uint8Array.from(binString, (m) => m.codePointAt(0));
    return new TextDecoder().decode(bytes);
  }
    
  function parseServerInfo(serverInfo) {
    let host, port;
    if (serverInfo.startsWith("[")) {
      const closeBracketIndex = serverInfo.indexOf("]");
      host = serverInfo.slice(1, closeBracketIndex);
      port = serverInfo.slice(closeBracketIndex + 2);
    } else {
      const lastColonIndex = serverInfo.lastIndexOf(":");
      host = serverInfo.slice(0, lastColonIndex);
      port = serverInfo.slice(lastColonIndex + 1);
    }
    return { host, port: parseInt(port) };
  }
  function parseUrlParams(url) {
    const [, rest] = url.split("://");
    const [addressPart, ...remainingParts] = rest.split("?");
    const paramsPart = remainingParts.join("?");
    const [paramsOnly, ...fragmentParts] = paramsPart.split("#");
    const searchParams = new URLSearchParams(paramsOnly);
    const params = Object.fromEntries(searchParams.entries());
    const name = fragmentParts.length > 0 ? decodeURIComponent(fragmentParts.join("#")) : "";
    return { addressPart, params, name };
  }
  function createTlsConfig(params) {
    let tls = { enabled: false };
    if (params.security === "xtls" || params.security === "tls" || params.security === "reality") {
      tls = {
        enabled: true,
        server_name: params.sni,
        insecure: false,
        utls: {
          enabled: true,
          fingerprint: "chrome"
        }
      };
      if (params.security === "reality") {
        tls.reality = {
          enabled: true,
          public_key: params.pbk,
          short_id: params.sid
        };
      }
    }
    return tls;
  }
  function createTransportConfig(params) {
    return {
      type: params.type,
      path: params.path ?? void 0,
      ...params.host && { "headers": { "host": params.host } },
      service_name: params.serviceName ?? void 0
    };
  }
  var ShadowsocksParser = class {
    parse(url) {
      let parts = url.replace("ss://", "").split("#");
      let mainPart = parts[0];
      let tag = parts[1];
      if (tag.includes("%")) {
        tag = decodeURIComponent(tag);
      }
      let [base64, serverPart] = mainPart.split("@");
      let decodedParts = decodeBase64(base64).split(":");
      let method = decodedParts[0];
      let password = decodedParts.slice(1).join(":");
      let match = serverPart.match(/\[([^\]]+)\]:(\d+)/);
      let server, server_port;
      if (match) {
        server = match[1];
        server_port = match[2];
      } else {
        [server, server_port] = serverPart.split(":");
      }
      return {
        "tag": tag,
        "type": "shadowsocks",
        "server": server,
        "server_port": parseInt(server_port),
        "method": method,
        "password": password,
        "network": "tcp",
        "tcp_fast_open": false
      };
    }
  };
  var VmessParser = class {
    parse(url) {
      let base64 = url.replace("vmess://", "");
      let vmessConfig = JSON.parse(decodeBase64(base64));
      let tls = { "enabled": false };
      let transport = {};
      if (vmessConfig.net === "ws") {
        transport = {
          "type": "ws",
          "path": vmessConfig.path,
          "headers": { "Host": vmessConfig.host ? vmessConfig.host : vmessConfig.sni }
        };
        if (vmessConfig.tls !== "") {
          tls = {
            "enabled": true,
            "server_name": vmessConfig.sni,
            "insecure": false
          };
        }
      } else if (vmessConfig.net === "tcp") {
        if (vmessConfig.type === "http") {
          transport = {
            "type": "http",
            "path": vmessConfig.path,
            "headers": { "Host": vmessConfig.host ? vmessConfig.host : vmessConfig.sni }
          };
        } else {
          transport = {
            "type": "tcp",
            "path": vmessConfig.path,
            "headers": { "Host": vmessConfig.host ? vmessConfig.host : vmessConfig.sni }
          };
        }
        if (vmessConfig.tls !== "" && vmessConfig.tls !== "none") {
          tls = {
            "enabled": true,
            "server_name": vmessConfig.sni,
            "insecure": false
          };
        }
      }
      return {
        "tag": vmessConfig.ps,
        "type": "vmess",
        "server": vmessConfig.add,
        "server_port": parseInt(vmessConfig.port),
        "uuid": vmessConfig.id,
        "alter_id": parseInt(vmessConfig.aid),
        "security": vmessConfig.scy || "auto",
        "network": "tcp",
        "tcp_fast_open": false,
        "transport": transport,
        "tls": tls.enabled ? tls : void 0
      };
    }
  };
  var VlessParser = class {
    parse(url) {
      const { addressPart, params, name } = parseUrlParams(url);
      const [uuid, serverInfo] = addressPart.split("@");
      const { host, port } = parseServerInfo(serverInfo);
      const tls = createTlsConfig(params);
      const transport = params.type !== "tcp" ? createTransportConfig(params) : void 0;
      return {
        type: "vless",
        tag: name,
        server: host,
        server_port: port,
        uuid,
        tcp_fast_open: false,
        tls,
        transport,
        network: "tcp",
        flow: params.flow ?? void 0
      };
    }
  };
  var Hysteria2Parser = class {
    parse(url) {
      const { addressPart, params, name } = parseUrlParams(url);
      const [uuid, serverInfo] = addressPart.split("@");
      const { host, port } = parseServerInfo(serverInfo);
      const tls = {
        enabled: true,
        server_name: params.sni,
        insecure: true,
        alpn: ["h3"]
      };
      const obfs = {};
      if (params["obfs-password"]) {
        obfs.type = params.obfs;
        obfs.password = params["obfs-password"];
      }
      ;
      return {
        tag: name,
        type: "hysteria2",
        server: host,
        server_port: port,
        password: uuid,
        tls,
        obfs,
        up_mbps: 100,
        down_mbps: 100
      };
    }
  };
  var TrojanParser = class {
    parse(url) {
      const { addressPart, params, name } = parseUrlParams(url);
      const [password, serverInfo] = addressPart.split("@");
      const { host, port } = parseServerInfo(serverInfo);
      const parsedURL = parseServerInfo(addressPart);
      const tls = createTlsConfig(params);
      const transport = params.type !== "tcp" ? createTransportConfig(params) : void 0;
      return {
        type: "trojan",
        tag: name,
        server: host,
        server_port: port,
        password: password || parsedURL.username,
        network: "tcp",
        tcp_fast_open: false,
        tls,
        transport,
        flow: params.flow ?? void 0
      };
    }
  };
  var TuicParser = class {
    parse(url) {
      const { addressPart, params, name } = parseUrlParams(url);
      const [userinfo, serverInfo] = addressPart.split("@");
      const { host, port } = parseServerInfo(serverInfo);
      const tls = {
        enabled: true,
        server_name: params.sni,
        alpn: [params.alpn],
        insecure: true
      };
      return {
        tag: name,
        type: "tuic",
        server: host,
        server_port: port,
        uuid: userinfo.split(":")[0],
        password: userinfo.split(":")[1],
        congestion_control: params.congestion_control,
        tls,
        flow: params.flow ?? void 0
      };
    }
  };
  var HttpParser = class {
    static async parse(url) {
      try {
        const response = await fetch(url);
        if (!response.ok) {
          throw new Error(`HTTP error! status: ${response.status}`);
        }
        const text = await response.text();
        let decodedText;
        try {
          decodedText = decodeBase64(text.trim());
          if (decodedText.includes("%")) {
            decodedText = decodeURIComponent(decodedText);
          }
        } catch (e) {
          decodedText = text;
          if (decodedText.includes("%")) {
            try {
              decodedText = decodeURIComponent(decodedText);
            } catch (urlError) {
              console.warn("Failed to URL decode the text:", urlError);
            }
          }
        }
        return decodedText.split("\n").filter((line) => line.trim() !== "");
      } catch (error) {
        console.error("Error fetching or parsing HTTP(S) content:", error);
        return null;
      }
    }
  };
  var ProxyParser = class {
    static parse(url) {
      url = url.trim();
      const type2 = url.split("://")[0];
      switch (type2) {
        case "ss":
          return new ShadowsocksParser().parse(url);
        case "vmess":
          return new VmessParser().parse(url);
        case "vless":
          return new VlessParser().parse(url);
        case "hysteria2":
          return new Hysteria2Parser().parse(url);
        case "https":
          return HttpParser.parse(url);
        case "trojan":
          return new TrojanParser().parse(url);
        case "tuic":
          return new TuicParser().parse(url);
      }
    }
  };
  class ClashBuilder {
    // 解析代理字符串并转换为 Clash 配置
    static async parseProxy(proxyString) {
      const parsedProxy = await ProxyParser.parse(proxyString);
      return this.convertToClashProxy(parsedProxy);
    }
  
    // 转换代理配置为 Clash 支持的格式
    static convertToClashProxy(proxy) {
      switch (proxy.type) {
        case "shadowsocks":
          return {
            name: proxy.tag,
            type: "ss",
            server: proxy.server,
            port: proxy.server_port,
            udp: true,
            cipher: proxy.method,
            password: proxy.password
          };
        case "vmess":
          return {
            name: proxy.tag,
            type: proxy.type,
            server: proxy.server,
            port: proxy.server_port,
            udp: true,
            uuid: proxy.uuid,
            alterId: proxy.alter_id,
            cipher: proxy.security,
            tls: proxy.tls?.enabled || false,
            servername: proxy.tls?.server_name || "",
            network: proxy.transport?.type || "tcp",
            "ws-opts": proxy.transport?.type === "ws" ? {
              path: proxy.transport.path,
              headers: proxy.transport.headers
            } : void 0,
            "http-opts": proxy.transport?.type === "http" ? {
              path: [proxy.transport.path],
              method: 'GET',
              headers: {
                Connection: ["keep-alive"],
                Host: [proxy.transport.headers.Host]
              }
            } : void 0
          };
        case "vless":{
          let result = {
            name: proxy.tag,
            type: proxy.type,
            server: proxy.server,
            port: proxy.server_port,
            udp: true,
            uuid: proxy.uuid,
            cipher: proxy.security,
            tls: proxy.tls?.enabled || false,
            "client-fingerprint": proxy.tls.utls?.fingerprint,
            servername: proxy.tls?.server_name || "",
            network: proxy.transport?.type || "tcp",
            "ws-opts": proxy.transport?.type === "ws" ? {
              path: proxy.transport.path,
              headers: proxy.transport.headers
            } : void 0,
            "http-opts": proxy.transport?.type === "http" ? {
              path: [proxy.transport.path],
              headers: ["Connection:"[keep-alive]]
            } : void 0,
            "reality-opts": proxy.tls.reality?.enabled ? {
              "public-key": proxy.tls.reality.public_key,
              "short-id": proxy.tls.reality.short_id
            } : void 0,
            "grpc-opts": proxy.transport?.type === "grpc" ? {
              "grpc-mode": "gun",
              "grpc-service-name": proxy.transport.service_name
            } : void 0,
            tfo: proxy.tcp_fast_open,
            "skip-cert-verify": proxy.tls.insecure,
            "flow": proxy.flow ?? void 0
          };
          return result;
        };
        case "hysteria2":
          return {
            name: proxy.tag,
            type: proxy.type,
            udp: true,
            server: proxy.server,
            port: proxy.server_port,
            obfs: proxy.obfs.type,
            "obfs-password": proxy.obfs.password,
            password: proxy.password,
            auth: proxy.password,
            "skip-cert-verify": proxy.tls.insecure
          };
        case "trojan":
          return {
            name: proxy.tag,
            type: proxy.type,
            server: proxy.server,
            port: proxy.server_port,
            password: proxy.password,
            udp: true,
            cipher: proxy.security,
            tls: proxy.tls?.enabled || false,
            "client-fingerprint": proxy.tls.utls?.fingerprint,
            servername: proxy.tls?.server_name || "",
            network: proxy.transport?.type || "tcp",
            "ws-opts": proxy.transport?.type === "ws" ? {
              path: proxy.transport.path,
              headers: proxy.transport.headers
            } : void 0,
            "reality-opts": proxy.tls.reality?.enabled ? {
              "public-key": proxy.tls.reality.public_key,
              "short-id": proxy.tls.reality.short_id
            } : void 0,
            "grpc-opts": proxy.transport?.type === "grpc" ? {
              "grpc-mode": "gun",
              "grpc-service-name": proxy.transport.service_name
            } : void 0,
            tfo: proxy.tcp_fast_open,
            "skip-cert-verify": proxy.tls.insecure,
            "flow": proxy.flow ?? void 0
          };
        case "tuic":
          return {
            name: proxy.tag,
            type: proxy.type,
            server: proxy.server,
            port: proxy.server_port,
            uuid: proxy.uuid,
            password: proxy.password,
            "congestion-controller": proxy.congestion,
            "skip-cert-verify": proxy.tls.insecure,
            "disable-sni": true,
            "alpn": proxy.tls.alpn,
            "sni": proxy.tls.server_name,
            "udp-relay-mode": "native"
          };
        default:
          return proxy;
      }
    }
  
  
    // 使用 ProxyParser 解析并转换代理配置
    static async buildClashLinks(proxyUrls) {
      const proxies = await Promise.all(proxyUrls.map(url => this.parseProxy(url).catch(() => null))); // 捕获单个失败，不影响其他代理
      return {
        proxies: proxies.filter(proxy => proxy) // 过滤掉解析失败的代理
      };
    }
    static async addProxyGroups(proxyGroups, proxyNames, rules, toppin) {
      proxyNames.unshift(...toppin);
      // 添加动态规则组
      Object.keys(rules).forEach(ruleKey => {
        const rule = rules[ruleKey];
        if (rule.outbound === "DIRECT") {
          return;
        }
        let filteredProxyNames = proxyNames;
        if (rule.selectproxykeyword && rule.selectproxykeyword.length > 0) {
          filteredProxyNames = proxyNames.filter(proxyName => {
            if (rule.isWhitelist === "true") {
              return rule.selectproxykeyword.some(keyword => proxyName.includes(keyword));
            } else {
              return !rule.selectproxykeyword.some(keyword => proxyName.includes(keyword));
            }
          });
        }
      
        // 将筛选后的代理名称添加到 proxyGroups 中
        if (filteredProxyNames.length > 0) {
          proxyGroups.push({
            type: rule.type,
            name: rule.outbound,  // 使用 rules[name]
            url: rule.url,
            interval: rule.interval,
            lazy: rule.lazy,
            strategy: rule.strategy,
            proxies: [...filteredProxyNames]
          });
        }
      });

    }
    static async addRules(rules, UNIFIED_RULES) {
      const ipRules = [];  // 用于存储所有 IP 规则
      const ipCidrRules = [];  // 用于存储所有 IP-CIDR 规则
    
      // 遍历并生成规则
      const generatedRules = UNIFIED_RULES.flatMap((rule) => {
        if(!rule.outbound) return null;
        // 处理 domain_suffix 规则
        const domainSuffixRules = rule.domain_suffix ? rule.domain_suffix.map((suffix) => `DOMAIN-SUFFIX,${suffix},${rule.outbound}`) : [];
        
        // 处理 domain_keyword 规则
        const domainKeywordRules = rule.domain_keyword ? rule.domain_keyword.map((keyword) => `DOMAIN-KEYWORD,${keyword},${rule.outbound}`) : [];
        
        // 处理 site_rules 规则
        const siteRules = rule.site_rules ? rule.site_rules.map((site) => `GEOSITE,${site},${rule.outbound}`) : [];
        
        // 提取 IP 规则
        if (rule.ip_rules) {
          ipRules.push(...rule.ip_rules.map((ip) => `GEOIP,${ip},${rule.outbound},no-resolve`));
        }
        
        // 提取 IP-CIDR 规则
        if (rule.ip_cidr) {
          ipCidrRules.push(...rule.ip_cidr.map((cidr) => `IP-CIDR,${cidr},${rule.outbound},no-resolve`));
        }
        
        // 返回当前规则的所有类型
        return [...domainSuffixRules, ...domainKeywordRules, ...siteRules];
      });
    
      // 合并所有规则到 rules 中
      rules.push(...generatedRules, ...ipCidrRules, ...ipRules, "MATCH,🐟 漏网之鱼");
    }
  }
  
/*
代码功能概述：

本代码实现了一个用于处理用户请求的 Cloudflare Worker 服务，支持用户数据加密存储、获取和管理。具体功能包括：

- 监听 `fetch` 事件，根据路径分发请求（handleRequest）。
- 处理 POST 请求，通常用于保存用户数据，数据会加密后保存到 KV 存储中（ifPost）。
- 处理 GET 请求，根据不同路径提供用户数据、管理界面或生成的订阅链接（ifGet）。
- 生成并返回 HTML 表单页面，用于用户输入或显示已保存数据（webPage）。
- 支持管理路径（/manage），进入管理页面查看和编辑用户数据（ifManage）。
- 根据路径（如 `/x`、`/c`、`/s`）展示加密存储的订阅配置数据或随机生成的订阅链接（returnLinksConfig）。
- 基于 `userId` 生成 UUID 和指定范围内的随机数，用于用户数据的唯一标识（get_UUID_Num）。
- 使用 AES-GCM 算法对用户数据进行加解密（enCD 和 deCD）。
- 在 KV 存储中查找加密的 `userId`（findUserId），比对用户输入用户id。
- 组合用户输入内容生成并编码的请求文本，发送至指定 URL 获取内容（fetchConfig）。

代码结构总结：

1. 事件监听器：监听 HTTP 请求并调用 `handleRequest` 进行处理。
2. 主处理函数 `handleRequest`：根据请求路径和方法（GET/POST）分发请求。
3. 请求处理函数：
   - `ifPost`：处理 POST 请求，加密用户数据并存储。
   - `ifGet`：处理 GET 请求，根据路径展示数据、生成订阅链接或进入管理界面。
4. 辅助函数：
   - `ifManage`：处理管理路径页面。
   - `returnLinksConfig`：根据路径提供订阅配置或链接。
   - `get_UUID_Num`：基于 `userId` 生成 UUID 和随机数。
   - `toHex`：将字节转换为十六进制格式。
   - `getResponse`：生成 HTTP 响应对象。
   - `webPage`：生成 HTML 表单。
   - `findUserId`：在 KV 中查找加密的 `userId`。
   - `fetchConfig`：组合生成请求文本并发送请求。
   - `enCD` 和 `deCD`：使用 AES-GCM 对数据进行加密和解密。
*/

addEventListener('fetch', event => event.respondWith(handleRequest(event.request)));

//必填
const selfURL = 'https://selfmix.lxmoon.eu.org';

//基本参数
const fakedomain = "www.cloudflare.com";
const fakeurl = "https://v1.mk/nFfUzUA";
const fakeSubLink = "https://url.v1.mk/";
const fakeSubConfig =  "&insert=false&config=https%3A%2F%2Fraw.githubusercontent.com%2FACL4SSR%2FACL4SSR%2Fmaster%2FClash%2Fconfig%2FACL4SSR_Online_Full_NoAuto.ini&emoji=true&list=false&xudp=false&udp=false&tfo=false&expand=true&scv=false&fdn=false&new_name=true";

const responsePaths = {
  "x": (sublink) => `${sublink}/xray?config=`,
  "c": (sublink) => `${sublink}/clash?config=`,
  "s": (sublink) => `${sublink}/singbox?config=`
};

//定义uuid获取方式
const extractors = {
  'trojan': link => link.match(/:\/\/(.*?)@/)[1], // 提取 trojan 协议的 UUID
  'hysteria2': link => link.match(/:\/\/(.*?)@/)[1], // 提取 hysteria2 协议的 UUID
  'vless': link => link.match(/:\/\/(.*?)@/)[1], // 提取 vless 协议的 UUID
  'vmess': link => JSON.parse(atob(link.slice(8))).id // 提取 vmess 协议的 UUID
};

const keyValuePairs = new Map(); // 使用 Map 存储 UUID 映射

// 提前创建编码器和解码器，避免重复创建实例
const encoder = new TextEncoder();
const decoder = new TextDecoder();

// 使用一个 Map 作为缓存，存储生成的密钥
const keyCache = new Map();

// 创建一个响应对象的辅助函数，便于设置内容、类型和状态码
const getResponse = (content, type = 'text/plain', status = 200) =>
  new Response(content, { headers: { 'Content-Type': `${type}; charset=utf-8` }, status });

//响应请求
async function handleRequest(request) {
  const url = new URL(request.url);
  const path = url.pathname.split('/').filter(Boolean);
  const userId = path[0];

  let { uuid } = await get_UUID_Num(userId, 1, 50);
  let olduserid = await findUserId(userId, uuid);

  const params = { userId, uuid, olduserid};

  if (request.method === 'POST') {
      const formData = Object.fromEntries(await request.formData());
      return await ifPost(formData, params);
  }
  else{
      return await ifGet(path, params);
  }
}

//提交信息
async function ifPost(formData, { userId, uuid, olduserid }) {
  const { input1 = '', input2 = '', inputSublink = '', inputSubconfig = '', Input3 = '', Input4 = '' } = formData;
  const userkey = await addUserIdData(input1, input2, olduserid, inputSublink, inputSubconfig, userId, uuid, Input3, Input4);

  const useridData = await mixkv.get(userkey);
  const [encheckinput1, encheckinput2, checkinputSublink, checkinputSubconfig, checkInput3, checkInput4] = useridData.split('@split@');
  const [checkput1, checkput2] = await Promise.all([deCD(encheckinput1, uuid), deCD(encheckinput2, uuid)]);

  return getResponse(`<script>alert('数据已成功保存!');</script>` + webPage(userId, checkput1, checkput2, checkinputSublink, checkinputSubconfig, checkInput3, checkInput4), 'text/html');
}


//请求页
async function ifGet(path, { userId, uuid, olduserid }) {
  //首页
  if (path.length === 0) return getResponse(webPage(), 'text/html');

  if (path[0] === "/favicon.ico") {
      return Response.redirect("https://cravatar.cn/avatar/9240d78bbea4cf05fb04f2b86f22b18d?s=160&d=retro&r=g", 301);
  }

  if (path[1] === 'delete') {
      await updateUserId (olduserid, 0);
      return getResponse('用户已删除！');
  }
  
  let useridData = olduserid ? await mixkv.get(olduserid) : '';
  if (path[1] === 'manage') {
      return ifManage(userId, uuid, useridData);
  }

  //获取转换后的节点配置
  return returnLinksConfig(path, useridData, uuid,userId);
}

//管理页
async function ifManage(userId, uuid, useridData) {
  if (!useridData) {
      const fakemessage = await fakeMessage(userId);
      return getResponse(webPage(userId, fakemessage, fakeurl, fakeSubLink, fakeSubConfig), 'text/html');
  }

  const [input1, input2, inputSublink, inputSubconfig, Input3, Input4] = useridData.split('@split@');
  
  // 解密 input1 和 input2
  const [decryptedInput1, decryptedInput2] = await Promise.all([deCD(input1, uuid), deCD(input2, uuid)]);
  
  // 返回渲染的管理页面，包含新增的输入框 Input3 和 Input4
  return getResponse(webPage(userId, decryptedInput1, decryptedInput2, inputSublink, inputSubconfig, Input3, Input4), 'text/html');
}

// 返回用户节点配置
async function returnLinksConfig(path, useridData, uuid, userId) {
  let eninput1, eninput2, sublink, subconfig, input1, input2, Input3, Input4;

  if (!useridData) {
      sublink = fakeSubLink;
      subconfig = fakeSubConfig;
      input2 = fakeurl;
      input1 = await fakeMessage(userId);
      Input3 = '';
      Input4 = '';
  } else {
      [eninput1, eninput2, sublink, subconfig, Input3, Input4] = useridData.split('@split@');
      [input1, input2] = await Promise.all([
          deCD(eninput1, uuid),
          deCD(eninput2, uuid)
      ]);
  }

  let responsePath = responsePaths[path[1]] ? responsePaths[path[1]](sublink) : null;

  if (sublink && !subconfig) {
      [responsePath, subconfig] = sublink.split('mylinks');
  }

  if (responsePath) {
      
      if (path[1] === "x") {
          const combinedResult = await getUrls(input2);
          const links = `${input1}\n${combinedResult}`;
          return getResponse(btoa(`${links}`));
      } else if (path[2] === "s") {
          // 将 Input3 和 Input4 赋值给 clashYaml 和 clashRules
          const clashYaml = Input3;
          const clashRules = Input4;
          if (clashYaml === '' || clashRules === ''){
            return getResponse("请输入远程配置和规则");
          }
          const ClashConfig = await editClashConfig(clashYaml, input2, clashRules,input1)
          if (path[3] === "ip"){
            return getResponse(`${await processYaml(ClashConfig)}`)
          }
          return getResponse(ClashConfig);
      } else if (path[1] === "c"){
          const enresponse = await fetchConfig(responsePath, input1, input2, subconfig); // 加密uuid并请求配置
          if (path[3] === "ip"){
            const re_enresponse = await restoreUUID(enresponse)
            return getResponse(`${await processYaml(re_enresponse)}`)
          }
          return getResponse(`${await restoreUUID(enresponse)}`); // 将获取的配置中的uuid全部还原并返回请求
      } else{
        const enresponse = await fetchConfig(responsePath, input1, input2, subconfig); // 加密uuid并请求配置
        return getResponse(`${await restoreUUID(enresponse)}`); // 将获取的配置中的uuid全部还原并返回请求
      }
  }

  return getResponse(`${input1}\n${input2}`);
}
async function fetchText(url) {
  const response = await fetch(url);
  if (!response.ok) throw new Error(`Failed to fetch from ${url}`);
  return response.text();
}
// 处理请求并返回合并后的 YAML 配置
async function editClashConfig(clashYaml, input2, clashRules,input1) {
try {
  
  const [yamlJson, proxyJson, UNIFIED_RULES] = await Promise.all([
    fetchText(clashYaml).then(yamlText => js_yaml_default.load(yamlText)),       
    getUrls(input2).then(proxyString => {
      const combinedInput = btoa(`${input1}\n${proxyString}`);
      return ClashBuilder.buildClashLinks(
        decodeBase64(combinedInput).split(/\r?\n/).filter(line => line.trim() !== '')
      );
    }),
    fetchText(clashRules).then(response => JSON.parse(response))
  ]);
  
  Object.assign(yamlJson, { "proxies": [], "proxy-groups": [], "rules": [] });

  let keywords = [
    
  ]; //筛选代理
  keywords.push(...UNIFIED_RULES.selectdefaultproxy);
  const isWhitelist = UNIFIED_RULES.selectdefaultproxymode; // 设置代理筛选模式
  //提取并筛选 proxyNames 中包含任意关键词的代理名
  const filteredProxyNames = proxyJson.proxies.map(proxy => proxy.name).filter(name => {const matchesKeyword = keywords.some(keyword => name.includes(keyword));return isWhitelist ? matchesKeyword : !matchesKeyword;});
  //筛选 proxyJson.proxies 中的代理项，确保它的 name 在 filteredProxyNames 中
  const filteredProxies = proxyJson.proxies.filter(proxy => filteredProxyNames.includes(proxy.name));

  //提取域名解析为ip (可选 )
  const proxyServers = proxyJson.proxies.map(proxy => proxy.server);

  yamlJson.proxies.push(...filteredProxies);

  // 获取 selectkeyword 中的所有元素
  const selectKeywords = UNIFIED_RULES.selectkeyword;
  // 筛选出 group 中 `outbound` 为 selectKeyword 中内容的条目
  const filteredGroup = UNIFIED_RULES.group.filter(item => selectKeywords.includes(item.outbound));
  const proxyMap = {

  };//筛选每个代理组的代理
  const WhitelistMap = {

  }; // 设置每个代理组代理筛选模式
  const updatedGroup = filteredGroup.map(item => {
    if (proxyMap[item.outbound]) item.selectproxykeyword = proxyMap[item.outbound];
    if (WhitelistMap[item.outbound]) item.isWhitelist = WhitelistMap[item.outbound];               
    return item;
  });

  await Promise.all([
    ClashBuilder.addProxyGroups(yamlJson["proxy-groups"], filteredProxyNames, updatedGroup, UNIFIED_RULES.toppin),
    ClashBuilder.addRules(yamlJson["rules"], updatedGroup)
  ]);
  return js_yaml_default.dump(yamlJson);
} catch (error) {
  console.error(error);
  return error.message;
}
}
//添加用户数据
async function addUserIdData(input1, input2, olduserid, inputSublink, inputSubconfig, userId , uuid,Input3, Input4){
  const [eninput1, eninput2, newuserid] = await Promise.all([
      enCD(input1, uuid),
      enCD(input2, uuid),
      enCD(userId, uuid)
  ]);
  const userkey = olduserid || newuserid;
  // 如果是新用户（没有 olduserid），将 newuserid 追加到 manageuserid 键下
  if (!olduserid) {
      await updateUserId (newuserid, 1);
  }
  await mixkv.put(userkey, `${eninput1}@split@${eninput2}@split@${inputSublink}@split@${inputSubconfig}@split@${Input3}@split@${Input4}`);
  return userkey;

}

//更新kv
async function updateUserId(userid, isADD) {
  // 从 KV 存储中获取 manageuserid 的值并分割成数组
  const existinguserid = (await mixkv.get('manageuserid')) || '';
  let userIdList = existinguserid ? existinguserid.split('@split@') : [];

  if (isADD) {
      // 添加操作：如果数组中没有该用户ID，则添加
      if (!userIdList.includes(userid)) {
          userIdList.push(userid);
      }
  } else {
      if (!userIdList.includes(userid)) {
          await mixkv.put('fakeuseridconfig',await enCD(userid));
          return getResponse('用户已删除！');
      }
      // 删除操作：从数组中移除该用户ID
      userIdList = userIdList.filter(storedUserId => storedUserId !== userid);

      // 删除单独存储的用户的数据 
      await mixkv.delete(userid);


  }
  // 将更新后的用户ID数组重新组合成字符串
  const updateduserid = userIdList.join('@split@');

  // 将新的用户ID列表保存回 mixkv 中
  if (updateduserid) {
      await mixkv.put('manageuserid', updateduserid);
  } else {
      await mixkv.delete('manageuserid'); // 如果列表为空，删除键
  }

  if(!isADD){
      await mixkv.put('fakeuseridconfig',await enCD(userid));
      return getResponse('用户已删除！');
  }

  
}

// 查询userid
async function findUserId(targetUserId, uuid) {
  if (!targetUserId) return "";

  try {
      // 直接获取 manageuserid 键下的所有加密用户名
      const encryptedNames = await mixkv.get('manageuserid');
      if (!encryptedNames) return "";

      // 分割加密的用户名
      const encryptedList = encryptedNames.split('@split@');

      // 使用 Map 存储解密结果，以便快速查找
      const userMap = new Map();
      
      // 分批解密，控制并发数量
      const batchSize = 10; // 每批解密数量，可以根据需要调整
      for (let i = 0; i < encryptedList.length; i += batchSize) {
          const batch = encryptedList.slice(i, i + batchSize);

          const decryptedResults = await Promise.all(
              batch.map(async (encryptedName) => {
                  try {
                      return await deCD(encryptedName, uuid);
                  } catch (error) {
                      return null; // 忽略解密失败
                  }
              })
          );

          // 将解密结果存入 Map 中
          decryptedResults.forEach((decryptedName, index) => {
              if (decryptedName !== null) {
                  userMap.set(decryptedName, batch[index]);
              }
          });

          // 提前检查目标用户 ID 是否匹配
          if (userMap.has(targetUserId)) {
              return userMap.get(targetUserId); // 返回匹配的原始加密用户名
          }
      }
  } catch (error) {
      return "";
  }
  return "";
}


//获取后端配置
async function fetchConfig(baseURL, text1, text2, subconfig) {

  const combinedResult = await getUrls(text2);
  const combinedText = `${text1}\n${combinedResult}`;
  const{uuid} = await get_UUID_Num('temp',1,50);
  let olduserid = await findUserId('temp', uuid);
  
  keyValuePairs.clear();
  const result = await ChangeUUIDs(combinedText);
  await addUserIdData(result, '', olduserid, '', '', 'temp', uuid);

  // 对拼接后的文本进行 URL 编码
  const encodedURL = encodeURIComponent(`${selfURL}/temp/x`);
  // 构建完整的 URL
  const fullUrl = `${baseURL}${encodedURL}${subconfig}`;
  // 发起请求并获取返回内容
  const response = await fetch(fullUrl);

  const xraytext = await response.text();
  return xraytext; // 返回请求到的内容
}

//解析所有url
async function getUrls(text) {
  // 使用空数组初始化，移除不必要的 trim 调用
  const urls = text ? text.split('\n').map(url => url.trim()).filter(Boolean) : []; 
  let combinedResult = "";

  async function getUrl(url) {
      try {
          const response = await fetch(url);
          if (!response.ok) {
              throw new Error(`HTTP error! status: ${response.status}`);
          }
    
          // 获取并解码文本，减少不必要的字符串操作
          const text = await response.text();
          const decodedText = atob(text.trim());
  
          // 使用正则表达式检查是否需要 URI 解码
          const inputData = decodedText.includes("%") ? decodeURIComponent(decodedText) : decodedText;
          // 直接在同一步去掉空行，减少多次字符串处理
          return inputData.split("\n").map(line => line.trim()).filter(Boolean).join("\n");
  
      } catch (error) {
          return null;
      }
  }

  try {
      // 使用 Promise.all 处理 URL 列表
      const results = await Promise.all(urls.map(getUrl));
      combinedResult = results.filter(Boolean).join('\n'); // 过滤掉空结果并合并
  } catch (error) {
      console.error("Error fetching URLs:", error);
  }
  return combinedResult;
}

//生成固定 UUID 和随机数
async function get_UUID_Num(userId, min = 0, max = 100) {
  const data = encoder.encode(userId);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  // 转换为十六进制字符串
  function toHex(byte) {
      return byte.toString(16).padStart(2, '0');
  }
  // 构造 UUID 字符串
  const uuid = `${toHex(hashArray[0])}${toHex(hashArray[1])}${toHex(hashArray[2])}${toHex(hashArray[3])}` +
               `-${toHex(hashArray[4])}${toHex(hashArray[5])}` +
               `-${toHex(hashArray[6])}${toHex(hashArray[7])}` +
               `-${toHex(hashArray[8])}${toHex(hashArray[9])}` +
               `-${hashArray.slice(10, 16).map(toHex).join('')}`;

  // 生成范围 [min, max] 的随机数
  const hashInt = hashArray.reduce((acc, byte) => acc * 256 + byte, 0);
  const randomNum = min + (hashInt % (max - min + 1));

  return { uuid, randomNum };
}

//替换成假的UUID
async function ChangeUUIDs(inputData) {
  const links = inputData.split('\n');
  const newlinks = new Set();

  // 提取 UUID 和链接，并去重
  await Promise.all(links.map(async (link) => {
      const result = await extractUUID(link);
      if (result) {
          newlinks.add(result);
      }
  }));

  return Array.from(newlinks).join('\n');
}

function restoreVmessLinks(link) {
  const newlinkStr = JSON.stringify(link);
  const encoded = new TextEncoder().encode(newlinkStr);
  const base64Encoded = btoa(String.fromCharCode(...encoded));
  return (`vmess://${base64Encoded}`);
}

async function extractUUID(link) {

  for (const [protocol, extractor] of Object.entries(extractors)) {
      if (link.startsWith(`${protocol}://`)) { // 检查协议前缀
          const uuid = extractor(link); // 调用相应的提取函数
          if (protocol === 'vmess') {
              if (!keyValuePairs.has(uuid)) {
                  const { uuid: newUUID } = await get_UUID_Num(uuid);
                  keyValuePairs.set(uuid, newUUID);
              }
              const decoded = atob(link.slice(8)); // 解码 vmess 协议
              const jsonString = new TextDecoder('utf-8').decode(Uint8Array.from(decoded, c => c.charCodeAt(0)));
              const newlink = JSON.parse(jsonString);
              newlink.id = keyValuePairs.get(newlink.id) || newlink.id;
              const restorelink = restoreVmessLinks(newlink);
              return restorelink; // 返回
          }
          if (!keyValuePairs.has(uuid)) {
              const { uuid: newUUID } = await get_UUID_Num(uuid);
              keyValuePairs.set(uuid, newUUID);
          }
          const modifiedLink = link.replace(uuid, keyValuePairs.get(uuid) || uuid);
          return modifiedLink; // 对其他协议返回链接和 UUID
      }
  }

  return null; // 如果没有匹配到协议
}

//还原 UUID
async function restoreUUID(enLinks) {
  const reversedKeyValuePairs = new Map(Array.from(keyValuePairs, ([oldUUID, newUUID]) => [newUUID, oldUUID]));
  // 构建反向替换的正则表达式
  const keys = Array.from(reversedKeyValuePairs.keys());
  const pattern = new RegExp(keys.join('|'), 'g'); // 构建反向替换的正则表达式
  const restoredText = enLinks.replace(pattern, match => reversedKeyValuePairs.get(match)); // 还原 UUID
  return restoredText; // 返回还原后的文本
}

//创建假的订阅信息
async function fakeMessage(userId){
  const isTrue = await mixkv.get('fakeuseridconfig');
  if (!isTrue){
      await mixkv.put('fakeuseridconfig',await enCD(userId));
  }
  const fakeuserid = `${userId}${await mixkv.get('fakeuseridconfig')}`;
  let { randomNum }= await get_UUID_Num (fakeuserid,1,50);
  const randomSubscriptions = await Promise.all(Array.from({ length: randomNum }, async (_, i) => {
      const userid = `${fakeuserid}${i + 1}`; // 生成 userid1 到 userid{randomNum}
      const { uuid }= await get_UUID_Num (userid);
      return `vless://${uuid}@${fakedomain}:443?encryption=none&security=tls&sni=${fakedomain}&fp=randomized&type=ws&host=${fakedomain}&path=%2F%3Fed%3D2048#${userId}${i + 1}`;
  }));
  return randomSubscriptions.join('\n');
}

//获取或创建密钥
async function getOrCreateKey(uuid) {
  // 密钥派生函数，使用 PBKDF2
  async function deriveKey(uuid) {
      const salt = new TextEncoder().encode("some_salt_string");  // 可以自定义 salt，增加随机性
      const password = encoder.encode(uuid);  // 使用 UUID 作为密码
  
      const keyMaterial = await crypto.subtle.importKey(
          'raw', password, { name: 'PBKDF2' }, false, ['deriveKey']
      );
  
      const key = await crypto.subtle.deriveKey(
          { name: 'PBKDF2', salt: salt, iterations: 100000, hash: 'SHA-256' },
          keyMaterial,
          { name: 'AES-GCM', length: 256 },
          false, ['encrypt', 'decrypt']
      );
  
      return key;
  }
  
  
  if (keyCache.has(uuid)) return keyCache.get(uuid);

  // 通过 PBKDF2 派生密钥并缓存
  const key = await deriveKey(uuid);
  keyCache.set(uuid, key);  // 缓存密钥
  return key;
}

//加密函数
async function enCD(plaintext, uuid) {
  const iv = crypto.getRandomValues(new Uint8Array(12)); // 生成 12 字节 IV
  const key = await getOrCreateKey(uuid);

  const encryptedContent = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: iv },
      key,
      encoder.encode(plaintext)
  );

  const ivHex = Array.from(iv).map(b => b.toString(16).padStart(2, '0')).join('');
  const encryptedText = btoa(String.fromCharCode(...new Uint8Array(encryptedContent)));

  return `${ivHex}:${encryptedText}`;
}

//解密函数
async function deCD(encryptedText, uuid) {
  const [ivHex, encryptedContent] = encryptedText.split(':');
  const iv = new Uint8Array(ivHex.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));
  const key = await getOrCreateKey(uuid);

  const encryptedBuffer = Uint8Array.from(atob(encryptedContent), c => c.charCodeAt(0));
  const decryptedContent = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: iv },
      key,
      encryptedBuffer
  );

  return decoder.decode(decryptedContent);
}

//渲染表单的函数，接受用户ID和输入框的内容
const webPage = (userId = '', input1 = '', input2 = '', inputSublink = '', inputSubconfig = '', Input3 = '', Input4 = '') => `
<html>
  <head>
      <meta charset="UTF-8">
      <style>
          * { 
              box-sizing: border-box; 
          }
          body { 
              display: flex; 
              justify-content: center; 
              align-items: center; 
              min-height: 100vh; 
              background-color: #f0f4f8; 
              font-family: 'Helvetica Neue', Arial, sans-serif; 
              margin: 0; 
              overflow-y: auto; /* 页面出现滚动条 */
          }
          
          .container { 
              text-align: center; 
              background: #ffffff; 
              padding: 40px 30px; 
              border-radius: 12px; 
              box-shadow: 0 4px 20px rgba(0, 0, 0, 0.1); 
              width: 90%; 
              max-width: 600px; 
              margin: auto 0; /* 上下居中 */
              box-sizing: border-box;
          }
          
          h1 { 
              color: #333; 
              font-size: 24px; 
              margin-bottom: 20px; 
          }
          label { 
              display: block; 
              font-weight: bold; 
              color: #555; 
              margin-top: 15px; 
          }
          input[type="text"], 
          textarea { 
              width: 100%; 
              padding: 12px; 
              margin-top: 8px; 
              margin-bottom: 20px; 
              border: 1px solid #ccc; 
              border-radius: 6px; 
              font-size: 16px; 
              transition: border-color 0.3s ease-in-out; 
          }
          input[type="text"]:focus, 
          textarea:focus { 
              border-color: #66afe9; 
              outline: none; 
          }
          textarea { 
              min-height: 120px; 
              resize: none; 
              overflow-y: hidden; 
              overflow-x: auto; 
              white-space: nowrap; 
          }
          input[type="submit"], 
          button { 
              background-color: #007BFF; 
              color: white; 
              padding: 12px 25px; 
              border: none; 
              border-radius: 6px; 
              font-size: 16px; 
              font-weight: bold; 
              cursor: pointer; 
              transition: background-color 0.3s ease; 
          }
          input[type="submit"]:hover { 
              background-color: #0056b3; 
          }
          button { 
              background-color: #dc3545; 
          }
          button:hover { 
              background-color: #c82333; 
          }
      </style>
      <script>
          document.addEventListener("DOMContentLoaded", () => {
              const userIdInput = document.getElementById('userId');
              const form = document.getElementById('form');
              userIdInput.addEventListener('input', () => {
                  if (userIdInput.value) {
                      form.action = '/' + userIdInput.value + '/manage';
                  }
              });

              const textareas = [document.getElementById('input1'), document.getElementById('input2')];
              textareas.forEach(textarea => {
                  textarea.addEventListener('input', () => {
                      textarea.style.height = 'auto'; 
                      textarea.style.height = textarea.scrollHeight + 'px'; 
                  });
                  textarea.style.height = textarea.scrollHeight + 'px';
              });
          });

          async function deleteUser(userId) {
              if (confirm('确定要删除该用户吗？')) {
                  try {
                      const response = await fetch('/' + userId + '/delete', { method: 'DELETE' });
                      const data = await response.text();
                      alert(data);
                      window.location.href = '/';
                  } catch (error) {
                      console.error('Error deleting user:', error);
                  }
              }
          }
      </script>
  </head>
  <body>
  <div class="container">
      <h1>订阅转换</h1>
      <form method="POST" id="form">
          <label for="userId">User ID:</label>
          <input type="text" id="userId" name="user_id" value="${userId}" placeholder="输入您的 User ID" required>
          
          <label for="input1">节点:</label>
          <textarea id="input1" name="input1" placeholder="在此输入节点信息">${input1}</textarea>
          
          <label for="input2">订阅:</label>
          <textarea id="input2" name="input2" placeholder="在此输入订阅内容">${input2}</textarea>

          <label for="Input3">Config:</label>
          <input type="text" id="Input3" name="Input3" value="${Input3}" placeholder="在此输入远程配置">

          <label for="Input4">Rules:</label>
          <input type="text" id="Input4" name="Input4" value="${Input4}" placeholder="在此输入远程规则">
          
          <label for="inputSublink">Sublink:</label>
          <input type="text" id="inputSublink" name="inputSublink" value="${inputSublink}" placeholder="输入Sublink URL">
          
          <label for="inputSubconfig">Subconfig:</label>
          <textarea id="inputSubconfig" name="inputSubconfig" placeholder="在此输入Subconfig配置">${inputSubconfig}</textarea>
          
          <input type="submit" value="提交">
          <button type="button" onclick="deleteUser('${userId}')">删除</button>
      </form>
  </div>
</body>
</html>
`;

// IPv6 地址的正则表达式
const ipv6Regex = /^([0-9a-fA-F]{1,4}:){7}([0-9a-fA-F]{1,4})$|^([0-9a-fA-F]{1,4}:){1,7}:$|^([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}$|^([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}$|^([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}$|^([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}$|^([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}$|^[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})$|^:((:[0-9a-fA-F]{1,4}){1,7}|:)$|^([0-9a-fA-F]{1,4}:){1,7}:$/;
// IPv4 地址的正则表达式
const ipv4Regex = /^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
// 处理 YAML 配置文件的主逻辑
async function processYaml(yamlText) {
  const domainPattern = /(?<=^|\s)server:\s*(\S+)/g;
  let domainsToResolve;
  domainsToResolve = new Set(
    [...yamlText.matchAll(domainPattern)]  // 匹配所有 server 域名
      .map(match => match[1])              // 提取出域名部分
      .filter(domain => !(ipv4Regex.test(domain) || ipv6Regex.test(domain))) // 过滤掉 IPv4 和 IPv6 地址
  );
  console.info(domainsToResolve)

  // 使用 Promise.all() 并行获取所有 IP 地址
  const domainToIpMap = {};// 创建一个对象，存储域名与解析到的 IP 地址的映射
  await Promise.all(
    [...domainsToResolve].map(async (domain) => {
      try {
        // 调用 getIP 函数解析域名到 IP 地址
        let ip = await getIP(domain);
        // 如果 IP 地址不为空，记录该映射
        if (ip !== null) {
          domainToIpMap[domain] = ip;
        }
      } catch (error) {
        // 如果无法解析域名，输出错误信息
        console.error(`无法解析域名 ${domain}: ${error.message}`);
      }
    })
  );


  // 替换 YAML 配置中的 server 域名为对应的 IP 地址
  const modifiedYaml = yamlText.replace(domainPattern, (match, domain) => {
    // 直接用映射中的 IP 替换域名
    return `server: ${domainToIpMap[domain] || domain}`;  // 如果映射中没有该域名，保持原样
  });

  // 返回修改后的 YAML 配置内容
  return modifiedYaml;
}

// 解析域名并返回对应的 IP 地址
async function getIP(domain) {
  // 查询DNS记录的辅助函数，支持查询 A、AAAA、CNAME 等类型
  async function resolveDNS(domain, type) {
    // 使用 Google DNS 进行查询
    const url = `https://dns.google/resolve?name=${domain}&type=${type}`;
    const response = await fetch(url);
    const data = await response.json();
    // 返回解析结果，如果没有记录，返回空数组
    return data.Answer || [];
  }

  function findIP(records,type){
    const regex = type === 'A' ? ipv4Regex : ipv6Regex ;
    for (let i = 0; i < records.length; i++) {
      if (regex.test(records[i].data)) {
        return records[i].data; // 返回第一个有效的 IPv4 地址
      } else if (records[i].type === 5) {
        const cname = records[i].data; 
        if (regex.test(cname)) {
          return cname;
        }
      }
    }
    return null;
  }

  async function resolve(domain) {
    // 首先查询 IPv6 地址（AAAA记录）
    let records
    records = await resolveDNS(domain, 'AAAA');
    let ip = findIP(records, 'AAAA');
    if (ip) {
      return ip;
    }else{
      // 如果没有找到 IPv6 地址，查询 IPv4 地址（A记录）
      records = await resolveDNS(domain, 'A');
      ip = findIP(records,'A');
      if (ip) return ip;
    }

    // 如果没有找到有效的 IP 或 CNAME，返回 null
    return null;
  }

  // 调用 resolve 函数获取最终的 IP 地址
  const ip = await resolve(domain);
  return ip;
}


