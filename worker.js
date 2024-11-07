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

//基本参数
const fakedomain = "";
const fakeurl = "";
const fakeSubLink = "";
const fakeSubConfig =  "";

const responsePaths = {
    "x": (sublink) => `${sublink}/xray?config=`,
    "c": (sublink) => `${sublink}/clash?config=`,
    "s": (sublink) => `${sublink}/singbox?config=`
};

//定义uuid获取方式
const extractors = {
    'trojan': link => link.match(/:\/\/(.*?)@/)[1], // 提取 trojan 协议的 UUID
    'vless': link => link.match(/:\/\/(.*?)@/)[1], // 提取 vless 协议的 UUID
    'vmess': link => JSON.parse(atob(link.slice(8))).id // 提取 vmess 协议的 UUID
};

const selfURL = '';

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

    const { input1 = '', input2 = '', inputSublink = '', inputSubconfig = '' } = formData;
    const userkey = await addUserIdData(input1, input2, olduserid, inputSublink, inputSubconfig, userId , uuid);

    const useridData = await yourkvspace.get(userkey);
    const [encheckinput1, encheckinput2, checkinputSublink, checkinputSubconfig] = useridData.split('@split@');
    const [checkput1, checkput2] = await Promise.all([
        deCD(encheckinput1, uuid),
        deCD(encheckinput2, uuid)
    ]);

    return getResponse( `<script>alert('数据已成功保存!');</script>`+ webPage(userId, checkput1, checkput2, checkinputSublink, checkinputSubconfig), 'text/html');

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
    
    let useridData = olduserid ? await yourkvspace.get(olduserid) : '';
    if (path[1] === 'manage') {
        return ifManage(userId, uuid, useridData);
    }

    //获取转换后的节点配置
    return returnLinksConfig(path, useridData, uuid,userId);
}

//管理页
async function ifManage(userId, uuid, useridData) {
    if (!useridData) {
        const fakemessage = await fakeMessage(userId)
        return getResponse(webPage(userId, fakemessage, fakeurl, fakeSubLink, fakeSubConfig), 'text/html');
    }
    const [input1, input2, inputSublink, inputSubconfig] = useridData.split('@split@');
    return getResponse(webPage(userId, ...(await Promise.all([deCD(input1, uuid), deCD(input2, uuid)])), inputSublink, inputSubconfig), 'text/html');
}

//返回用户节点配置
async function returnLinksConfig(path, useridData, uuid, userId) {
    let eninput1, eninput2, sublink, subconfig, input1, input2;

    if (!useridData) {
        sublink = fakeSubLink;
        subconfig = fakeSubConfig;
        input2 = fakeurl;
        input1 = await fakeMessage(userId)

    } else {
        [eninput1, eninput2, sublink, subconfig] = useridData.split('@split@');
        [input1, input2] = await Promise.all([
            deCD(eninput1, uuid),
            deCD(eninput2, uuid)
        ]);
    }

    let responsePath = responsePaths[path[1]] ? responsePaths[path[1]](sublink) : null;
  
    if(sublink && !subconfig){
        [responsePath , subconfig] =  sublink.split('mylinks');
    }
    if (responsePath) {
        if (path[1] === "x"){
            const combinedResult = await getUrls(input2);
            const links = `${input1}\n${combinedResult}`;
            return getResponse(btoa(`${links}`));
        }else{
            const enresponse = await fetchConfig(responsePath, input1, input2, subconfig);//加密uuid并请求配置
            return getResponse(`${await restoreUUID(enresponse)}`);//将获取的配置中的uuid全部还原并返回请求
        }
    }

    return getResponse(`${input1}\n${input2}`);

}

//添加用户数据
async function addUserIdData(input1, input2, olduserid, inputSublink, inputSubconfig, userId , uuid){
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
    await yourkvspace.put(userkey, `${eninput1}@split@${eninput2}@split@${inputSublink}@split@${inputSubconfig}`);
    return userkey;

}

//更新kv
async function updateUserId(userid, isADD) {
    // 从 KV 存储中获取 manageuserid 的值并分割成数组
    const existinguserid = (await yourkvspace.get('manageuserid')) || '';
    let userIdList = existinguserid ? existinguserid.split('@split@') : [];

    if (isADD) {
        // 添加操作：如果数组中没有该用户ID，则添加
        if (!userIdList.includes(userid)) {
            userIdList.push(userid);
        }
    } else {
        if (!userIdList.includes(userid)) {
            await yourkvspace.put('fakeuseridconfig',await enCD(userid));
            return getResponse('用户已删除！');
        }
        // 删除操作：从数组中移除该用户ID
        userIdList = userIdList.filter(storedUserId => storedUserId !== userid);

        // 删除单独存储的用户的数据 
        await yourkvspace.delete(userid);


    }
    // 将更新后的用户ID数组重新组合成字符串
    const updateduserid = userIdList.join('@split@');

    // 将新的用户ID列表保存回 yourkvspace 中
    if (updateduserid) {
        await yourkvspace.put('manageuserid', updateduserid);
    } else {
        await yourkvspace.delete('manageuserid'); // 如果列表为空，删除键
    }

    if(!isADD){
        await yourkvspace.put('fakeuseridconfig',await enCD(userid));
        return getResponse('用户已删除！');
    }

    
}

// 查询userid
async function findUserId(targetUserId, uuid) {
    if (!targetUserId) return "";

    try {
        // 直接获取 manageuserid 键下的所有加密用户名
        const encryptedNames = await yourkvspace.get('manageuserid');
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

    console.info(combinedResult);
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
    const isTrue = await yourkvspace.get('fakeuseridconfig');
    if (!isTrue){
        await yourkvspace.put('fakeuseridconfig',await enCD(userId));
    }
    const fakeuserid = `${userId}${await yourkvspace.get('fakeuseridconfig')}`;
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
const webPage = (userId = '', input1 = '', input2 = '', inputSublink = '', inputSubconfig = '') => `
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
            // 页面加载完成后，给输入框添加事件监听
            document.addEventListener("DOMContentLoaded", () => {
                const userIdInput = document.getElementById('userId');
                const form = document.getElementById('form');

                userIdInput.addEventListener('input', () => {
                    if (userIdInput.value) {
                        form.action = '/' + userIdInput.value + '/manage';
                    }
                });

                // 自适应调整文本区域的高度
                const textareas = [document.getElementById('input1'), document.getElementById('input2')];
                textareas.forEach(textarea => {
                    textarea.addEventListener('input', () => {
                        textarea.style.height = 'auto'; // 重置高度
                        textarea.style.height = textarea.scrollHeight + 'px'; // 设置为内容高度
                    });
                    // 初始设置高度
                    textarea.style.height = textarea.scrollHeight + 'px';
                });
            });

            // 删除用户的函数,确认后发送DELETE请求
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
        <h1>订阅仓库</h1>
        <form method="POST" id="form">
            <label for="userId">User ID:</label>
            <input type="text" id="userId" name="user_id" value="${userId}" placeholder="输入您的 User ID" required>
            
            <label for="input1">节点:</label>
            <textarea id="input1" name="input1" placeholder="在此输入节点信息" >${input1}</textarea>
            
            <label for="input2">订阅:</label>
            <textarea id="input2" name="input2" placeholder="在此输入订阅内容" >${input2}</textarea>
            
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
