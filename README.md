# Cloudflare Worker 订阅管理面板

一个基于 Cloudflare Worker 编写的节点和订阅的管理面板。

## 安装步骤

1. 复制 `worker.js` 到新建的 Worker 项目中。
2. 创建 KV 变量。
3. 绑定 KV 到新建的项目中。
4. 修改代码中 KV 变量的名称与绑定的 KV 变量名称一致。（查找‘yourkvspace并全部替换成你的kv空间变量名’）
5. 在代码中填写fakedomain、fakeurl等信息

## 使用说明

1. 填写对应的信息

![image](https://github.com/user-attachments/assets/f47fbe5f-5276-4705-8aa6-7fc30e8bde5e)


2. 输入域名/userid 查看节点和订阅信息。
3. 输入域名/userid/manage 管理用户数据。
4. 输入域名/userid/x 转换成 xray，/c 转换成 clash，/s 转换成 singbox。
（需要根据使用的后端的格式对代码的 const responsePaths 部分进行必要的修改)
5. 在任意订阅转换前端输入mylinks获取转换链接，填入Sublink行即可发送替换uuid的节点信息到任意转换前端并在worker中还原原uuid。
（发送的信息的uuid是假的，后端订阅转换不会知道你真实的节点信息）

详细的功能与代码实现可以参考完整代码部分，确保在实际使用时进行必要的修改与配置。

## 功能特性
1、输入未保存的路径（userid）会随机生成任意条，任意uuid的节点。

2、面板对userid、节点、订阅进行加密算法保存，务必牢记userid，否则无法找回。


