<center>
<h1 align="center">YCT - YCryptoTools</h1>
<br>
<img src="https://socialify.git.ci/Y5neKO/YCryptoTools/image?description=1&font=Source+Code+Pro&forks=1&issues=1&language=1&name=1&owner=1&pattern=Plus&pulls=1&stargazers=1&theme=Light" alt="YCryptoTools" width="640" height="320" />
<br>
<a href='https://ysneko.github.io'><img src="https://img.shields.io/static/v1?label=Powered%20by&message=Y5neKO&color=green" alt="Author"></a>
<a href='https://www.java.com'><img src="https://img.shields.io/static/v1?label=JDK&message=8u421&color=yellow" alt="JDK"></a>
<a href='LICENSE'><img src="https://img.shields.io/static/v1?label=LICENSE&message=MIT&color=blue" alt="LICENSE"></a>
</center>

# YCryptoTools
一个前端加解密BurpSuite插件，用于加密解密请求和响应数据，方便渗透测试过程中分析HTTP流量。

## Features

- [x] 预置请求参数匹配规则（GET参数、POST参数、GET和POST参数）
- [x] 预置请求参数格式匹配（x-www、JSON）
- [ ] 复杂请求使用API加密解密
- [ ] 正则表达式匹配
- [ ] 占位符

## P.S.

目前只是方便自己使用，写了一些简单的功能，后续持续更新。

## Supported Algorithms
- URL
- AES
- DES
- RSA
- BASE64
- MD5
- SHA-1
- SM2
- SM3
- SM4

## Usage

### 请求/响应处理规则

![img.png](img/usage-addrules.png)

### 加解密器配置

![img.png](img/usage-addcryptorules.png)

## Example

### AES-CBC

![img.png](img/exam-aescbc.png)

原始请求：

![img.png](img/exam-reqres.png)

新增一个加解密器：

![img.png](img/exam-addcryptorules.png)

新增请求和响应处理规则：

使用加密器通过“,”按顺序分隔

![img.png](img/exam-addrules.png)

发送请求进行自动加解密：

![img.png](img/exam-autoende.png)

## Contributors

<a href="https://github.com/Y5neKO/YCryptoTools/graphs/contributors">
  <img src="https://contrib.rocks/image?repo=Y5neKO/YCryptoTools" />
</a>

[![Stargazers repo roster for @Y5neKO/YCryptoTools](http://reporoster.com/stars/Y5neKO/YCryptoTools)](https://github.com/Y5neKO/YCryptoTools/stargazers)

## LICENSE

[MIT](LICENSE) © Y5neKO