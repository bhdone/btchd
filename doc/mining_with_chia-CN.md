# 如何使用chia plotter来进行挖矿？(BHDIP009)

## 编译

### 编译环境使用Linux，推荐Ubuntu 20.04发行版

注：不管是Windows版本还是Linux版本都需要在Linux系统下

#### Windows版本编译办法

**请阅读[build-windows.md](build-windows.md)中的相关章节来准备编译环境，包括安装mingw32。**

1. 在项目的根目录下运行`cd depends`
2. 执行命令下载并编译支持库`make HOST=x86_64-w64-mingw32`
3. 回到项目根目录`cd ..`
4. 执行命令进行编译

```bash
./autogen.sh && ./configure --prefix=`pwd`/depends/x86_64-w64-mingw32
```
5. 执行命令打包安装文件`make deploy`

#### Linux版本编译办法

1. 在项目的根目录下运行`cd depends`
2. 执行命令下载并编译支持库`make`
3. 回到项目根目录`cd ..`
4. 执行命令进行编译

```bash
./autogen.sh && ./configure --prefix=`pwd`/depends/x86_64-pc-linux-gnu
```

编译成功后可以执行`src/btchd-miner -h`来确认二进制文件已经生成成功

## 准备Plotter文件

请自行下载chia的钱包客户端，并使用其Plot功能对你的存储设备进行初始化。

## 配置Miner(btchd-miner)

编译完成后，可以在`src/`目录中找到可执行文件`btchd-miner`，使用命令`btchd-miner --help`可以查看基本的参数介绍。

```
BitcoinHD1 miner (chiapos)
usage:
  ./btchd-miner <command> [arguments]...
  -h [ --help ]                      show help document
  -v [ --verbose ]                   show debug logs
  -c [ --config ] arg (=config.json) the farming config file
  -m [ --min-vdf-count ] arg (=1)    minimal number of VDF forms
  --disable-computer                 disable vdf computer
  --command arg                      Command: generate-config, mining, account
```

* `--help` 显示帮助信息
* `--verbose` 显示详细的调试日志
* `--config` 指定配置文件的路径，默认为当前目录下的`config.json`
* `--min-vdf-count` 运行vdf次数，该参数只用于测试多次vdf后才出块的情况
* `--disable-computer` 不要在本地计算vdf
* `--cookie` 指定本地节点的`.cookie`文件所在的路径，默认为`$HOME/.btchd/.cookie`，Miner需要该文件与本地节点进行通信。
* `--command` 主命令。`generate-config`用于产生默认的config文件，`mining`启动挖矿，`account`用于账户相关操作

## 配置文件说明

挖矿的基本信息需要保存到配置文件中，使用`./bhd_miner
generate-config`来产生一个空的配置文件，然后将基本信息保存到该文件中。

```
{
    "plotPath" : [
        "xxxxx",
        "xxxxx"
    ], // Chia plot文件的保存路径
    "reward" : "", // BHD1的账号地址，奖励将会发送至该地址中
    "rpc" : // rpc相关
    {
        "host" : "", // RPC地址
        "passwd" : "", // RPC用户名（可省略，省略则会自动从$HOME/.btchd/.cookie读取user和password）
        "user" : "", // RPC密码（可省略，省略则会自动从$HOME/.btchd/.cookie读取user和password）
    },
    "seed" : "", // Chia钱包的助记词，用于产生farmer public-key
}
```

## 绑定plotter与chia farmer的关系

当配置文件填写完成后，请使用命令`src/btchd-miner account --bind`来尝试绑定Farmer信息到BHD1链上。

## 启动挖矿程序

1. 先确保已经启动了BHD1的节点，并打开RPC消息模式。可以使用命令`src/btchdd -server`，或是测试网络则添加参数`-testnet`。
2. 确认`config.json`中已经包含了正确的矿工信息。
3. 使用`src/btchd-miner mining`来启动挖矿客户端。注：若使用测试网络，请使用`--cookie`参数指定对应的`.cookie`文件。

## 出块及challenge的逻辑关系

* 一个区块包含一个或多个vdf proof及一个PoS proof
* 多个vdf proof的原因是因为某个challenge有可能出现全网都没有答案的情况，那么这时需要重新run一次vdf来获得下一个pos challenge 

### 步骤

1. 设定Initial challenge为上一区块的hash256+最后一个vdf proof
2. 计算vdf的proof，首次challenge为Initial challenge
3. 获得vdf proof后，由该proof+challenge计算出新的challenge2
4. 使用challenge2寻找PoS的proof，若找到则返回vdf proof和PoS的proof用于出块
5. 若PoS的proof找不到，则使用challenge2来计算新的vdf proof，然后重复[3]
6. 直到找出有效的PoS的proof，然后将PoS proof连同vdf proofs一同用于出块
