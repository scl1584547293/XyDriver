# XyDriver
这是一个通用驱动程序，包括对文件（Minifilter）、网络（WFP、TDI）、进程、线程、句柄和注册表操作的检测和控制。该项目包括驱动程序工程、应用层API、MFC接口测试程序。

使用 WDK 15063 和 VS2015可以正常编译通过，其他的需要自己尝试。



## 目录结构

|  一级目录   | 二级目录    | 说明              |
| :---------: | ----------- | ----------------- |
|  XyDriver   |             | 驱动工程          |
| XyDriverDll | XyDriverDll | 应用层接口Dll库   |
| XyDriverDll | dllMFC      | 应用层MFC测试程序 |

