# 第三方组件说明

ADism 不随项目分发 Windows 系统镜像、系统组件库、BCDBoot、bootsect、系统文件检查器或从其他产品提取的引导代码。运行时需要的 Windows 组件来自用户自己的 Windows 安装或合法安装介质。

本次 Linux 交叉构建使用 MinGW-w64、GCC 及其 C++ 和线程运行库。可执行文件静态链接了相应运行库；相关许可随安装包提供：

- GCC 与标准 C++ 运行库：GNU GPL v3 与 GCC Runtime Library Exception，见 `LICENSES/GCC-COPYING3.txt`、`LICENSES/GCC-RUNTIME-EXCEPTION.txt`。
- MinGW-w64 运行支持：见 `LICENSES/MinGW-w64-CRT.txt`。
- winpthreads 运行支持：见 `LICENSES/winpthreads.txt`。

这些许可适用于对应第三方代码，项目自身源码的许可证为根目录 `LICENSE` 中的 GNU GPL v3。采用其他工具链自行构建时，还应遵守所用工具链和运行库的分发条款。
