# 嵌入式固件内存可视化分析器 (Firmware Memory Visualizer)

> **专为嵌入式开发者打造的纯桌面原生 GUI 固件体积与内存预算分析工具。**  
> 零 Web 依赖、完全离线运行、支持将编译生成的 `.elf`、`.axf`、`.out` 或 `.map` 文件直接拖拽分析。

![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)
![GUI](https://img.shields.io/badge/GUI-PyQt5-green.svg)
![Parser](https://img.shields.io/badge/Parser-pyelftools-orange.svg)
![License](https://img.shields.io/badge/License-MIT-purple.svg)

---

## ✨ 核心特性

1. **跨编译器与架构通用（基于标准 ELF）**：
   - 彻底摆脱单一 IDE 插件限制，直接解析底层 ELF 标准头、段表（Section Headers）、程序头（Program Headers）和符号表（DWARF / Symbol Table）。
   - **通吃主流工具链**：GNU GCC (`arm-none-eabi-gcc`, `riscv-none-elf-gcc`)、Keil MDK (`ARMCC / ARMClang AC6`)、TI CCS (`tiarmclang`)、IAR EWARM、ESP-IDF 等。
   - **全面支持主流芯片平台**：STM32、ESP32 (ESP32 / S2 / S3 / C3 / C6 / P4)、沁恒 CH32 (RISC-V / ARM)、TI MSPM0、GD32 等。

2. **精细化物理内存划分（片内 SRAM 与片外 PSRAM/SDRAM 智能分流）**：
   - **Flash (ROM)**：精确统计实际物理烧录固件大小；
   - **片内 SRAM (Internal RAM)**：精确统计芯片内部物理 SRAM 占用（支持识别段在 RAM 执行、LMA 在 Flash 的 RAM 函数）；
   - **片外 RAM (PSRAM / SDRAM)**：智能检测外扩内存（如 ESP32-S3 的 8MB Octal PSRAM、ESP32-P4 的 16MB Hexa PSRAM、STM32 FMC 外挂 SDRAM），自动展开专属看板。

3. **LMA 加载与 VMA 运行地址精准追踪**：
   - 区分加载存储地址（LMA）与运行执行地址（VMA）。
   - 完美支持 `__attribute__((section(".ramfunc")))`（Flash 存代码 + RAM 占运行空间）、`NOLOAD` 未初始化保留段。

4. **芯片容量自动识别与超限强预警**：
   - 自动关联工程 `sdkconfig`、链接器 `Memory Configuration` 与芯片特征库，自动填入额定容量；
   - **超限绝不粉饰**：当固件超过芯片额定容量时，进度条变红并以警示色显示实际溢出字节（例如 `117.2% (超出 22.0 KB)`）；空间紧缺（>90%）时显示琥珀色警告。

5. **全交互式桌面体验**：
   - **内存段比例条 (Memory Bar)**：按代码（蓝）、只读数据（紫）、片内数据（橙）、片内变量（绿）、片外外存（青）直观展示物理段分布；
   - **符号体积排行榜 (Top Symbols)**：所有函数与全局/静态变量按字节大小降序排列，毫秒级快速抓出撑爆内存的“元凶”；
   - **快捷搜索与过滤**：支持按段类型、符号类型快速过滤，双击任意行自动复制名称与地址。

---

## 🛠️ 快速上手

### 环境依赖

- Python 3.8+
- 安装依赖库：
  ```bash
  pip install -r requirements.txt
  ```

### 直接运行源码

```bash
python app_gui.py
```
或者在启动时直接附带固件路径：
```bash
python app_gui.py path/to/firmware.elf
```

### Windows 独立打包为单文件 EXE

使用 PyInstaller 一键编译为免安装独立运行程序（带应用图标）：
```bash
pyinstaller --noconsole --onefile --clean --icon="app_icon.ico" --add-data="app_icon.ico;." --name "FirmwareMemoryVisualizer" app_gui.py
```
打包生成的可执行文件位于 `dist/FirmwareMemoryVisualizer.exe`。

---

## 📂 项目结构

```text
FirmwareMemoryVisualizer/
├── app_gui.py            # PyQt5 桌面端图形界面实现（三卡片仪表盘、表格视图、颜色条）
├── parser.py             # 核心解析引擎（ELF/AXF 二进制解析、GCC/Keil/TI Map 状态机解析）
├── app_icon.ico          # 应用程序原生图标
├── requirements.txt      # Python 依赖清单
├── run.bat               # Windows 快速启动脚本
├── run.vbs               # Windows 静默无黑框启动脚本
└── README.md             # 工程说明文档
```

---

## 📄 许可证

本项目基于 [MIT License](LICENSE) 开源。
