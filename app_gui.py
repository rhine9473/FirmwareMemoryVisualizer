"""
Firmware Memory Visualizer - Native Desktop GUI & CLI (PyQt5)
Universal memory allocation analyzer for ELF, AXF and MAP files.
Supports internal SRAM and external PSRAM/SDRAM visual split.
Features:
- Application Partition Budget detection (应用分区上限精准预警)
- Headless CLI mode for CI/CD & Automated Budget Gatekeeping (--cli)
- Copy Markdown Summary to clipboard (一键复制 Markdown 摘要)
- Firmware Version Diff & Baseline comparison (增减对比)
- C++ Symbol Demangling toggle (C++符号还原)
- Cross-toolchain Module attribution (模块/源文件归因)
- One-click export to HTML / CSV / JSON (离线报表导出)
"""

import os
import sys
import json
import csv
import time
import argparse
from typing import Optional, Dict, Any, List

from PyQt5.QtCore import Qt, QSize, QRectF
from PyQt5.QtGui import (
    QColor, QFont, QIcon, QPainter, QBrush, QPen,
    QDragEnterEvent, QDropEvent
)
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QPushButton, QFileDialog, QTabWidget, QTableWidget,
    QTableWidgetItem, QHeaderView, QLineEdit, QComboBox, QProgressBar,
    QFrame, QStatusBar, QMessageBox, QAbstractItemView, QMenu, QAction, QCheckBox
)

from parser import FirmwareParser, format_bytes, batch_demangle


def get_resource_path(relative_path):
    base_path = getattr(sys, '_MEIPASS', os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base_path, relative_path)


def generate_html_content(data: Dict[str, Any], fl_cap: str, ram_int_cap: str, ram_ext_cap: str,
                          fl_pct: str, ram_int_pct: str, fl_sub: str, ram_int_sub: str, ext_sub: str) -> str:
    """Generate standalone interactive HTML report."""
    fl_str = format_bytes(data.get('flash_total', 0))
    ram_int_str = format_bytes(data.get('ram_internal_total', 0))
    ram_ext_str = format_bytes(data.get('ram_external_total', 0))
    gen_time = time.strftime("%Y-%m-%d %H:%M:%S")

    sec_rows = ""
    for s in data.get('sections', []):
        sec_rows += f"<tr><td>{s['name']}</td><td>{s.get('category','')}</td><td>{s['address_hex']}</td><td>{s['size']:,}</td><td>{s['size_str']}</td><td>{s.get('flags','')}</td></tr>\n"

    sym_rows = ""
    for s in data.get('symbols', [])[:300]:
        name = s.get('demangled_name', s['name'])
        sym_rows += f"<tr><td>{name}</td><td>{s['type']}</td><td>{s.get('section','')}</td><td>{s.get('module','')}</td><td>{s['address_hex']}</td><td>{s['size']:,}</td><td>{s['size_str']}</td></tr>\n"

    mod_rows = ""
    for m_name, m in sorted(data.get('modules', {}).items(), key=lambda x: x[1]['flash'] + x[1]['ram'], reverse=True):
        mod_rows += f"<tr><td>{m_name}</td><td>{format_bytes(m['code'])}</td><td>{format_bytes(m['ro_data'])}</td><td>{format_bytes(m['rw_data'])}</td><td>{format_bytes(m['zi_data'])}</td><td><b>{format_bytes(m['flash'])}</b></td><td><b>{format_bytes(m['ram'])}</b></td></tr>\n"

    ext_card_html = ""
    if data.get('has_external_ram'):
        ext_name = data.get('external_ram_name', '外扩 RAM')
        ext_card_html = f"""
        <div class="card">
            <div class="card-title">片外 RAM ({ext_name})</div>
            <div class="card-val val-cyan">{ram_ext_str}</div>
            <div class="sub">额定: {ram_ext_cap} KB | 状态: {ext_sub}</div>
        </div>
        """

    return f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>固件内存分析报告 - {data['file_name']}</title>
<style>
body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Arial, sans-serif; background: #f8fafc; margin: 24px; color: #1e293b; }}
.header {{ background: white; border-radius: 8px; border: 1px solid #e2e8f0; padding: 18px 24px; margin-bottom: 20px; }}
.header h1 {{ margin: 0 0 6px 0; font-size: 22px; color: #0f172a; }}
.header p {{ margin: 0; font-size: 13px; color: #64748b; }}
.grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 16px; margin-bottom: 24px; }}
.card {{ background: white; border-radius: 8px; border: 1px solid #e2e8f0; padding: 16px 20px; }}
.card-title {{ font-size: 13px; font-weight: 600; color: #475569; }}
.card-val {{ font-size: 26px; font-weight: bold; margin: 8px 0; }}
.val-blue {{ color: #2563eb; }}
.val-green {{ color: #059669; }}
.val-cyan {{ color: #0891b2; }}
.sub {{ font-size: 11px; color: #64748b; }}
.panel {{ background: white; border-radius: 8px; border: 1px solid #e2e8f0; padding: 20px; margin-bottom: 24px; }}
.panel h2 {{ margin: 0 0 12px 0; font-size: 16px; color: #1e293b; }}
table {{ width: 100%; border-collapse: collapse; font-size: 12px; margin-top: 10px; }}
th, td {{ border: 1px solid #e2e8f0; padding: 7px 10px; text-align: left; }}
th {{ background: #f1f5f9; font-weight: 600; color: #475569; }}
tr:nth-child(even) {{ background: #f8fafc; }}
input.filter-box {{ width: 100%; box-sizing: border-box; padding: 8px 12px; border: 1px solid #cbd5e1; border-radius: 6px; font-size: 13px; margin-bottom: 12px; }}
</style>
<script>
function filterTable(inputId, tableId) {{
    var input = document.getElementById(inputId);
    var filter = input.value.toLowerCase();
    var rows = document.querySelectorAll('#' + tableId + ' tbody tr');
    rows.forEach(function(row) {{
        row.style.display = row.textContent.toLowerCase().includes(filter) ? '' : 'none';
    }});
}}
</script>
</head>
<body>
<div class="header">
    <h1>📊 嵌入式固件内存分析报告: {data['file_name']}</h1>
    <p>文件类型: {data['file_type']} | 目标架构: {data['arch']} | 生成时间: {gen_time}</p>
    <p style="margin-top:4px; font-size:11px; color:#94a3b8;">源路径: {data['file_path']}</p>
</div>

<div class="grid">
    <div class="card">
        <div class="card-title">Flash (ROM 固件占用)</div>
        <div class="card-val val-blue">{fl_str}</div>
        <div class="sub">额定/预算: {fl_cap} KB | 占用率: <b>{fl_pct}</b> {fl_sub}</div>
    </div>
    <div class="card">
        <div class="card-title">片内 SRAM (Internal RAM)</div>
        <div class="card-val val-green">{ram_int_str}</div>
        <div class="sub">额定: {ram_int_cap} KB | 占用率: <b>{ram_int_pct}</b> {ram_int_sub}</div>
    </div>
    {ext_card_html}
</div>

<div class="panel">
    <h2>📌 内存段构成 (Sections)</h2>
    <input type="text" id="secInput" class="filter-box" onkeyup="filterTable('secInput', 'secTable')" placeholder="🔍 快速搜索段名称 (如 .text, .data, bss)...">
    <table id="secTable">
        <thead>
            <tr><th>段名称 (Section)</th><th>内存归属类别</th><th>虚拟地址 (VMA)</th><th>大小 (字节)</th><th>格式化大小</th><th>属性 Flags</th></tr>
        </thead>
        <tbody>
            {sec_rows}
        </tbody>
    </table>
</div>

<div class="panel">
    <h2>🏆 符号体积排行榜 Top 300 (Symbols)</h2>
    <input type="text" id="symInput" class="filter-box" onkeyup="filterTable('symInput', 'symTable')" placeholder="🔍 快速搜索函数名或全局变量名...">
    <table id="symTable">
        <thead>
            <tr><th>符号名称 (Symbol)</th><th>类型</th><th>所属段</th><th>所属模块 / 源文件</th><th>地址 (VMA)</th><th>大小 (字节)</th><th>格式化大小</th></tr>
        </thead>
        <tbody>
            {sym_rows}
        </tbody>
    </table>
</div>

<div class="panel">
    <h2>📦 模块与源文件分析 (Modules)</h2>
    <input type="text" id="modInput" class="filter-box" onkeyup="filterTable('modInput', 'modTable')" placeholder="🔍 快速搜索模块名称...">
    <table id="modTable">
        <thead>
            <tr><th>目标模块 / 源文件</th><th>Code 代码</th><th>RO 数据</th><th>RW 数据</th><th>ZI 数据</th><th>总 Flash</th><th>总 RAM</th></tr>
        </thead>
        <tbody>
            {mod_rows}
        </tbody>
    </table>
</div>
</body>
</html>"""


class MemoryBarWidget(QWidget):
    """Custom widget to draw a proportional colored memory layout bar."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.segments = []
        self.total_size = 0
        self.setFixedHeight(26)
        self.setToolTip("内存段分布比例图 (悬停查看详情)")

    def set_data(self, sections: list):
        self.segments = []
        valid_secs = [
            s for s in sections
            if s.get('size', 0) > 0 and (
                s.get('category', '').startswith('Flash') or
                'RAM' in s.get('category', '')
            )
        ]
        self.total_size = sum(s['size'] for s in valid_secs)

        color_map = {
            "Flash (Code)": QColor("#2563eb"),
            "Flash (RO-Data)": QColor("#7c3aed"),
            "片内 RAM & Flash (Data)": QColor("#d97706"),
            "片内 RAM & Flash (Data/Code)": QColor("#d97706"),
            "片内 RAM (Internal SRAM)": QColor("#059669"),
            "片内 RAM (BSS/NOLOAD)": QColor("#059669"),
            "片外 RAM & Flash (Data)": QColor("#e11d48"),
            "片外 RAM & Flash (Data/Code)": QColor("#e11d48"),
            "片外 RAM (PSRAM/SDRAM)": QColor("#0891b2"),
            "片外 RAM (BSS/NOLOAD)": QColor("#0891b2"),
            "片内 RAM & Flash (RTC)": QColor("#10b981")
        }

        for sec in sorted(valid_secs, key=lambda x: x['size'], reverse=True):
            cat = sec.get('category', '')
            color = color_map.get(cat, QColor("#6b7280"))
            self.segments.append({
                'name': sec['name'],
                'size': sec['size'],
                'size_str': sec['size_str'],
                'category': cat,
                'color': color
            })
        self.update()

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)

        rect = self.rect()
        w = rect.width()
        h = rect.height()

        if not self.segments or self.total_size == 0:
            painter.setBrush(QColor("#e5e7eb"))
            painter.setPen(Qt.NoPen)
            painter.drawRoundedRect(0, 0, w, h, 6, 6)
            painter.setPen(QColor("#9ca3af"))
            painter.drawText(rect, Qt.AlignCenter, "暂无内存段数据")
            return

        x_cur = 0.0
        painter.setPen(Qt.NoPen)
        painter.setClipRect(rect)

        for i, seg in enumerate(self.segments):
            frac = seg['size'] / self.total_size
            seg_w = max(2.0, frac * w)
            if i == len(self.segments) - 1:
                seg_w = w - x_cur

            painter.setBrush(seg['color'])
            painter.drawRect(QRectF(x_cur, 0, seg_w, h))

            if seg_w > 45:
                painter.setPen(QColor("#ffffff"))
                font = painter.font()
                font.setPointSize(8)
                font.setBold(True)
                painter.setFont(font)
                text = f"{seg['name']} ({seg['size_str']})" if seg_w > 90 else seg['name']
                painter.drawText(QRectF(x_cur + 4, 0, seg_w - 8, h), Qt.AlignVCenter | Qt.AlignLeft, text)
                painter.setPen(Qt.NoPen)

            x_cur += seg_w


class NumericTableWidgetItem(QTableWidgetItem):
    """Table item with custom numeric sort order."""
    def __init__(self, value, text=None):
        super().__init__(text if text is not None else str(value))
        self.numeric_value = value

    def __lt__(self, other):
        if isinstance(other, NumericTableWidgetItem):
            return self.numeric_value < other.numeric_value
        return super().__lt__(other)


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.current_data: Optional[Dict[str, Any]] = None
        self.baseline_data: Optional[Dict[str, Any]] = None
        self.init_ui()

    def init_ui(self):
        self.setWindowTitle("嵌入式固件内存可视化分析器 (Firmware Memory Visualizer)")

        screen = QApplication.primaryScreen()
        if screen:
            avail = screen.availableGeometry()
            w = min(1140, max(840, int(avail.width() * 0.78)))
            h = min(660, max(500, int(avail.height() * 0.74)))
            self.resize(w, h)
            self.setMinimumSize(800, 480)
            self.move(avail.x() + (avail.width() - w) // 2, avail.y() + (avail.height() - h) // 2)
        else:
            self.resize(1080, 640)
            self.setMinimumSize(800, 480)

        self.setAcceptDrops(True)
        self.apply_stylesheet()

        central = QWidget(self)
        self.setCentralWidget(central)
        main_layout = QVBoxLayout(central)
        main_layout.setContentsMargins(12, 10, 12, 6)
        main_layout.setSpacing(8)

        # 1. Top Bar
        top_box = QFrame()
        top_box.setObjectName("topBox")
        top_layout = QHBoxLayout(top_box)
        top_layout.setContentsMargins(12, 6, 12, 6)
        top_layout.setSpacing(8)

        self.lbl_file_info = QLabel("请将 <b>.elf</b>、<b>.axf</b> 或 <b>.map</b> 固件文件拖入窗口，或点击右侧按钮打开")
        self.lbl_file_info.setStyleSheet("font-size: 13px; color: #1e293b;")
        top_layout.addWidget(self.lbl_file_info, stretch=1)

        btn_open = QPushButton("📂 打开固件")
        btn_open.setObjectName("btnPrimary")
        btn_open.setCursor(Qt.PointingHandCursor)
        btn_open.clicked.connect(self.choose_file)
        top_layout.addWidget(btn_open)

        self.btn_reload = QPushButton("🔄 重新解析")
        self.btn_reload.setObjectName("btnSecondary")
        self.btn_reload.setCursor(Qt.PointingHandCursor)
        self.btn_reload.clicked.connect(self.reload_file)
        self.btn_reload.setEnabled(False)
        top_layout.addWidget(self.btn_reload)

        self.btn_set_baseline = QPushButton("📌 设为基线")
        self.btn_set_baseline.setObjectName("btnSecondary")
        self.btn_set_baseline.setCursor(Qt.PointingHandCursor)
        self.btn_set_baseline.setToolTip("将当前固件锁定为基线，随后载入新构建产物即可直观对比增减体积")
        self.btn_set_baseline.clicked.connect(self.set_as_baseline)
        self.btn_set_baseline.setEnabled(False)
        top_layout.addWidget(self.btn_set_baseline)

        self.btn_clear_baseline = QPushButton("❌ 取消基线")
        self.btn_clear_baseline.setObjectName("btnSecondary")
        self.btn_clear_baseline.setCursor(Qt.PointingHandCursor)
        self.btn_clear_baseline.clicked.connect(self.clear_baseline)
        self.btn_clear_baseline.setVisible(False)
        top_layout.addWidget(self.btn_clear_baseline)

        self.btn_copy_md = QPushButton("📋 复制 Markdown")
        self.btn_copy_md.setObjectName("btnSecondary")
        self.btn_copy_md.setCursor(Qt.PointingHandCursor)
        self.btn_copy_md.setToolTip("一键生成精美 Markdown 内存分析摘要表格并复制到剪贴板，方便直接粘贴到 PR 或群聊中汇报")
        self.btn_copy_md.clicked.connect(self.copy_markdown_summary)
        self.btn_copy_md.setEnabled(False)
        top_layout.addWidget(self.btn_copy_md)

        self.btn_export = QPushButton("📤 导出分析 ▾")
        self.btn_export.setObjectName("btnSecondary")
        self.btn_export.setCursor(Qt.PointingHandCursor)
        export_menu = QMenu(self)
        act_html = export_menu.addAction("🌐 导出交互式网页报告 (*.html)")
        act_csv = export_menu.addAction("📊 导出符号与模块表 (*.csv)")
        act_json = export_menu.addAction("📄 导出原始数据 (*.json)")
        act_html.triggered.connect(self.export_html)
        act_csv.triggered.connect(self.export_csv)
        act_json.triggered.connect(self.export_json)
        self.btn_export.setMenu(export_menu)
        self.btn_export.setEnabled(False)
        top_layout.addWidget(self.btn_export)

        main_layout.addWidget(top_box)

        # Baseline Alert Banner
        self.banner_baseline = QFrame()
        self.banner_baseline.setObjectName("bannerBox")
        self.banner_baseline.setVisible(False)
        banner_lay = QHBoxLayout(self.banner_baseline)
        banner_lay.setContentsMargins(12, 4, 12, 4)
        self.lbl_banner_text = QLabel("")
        self.lbl_banner_text.setStyleSheet("font-size: 11px; color: #0369a1; font-weight: 500;")
        banner_lay.addWidget(self.lbl_banner_text)
        main_layout.addWidget(self.banner_baseline)

        # 2. Gauge Cards: Flash, 片内 SRAM, 片外 RAM
        gauge_layout = QHBoxLayout()
        gauge_layout.setSpacing(10)

        # Card 1: Flash
        self.card_flash, self.lbl_flash_val, self.lbl_flash_bytes, self.lbl_flash_pct, self.prog_flash, self.txt_flash_cap, self.lbl_flash_sub = self.create_gauge_card(
            "Flash (ROM 固件占用)", "#2563eb", "512"
        )
        gauge_layout.addWidget(self.card_flash)

        # Card 2: 片内 SRAM
        self.card_ram_int, self.lbl_ram_int_val, self.lbl_ram_int_bytes, self.lbl_ram_int_pct, self.prog_ram_int, self.txt_ram_int_cap, self.lbl_ram_int_sub = self.create_gauge_card(
            "片内 SRAM (Internal RAM)", "#059669", "128"
        )
        gauge_layout.addWidget(self.card_ram_int)

        # Card 3: 片外 RAM (PSRAM / SDRAM)
        self.card_ram_ext, self.lbl_ram_ext_val, self.lbl_ram_ext_bytes, self.lbl_ram_ext_pct, self.prog_ram_ext, self.txt_ram_ext_cap, self.lbl_ram_ext_sub = self.create_gauge_card(
            "片外 RAM (PSRAM / SDRAM)", "#0891b2", "8192"
        )
        self.card_ram_ext.setVisible(False)
        gauge_layout.addWidget(self.card_ram_ext)

        main_layout.addLayout(gauge_layout)

        # 3. Proportional Memory Bar
        mem_bar_box = QFrame()
        mem_bar_box.setObjectName("cardBox")
        mem_bar_layout = QVBoxLayout(mem_bar_box)
        mem_bar_layout.setContentsMargins(10, 6, 10, 6)
        mem_bar_layout.setSpacing(3)

        bar_title = QLabel("<b>内存段分布示意图 (Proportional Memory Map)</b>")
        bar_title.setStyleSheet("font-size: 11px; color: #64748b;")
        mem_bar_layout.addWidget(bar_title)

        self.mem_bar = MemoryBarWidget()
        mem_bar_layout.addWidget(self.mem_bar)

        legend_layout = QHBoxLayout()
        legend_layout.setSpacing(14)
        legend_layout.addWidget(self.create_legend_dot("#2563eb", "代码 (.text)"))
        legend_layout.addWidget(self.create_legend_dot("#7c3aed", "只读数据 (.rodata)"))
        legend_layout.addWidget(self.create_legend_dot("#d97706", "片内数据 (.data)"))
        legend_layout.addWidget(self.create_legend_dot("#059669", "片内变量 (.bss)"))
        legend_layout.addWidget(self.create_legend_dot("#0891b2", "片外 RAM (PSRAM/SDRAM)"))
        legend_layout.addStretch()
        mem_bar_layout.addLayout(legend_layout)

        main_layout.addWidget(mem_bar_box)

        # 4. Tabs Section
        self.tabs = QTabWidget()
        self.tabs.setObjectName("mainTabs")

        # Tab 1: Sections
        tab_sec = QWidget()
        sec_layout = QVBoxLayout(tab_sec)
        sec_layout.setContentsMargins(8, 10, 8, 8)
        sec_layout.setSpacing(8)

        sec_ctrl = QHBoxLayout()
        self.search_sec = QLineEdit()
        self.search_sec.setPlaceholderText("🔍 快速过滤段名称 (如 .text, .bss, psram, isr)...")
        self.search_sec.textChanged.connect(self.filter_sections)
        sec_ctrl.addWidget(self.search_sec, stretch=1)

        self.cb_sec_filter = QComboBox()
        self.cb_sec_filter.addItems(["显示全部段", "仅看 Flash 相关段", "仅看片内 RAM 段", "仅看片外 RAM 段", "仅看代码段 (Exec)", "仅看有变动的段 (Diff)"])
        self.cb_sec_filter.currentIndexChanged.connect(self.filter_sections)
        sec_ctrl.addWidget(self.cb_sec_filter)
        sec_layout.addLayout(sec_ctrl)

        self.tbl_sections = QTableWidget()
        self.tbl_sections.setColumnCount(8)
        self.tbl_sections.setHorizontalHeaderLabels([
            "序号", "段名称 (Section)", "内存归属类别", "虚拟地址 (VMA)", "大小 (字节)", "格式化大小", "变化量 (Diff)", "属性 Flags"
        ])
        self.tbl_sections.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.tbl_sections.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.tbl_sections.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeToContents)
        self.tbl_sections.horizontalHeader().setSectionResizeMode(6, QHeaderView.ResizeToContents)
        self.tbl_sections.setSortingEnabled(True)
        self.tbl_sections.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.tbl_sections.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.tbl_sections.doubleClicked.connect(self.on_table_double_clicked)
        sec_layout.addWidget(self.tbl_sections)
        self.tabs.addTab(tab_sec, "📌 内存段构成 (Sections)")

        # Tab 2: Symbols
        tab_sym = QWidget()
        sym_layout = QVBoxLayout(tab_sym)
        sym_layout.setContentsMargins(8, 10, 8, 8)
        sym_layout.setSpacing(8)

        sym_ctrl = QHBoxLayout()
        self.search_sym = QLineEdit()
        self.search_sym.setPlaceholderText("🔍 搜索函数名或全局变量名 (支持 C++ 还原名实时检索)...")
        self.search_sym.textChanged.connect(self.filter_symbols)
        sym_ctrl.addWidget(self.search_sym, stretch=1)

        self.cb_sym_type = QComboBox()
        self.cb_sym_type.addItems(["全部符号", "仅看函数 (Functions)", "仅看变量 (Variables)", "仅看有变化的符号 (Only Changed)"])
        self.cb_sym_type.currentIndexChanged.connect(self.filter_symbols)
        sym_ctrl.addWidget(self.cb_sym_type)

        self.chk_demangle = QCheckBox("还原 C++ 符号名")
        self.chk_demangle.setChecked(True)
        self.chk_demangle.setToolTip("勾选后将自动将编译器混淆的 C++ 符号名（如 _ZN7MyClass4initEv）还原为易读形式（如 MyClass::init()）")
        self.chk_demangle.toggled.connect(self.populate_symbols)
        sym_ctrl.addWidget(self.chk_demangle)

        sym_layout.addLayout(sym_ctrl)

        self.tbl_symbols = QTableWidget()
        self.tbl_symbols.setColumnCount(9)
        self.tbl_symbols.setHorizontalHeaderLabels([
            "排名", "符号名称 (Symbol)", "类型", "所属段 (Section)", "所属模块 / 文件", "虚拟地址 (VMA)", "大小 (字节)", "格式化大小", "变化量 (Diff)"
        ])
        self.tbl_symbols.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.tbl_symbols.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.tbl_symbols.horizontalHeader().setSectionResizeMode(6, QHeaderView.ResizeToContents)
        self.tbl_symbols.horizontalHeader().setSectionResizeMode(8, QHeaderView.ResizeToContents)
        self.tbl_symbols.setSortingEnabled(True)
        self.tbl_symbols.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.tbl_symbols.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.tbl_symbols.doubleClicked.connect(self.on_table_double_clicked)
        sym_layout.addWidget(self.tbl_symbols)
        self.tabs.addTab(tab_sym, "🏆 符号体积排行榜 (Top Symbols)")

        # Tab 3: Modules
        tab_mod = QWidget()
        mod_layout = QVBoxLayout(tab_mod)
        mod_layout.setContentsMargins(8, 10, 8, 8)
        mod_layout.setSpacing(8)

        self.search_mod = QLineEdit()
        self.search_mod.setPlaceholderText("🔍 过滤源文件或库模块名称 (如 main.o, lv_font, libc.a)...")
        self.search_mod.textChanged.connect(self.filter_modules)
        mod_layout.addWidget(self.search_mod)

        self.tbl_modules = QTableWidget()
        self.tbl_modules.setColumnCount(7)
        self.tbl_modules.setHorizontalHeaderLabels([
            "目标模块 / 源文件 (.o / .lib)", "Code 代码", "RO 数据", "RW 数据", "ZI 数据", "总 Flash", "总 RAM"
        ])
        self.tbl_modules.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.tbl_modules.horizontalHeader().setSectionResizeMode(5, QHeaderView.ResizeToContents)
        self.tbl_modules.horizontalHeader().setSectionResizeMode(6, QHeaderView.ResizeToContents)
        self.tbl_modules.setSortingEnabled(True)
        self.tbl_modules.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.tbl_modules.setEditTriggers(QAbstractItemView.NoEditTriggers)
        mod_layout.addWidget(self.tbl_modules)
        self.tabs.addTab(tab_mod, "📦 模块 / 目标文件分析 (Modules)")

        main_layout.addWidget(self.tabs, stretch=1)

        # Status Bar
        self.status = QStatusBar()
        self.setStatusBar(self.status)
        self.status.showMessage("就绪。直接拖入 .elf / .axf / .map 文件即可瞬间完成全量分析。双击任意表格项可复制内容。")

    def create_gauge_card(self, title: str, color_hex: str, default_cap: str):
        card = QFrame()
        card.setObjectName("cardBox")
        layout = QVBoxLayout(card)
        layout.setContentsMargins(12, 8, 12, 8)
        layout.setSpacing(4)

        title_row = QHBoxLayout()
        lbl_title = QLabel(f"<b>{title}</b>")
        lbl_title.setStyleSheet("font-size: 12px; color: #475569;")
        title_row.addWidget(lbl_title)
        title_row.addStretch()

        lbl_cap = QLabel("额定/预算:")
        lbl_cap.setStyleSheet("font-size: 11px; color: #64748b;")
        title_row.addWidget(lbl_cap)

        txt_cap = QLineEdit(default_cap)
        txt_cap.setFixedWidth(54)
        txt_cap.setAlignment(Qt.AlignCenter)
        txt_cap.setStyleSheet("font-size: 11px; padding: 2px; border: 1px solid #cbd5e1; border-radius: 4px;")
        title_row.addWidget(txt_cap)

        lbl_unit = QLabel("KB")
        lbl_unit.setStyleSheet("font-size: 11px; color: #64748b;")
        title_row.addWidget(lbl_unit)
        layout.addLayout(title_row)

        val_row = QHBoxLayout()
        lbl_val = QLabel("0.00 KB")
        lbl_val.setStyleSheet(f"font-size: 20px; font-weight: bold; color: {color_hex};")
        val_row.addWidget(lbl_val)

        lbl_bytes = QLabel("(0 字节)")
        lbl_bytes.setStyleSheet("font-size: 11px; color: #94a3b8; padding-top: 4px;")
        val_row.addWidget(lbl_bytes)
        val_row.addStretch()

        lbl_percent = QLabel("0.0 %")
        lbl_percent.setStyleSheet(f"font-size: 16px; font-weight: bold; color: {color_hex};")
        val_row.addWidget(lbl_percent)
        layout.addLayout(val_row)

        prog = QProgressBar()
        prog.setRange(0, 1000)
        prog.setValue(0)
        prog.setTextVisible(False)
        prog.setFixedHeight(7)
        prog.setStyleSheet(f"""
            QProgressBar {{
                background-color: #f1f5f9;
                border-radius: 3px;
            }}
            QProgressBar::chunk {{
                background-color: {color_hex};
                border-radius: 3px;
            }}
        """)
        layout.addWidget(prog)

        lbl_sub = QLabel("")
        lbl_sub.setStyleSheet("font-size: 10px; color: #64748b;")
        layout.addWidget(lbl_sub)

        txt_cap.textChanged.connect(self.update_gauges)

        return card, lbl_val, lbl_bytes, lbl_percent, prog, txt_cap, lbl_sub

    def create_legend_dot(self, color_hex: str, label_text: str) -> QWidget:
        w = QWidget()
        lay = QHBoxLayout(w)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(5)

        dot = QLabel()
        dot.setFixedSize(9, 9)
        dot.setStyleSheet(f"background-color: {color_hex}; border-radius: 4px;")
        lay.addWidget(dot)

        lbl = QLabel(label_text)
        lbl.setStyleSheet("font-size: 11px; color: #475569;")
        lay.addWidget(lbl)
        return w

    def apply_stylesheet(self):
        self.setStyleSheet("""
            QMainWindow {
                background-color: #f8fafc;
            }
            QFrame#topBox, QFrame#cardBox {
                background-color: #ffffff;
                border: 1px solid #e2e8f0;
                border-radius: 8px;
            }
            QFrame#bannerBox {
                background-color: #f0f9ff;
                border: 1px solid #bae6fd;
                border-radius: 6px;
            }
            QPushButton#btnPrimary {
                background-color: #2563eb;
                color: #ffffff;
                border: none;
                border-radius: 6px;
                padding: 6px 14px;
                font-size: 12px;
                font-weight: bold;
            }
            QPushButton#btnPrimary:hover {
                background-color: #1d4ed8;
            }
            QPushButton#btnSecondary {
                background-color: #f1f5f9;
                color: #334155;
                border: 1px solid #cbd5e1;
                border-radius: 6px;
                padding: 6px 12px;
                font-size: 12px;
            }
            QPushButton#btnSecondary:hover {
                background-color: #e2e8f0;
            }
            QLineEdit {
                background-color: #ffffff;
                border: 1px solid #cbd5e1;
                border-radius: 6px;
                padding: 5px 10px;
                font-size: 12px;
            }
            QLineEdit:focus {
                border: 1px solid #3b82f6;
            }
            QComboBox {
                background-color: #ffffff;
                border: 1px solid #cbd5e1;
                border-radius: 6px;
                padding: 4px 8px;
                font-size: 12px;
            }
            QCheckBox {
                font-size: 12px;
                color: #475569;
            }
            QTabWidget::pane {
                border: 1px solid #e2e8f0;
                background: #ffffff;
                border-radius: 6px;
            }
            QTabBar::tab {
                background: #f1f5f9;
                color: #475569;
                padding: 7px 15px;
                font-size: 12px;
                font-weight: bold;
                border-top-left-radius: 6px;
                border-top-right-radius: 6px;
                margin-right: 2px;
            }
            QTabBar::tab:selected {
                background: #ffffff;
                color: #2563eb;
                border-bottom: 2px solid #2563eb;
            }
            QTableWidget {
                border: 1px solid #e2e8f0;
                gridline-color: #f1f5f9;
                background-color: #ffffff;
                font-size: 12px;
            }
            QTableWidget::item {
                padding: 3px;
            }
            QHeaderView::section {
                background-color: #f8fafc;
                color: #475569;
                font-weight: bold;
                padding: 5px;
                border: 1px solid #e2e8f0;
                font-size: 11px;
            }
            QStatusBar {
                background-color: #f1f5f9;
                color: #64748b;
                font-size: 11px;
            }
        """)

    # -------------------------------------------------------------------------
    # Baseline Diff Mode
    # -------------------------------------------------------------------------
    def set_as_baseline(self):
        if not self.current_data:
            return
        self.baseline_data = self.current_data
        self.btn_clear_baseline.setVisible(True)
        self.banner_baseline.setVisible(True)

        fl = format_bytes(self.baseline_data.get('flash_total', 0))
        ram = format_bytes(self.baseline_data.get('ram_internal_total', 0))
        fn = self.baseline_data.get('file_name', '未命名')
        self.lbl_banner_text.setText(
            f"⚖️ 对比基线已锁定: <b>{fn}</b> (Flash: {fl}, 片内RAM: {ram})。现在重新编译并点击【重新解析】，或拖入新固件即可查看增减差异！"
        )
        self.status.showMessage(f"已将 {fn} 设定为对比基准！")
        self.update_gauges()
        self.populate_sections()
        self.populate_symbols()

    def clear_baseline(self):
        self.baseline_data = None
        self.btn_clear_baseline.setVisible(False)
        self.banner_baseline.setVisible(False)
        self.status.showMessage("已清除对比基准，恢复常规统计模式。")
        self.update_gauges()
        self.populate_sections()
        self.populate_symbols()

    # -------------------------------------------------------------------------
    # Drag and Drop Handling
    # -------------------------------------------------------------------------
    def dragEnterEvent(self, event: QDragEnterEvent):
        if event.mimeData().hasUrls():
            urls = event.mimeData().urls()
            if urls:
                path = urls[0].toLocalFile()
                ext = os.path.splitext(path)[1].lower()
                if ext in ['.elf', '.axf', '.out', '.map', '.o'] or os.path.isfile(path):
                    event.acceptProposedAction()
                    return
        event.ignore()

    def dropEvent(self, event: QDropEvent):
        urls = event.mimeData().urls()
        if urls:
            path = urls[0].toLocalFile()
            if os.path.isfile(path):
                self.load_file(path)

    # -------------------------------------------------------------------------
    # File Operations
    # -------------------------------------------------------------------------
    def choose_file(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "选择固件或 Map 文件",
            "",
            "固件与映射文件 (*.elf *.axf *.out *.map);;ELF/AXF 固件 (*.elf *.axf *.out);;Linker Map 映射文件 (*.map);;所有文件 (*.*)"
        )
        if file_path:
            self.load_file(file_path)

    def reload_file(self):
        if self.current_data and 'file_path' in self.current_data:
            self.load_file(self.current_data['file_path'])

    def load_file(self, file_path: str):
        try:
            self.status.showMessage(f"正在解析 {file_path} ...")
            QApplication.processEvents()

            data = FirmwareParser.parse_file(file_path)
            self.current_data = data
            self.btn_reload.setEnabled(True)
            self.btn_set_baseline.setEnabled(True)
            self.btn_copy_md.setEnabled(True)
            self.btn_export.setEnabled(True)

            entry_str = f", 入口: 0x{data['entry']:08X}" if data.get('entry') else ""
            arch_str = f" | 架构: {data['arch']}" if data.get('arch') != 'Unknown' else ""
            ext_badge = f" | <span style='color: #0891b2;'>{data.get('external_ram_name')}</span>" if data.get('has_external_ram') else ""
            self.lbl_file_info.setText(
                f"<b>{data['file_name']}</b> <span style='color: #64748b;'>({data['file_type']}{arch_str}{entry_str}{ext_badge})</span><br>"
                f"<span style='font-size: 11px; color: #94a3b8;'>{file_path}</span>"
            )

            # Auto populate capacities
            if data.get('chip_flash_kb'):
                self.txt_flash_cap.setText(str(data['chip_flash_kb']))
            self.lbl_flash_sub.setText(data.get('flash_sub_note', ''))

            if data.get('chip_internal_ram_kb'):
                self.txt_ram_int_cap.setText(str(data['chip_internal_ram_kb']))
            self.lbl_ram_int_sub.setText(data.get('ram_int_note', ''))

            has_ext = data.get('has_external_ram', False)
            self.card_ram_ext.setVisible(has_ext)
            if has_ext:
                if data.get('chip_external_ram_kb'):
                    self.txt_ram_ext_cap.setText(str(data['chip_external_ram_kb']))
                ext_name = data.get('external_ram_name', '外部扩展 RAM')
                self.lbl_ram_ext_sub.setText(f"【{ext_name} 已就绪】")
            else:
                self.lbl_ram_ext_sub.setText("")

            self.update_gauges()
            self.populate_sections()
            self.populate_symbols()
            self.populate_modules()
            self.mem_bar.set_data(data.get('sections', []))

            sym_cnt = len(data.get('symbols', []))
            sec_cnt = len(data.get('sections', []))

            if not data.get('parsed_ok', True):
                warn_msg = data.get('warning_message', '未能正确识别该文件格式！')
                self.lbl_file_info.setText(
                    f"<b>{data['file_name']}</b> <span style='color: #ef4444;'>({data['file_type']} - 格式不支持)</span><br>"
                    f"<span style='font-size: 11px; color: #ef4444; font-weight: bold;'>⚠️ {warn_msg}</span>"
                )
                self.status.showMessage(f"⚠️ {warn_msg}", 10000)
            else:
                diff_hint = " [对比基准激活中]" if self.baseline_data else ""
                self.status.showMessage(f"解析成功！共提取 {sec_cnt} 个段，{sym_cnt} 个符号。双击表格项可复制内容。{diff_hint}")

        except Exception as e:
            QMessageBox.critical(self, "解析错误", f"解析文件失败:\n{str(e)}")
            self.status.showMessage(f"解析失败: {str(e)}")

    # -------------------------------------------------------------------------
    # Populate UI Data
    # -------------------------------------------------------------------------
    def update_gauges(self):
        if not self.current_data:
            return

        base_fl = self.baseline_data.get('flash_total') if self.baseline_data else None
        base_ram = self.baseline_data.get('ram_internal_total') if self.baseline_data else None

        # 1. Flash
        flash_used = self.current_data.get('flash_total', 0)
        self.lbl_flash_val.setText(format_bytes(flash_used))
        diff_str = ""
        if base_fl is not None:
            d = flash_used - base_fl
            sign = "+" if d > 0 else ""
            diff_str = f" [基线差: {sign}{format_bytes(d)}]"
        self.lbl_flash_bytes.setText(f"({flash_used:,} 字节){diff_str}")
        self._calc_gauge(flash_used, self.txt_flash_cap, self.lbl_flash_pct, self.prog_flash, "#2563eb")

        # 2. 片内 SRAM
        ram_int_used = self.current_data.get('ram_internal_total', 0)
        self.lbl_ram_int_val.setText(format_bytes(ram_int_used))
        diff_ram_str = ""
        if base_ram is not None:
            d = ram_int_used - base_ram
            sign = "+" if d > 0 else ""
            diff_ram_str = f" [基线差: {sign}{format_bytes(d)}]"
        self.lbl_ram_int_bytes.setText(f"({ram_int_used:,} 字节){diff_ram_str}")
        self._calc_gauge(ram_int_used, self.txt_ram_int_cap, self.lbl_ram_int_pct, self.prog_ram_int, "#059669")

        # 3. 片外 RAM (PSRAM / SDRAM)
        if self.current_data.get('has_external_ram', False):
            ram_ext_used = self.current_data.get('ram_external_total', 0)
            if ram_ext_used > 0:
                self.lbl_ram_ext_val.setText(format_bytes(ram_ext_used))
                self.lbl_ram_ext_bytes.setText(f"({ram_ext_used:,} 字节)")
                self._calc_gauge(ram_ext_used, self.txt_ram_ext_cap, self.lbl_ram_ext_pct, self.prog_ram_ext, "#0891b2")
            else:
                self.lbl_ram_ext_val.setText("0 B")
                self.lbl_ram_ext_bytes.setText("(静态0B / 运行时动态堆池)")
                self.lbl_ram_ext_pct.setText("0.0 %")
                self.lbl_ram_ext_pct.setStyleSheet("font-size: 16px; font-weight: bold; color: #0891b2;")
                self.prog_ram_ext.setValue(0)
                self.prog_ram_ext.setStyleSheet("""
                    QProgressBar { background-color: #f1f5f9; border-radius: 3px; }
                    QProgressBar::chunk { background-color: #0891b2; border-radius: 3px; }
                """)

    def _calc_gauge(self, used_bytes, txt_cap_widget, lbl_pct_widget, prog_widget, normal_color="#2563eb"):
        try:
            cap_kb = float(txt_cap_widget.text().strip() or "0")
            cap_bytes = cap_kb * 1024
            if cap_bytes > 0:
                pct = (used_bytes / cap_bytes) * 100
                if pct > 100.0:
                    diff_kb = (used_bytes - cap_bytes) / 1024.0
                    lbl_pct_widget.setText(f"{pct:.1f}% (超 {diff_kb:.1f}KB)")
                    lbl_pct_widget.setStyleSheet("font-size: 13px; font-weight: bold; color: #ef4444;")
                    prog_widget.setValue(1000)
                    prog_widget.setStyleSheet("""
                        QProgressBar {
                            background-color: #fee2e2;
                            border-radius: 3px;
                        }
                        QProgressBar::chunk {
                            background-color: #ef4444;
                            border-radius: 3px;
                        }
                    """)
                elif pct > 90.0:
                    lbl_pct_widget.setText(f"{pct:.1f} % (紧缺)")
                    lbl_pct_widget.setStyleSheet("font-size: 15px; font-weight: bold; color: #f59e0b;")
                    prog_widget.setValue(min(1000, int(pct * 10)))
                    prog_widget.setStyleSheet("""
                        QProgressBar {
                            background-color: #fef3c7;
                            border-radius: 3px;
                        }
                        QProgressBar::chunk {
                            background-color: #f59e0b;
                            border-radius: 3px;
                        }
                    """)
                else:
                    lbl_pct_widget.setText(f"{pct:.1f} %")
                    lbl_pct_widget.setStyleSheet(f"font-size: 16px; font-weight: bold; color: {normal_color};")
                    prog_widget.setValue(min(1000, int(pct * 10)))
                    prog_widget.setStyleSheet(f"""
                        QProgressBar {{
                            background-color: #f1f5f9;
                            border-radius: 3px;
                        }}
                        QProgressBar::chunk {{
                            background-color: {normal_color};
                            border-radius: 3px;
                        }}
                    """)
            else:
                lbl_pct_widget.setText("- %")
                prog_widget.setValue(0)
        except ValueError:
            lbl_pct_widget.setText("- %")

    def populate_sections(self):
        self.tbl_sections.setSortingEnabled(False)
        self.tbl_sections.setRowCount(0)

        base_sec_map = {}
        if self.baseline_data:
            for s in self.baseline_data.get('sections', []):
                base_sec_map[s['name']] = s.get('size', 0)

        sections = self.current_data.get('sections', []) if self.current_data else []
        for i, s in enumerate(sections):
            row = self.tbl_sections.rowCount()
            self.tbl_sections.insertRow(row)

            cat = s.get('category', '')
            cat_color = "#334155"
            if "Flash" in cat and "RAM" not in cat:
                cat_color = "#2563eb"
            elif "片外" in cat or "PSRAM" in cat or "SDRAM" in cat:
                cat_color = "#0891b2"
            elif "片内" in cat or "SRAM" in cat or "RAM" in cat:
                cat_color = "#059669"
            elif "Dummy" in cat or "保留" in cat:
                cat_color = "#94a3b8"

            item_idx = NumericTableWidgetItem(i + 1)
            item_name = QTableWidgetItem(s['name'])
            item_name.setFont(QFont("Consolas", 10))

            item_cat = QTableWidgetItem(cat)
            item_cat.setForeground(QColor(cat_color))

            item_addr = QTableWidgetItem(s['address_hex'])
            item_addr.setFont(QFont("Consolas", 10))

            item_size = NumericTableWidgetItem(s['size'], f"{s['size']:,}")
            item_size_str = QTableWidgetItem(s['size_str'])

            # Diff Column
            sec_sz = s.get('size', 0)
            if self.baseline_data:
                old_sz = base_sec_map.get(s['name'])
                if old_sz is None:
                    item_diff = NumericTableWidgetItem(sec_sz, f"[新增] +{format_bytes(sec_sz)}")
                    item_diff.setForeground(QColor("#dc2626"))
                    item_diff.setFont(QFont("Segoe UI", 9, QFont.Bold))
                else:
                    d = sec_sz - old_sz
                    if d > 0:
                        item_diff = NumericTableWidgetItem(d, f"+{format_bytes(d)}")
                        item_diff.setForeground(QColor("#dc2626"))
                    elif d < 0:
                        item_diff = NumericTableWidgetItem(d, f"-{format_bytes(abs(d))}")
                        item_diff.setForeground(QColor("#16a34a"))
                    else:
                        item_diff = NumericTableWidgetItem(0, "-")
                        item_diff.setForeground(QColor("#94a3b8"))
            else:
                item_diff = NumericTableWidgetItem(0, "-")
                item_diff.setForeground(QColor("#94a3b8"))

            item_flags = QTableWidgetItem(s.get('flags', ''))

            for it in [item_idx, item_addr, item_size, item_diff, item_flags]:
                it.setTextAlignment(Qt.AlignCenter)

            self.tbl_sections.setItem(row, 0, item_idx)
            self.tbl_sections.setItem(row, 1, item_name)
            self.tbl_sections.setItem(row, 2, item_cat)
            self.tbl_sections.setItem(row, 3, item_addr)
            self.tbl_sections.setItem(row, 4, item_size)
            self.tbl_sections.setItem(row, 5, item_size_str)
            self.tbl_sections.setItem(row, 6, item_diff)
            self.tbl_sections.setItem(row, 7, item_flags)

        self.tbl_sections.setSortingEnabled(True)

    def populate_symbols(self):
        self.tbl_symbols.setSortingEnabled(False)
        self.tbl_symbols.setRowCount(0)

        use_demangle = self.chk_demangle.isChecked()

        base_sym_map = {}
        if self.baseline_data:
            for sym in self.baseline_data.get('symbols', []):
                base_sym_map[sym['name']] = sym.get('size', 0)

        symbols = self.current_data.get('symbols', []) if self.current_data else []
        for i, sym in enumerate(symbols):
            row = self.tbl_symbols.rowCount()
            self.tbl_symbols.insertRow(row)

            item_rank = NumericTableWidgetItem(i + 1)

            disp_name = sym.get('demangled_name', sym['name']) if use_demangle else sym['name']
            item_name = QTableWidgetItem(disp_name)
            item_name.setFont(QFont("Consolas", 10))
            if sym.get('demangled_name') != sym['name']:
                item_name.setToolTip(f"原始混淆名: {sym['name']}")

            item_type = QTableWidgetItem(sym['type'])
            if "FUNC" in sym['type']:
                item_type.setForeground(QColor("#2563eb"))
            elif "OBJECT" in sym['type']:
                item_type.setForeground(QColor("#059669"))

            item_sec = QTableWidgetItem(sym.get('section', ''))
            item_mod = QTableWidgetItem(sym.get('module', ''))
            item_addr = QTableWidgetItem(sym['address_hex'])
            item_addr.setFont(QFont("Consolas", 10))

            item_size = NumericTableWidgetItem(sym['size'], f"{sym['size']:,}")
            item_size_str = QTableWidgetItem(sym['size_str'])

            # Diff Column
            sym_sz = sym.get('size', 0)
            if self.baseline_data:
                old_sz = base_sym_map.get(sym['name'])
                if old_sz is None:
                    item_diff = NumericTableWidgetItem(sym_sz, f"[新增] +{format_bytes(sym_sz)}")
                    item_diff.setForeground(QColor("#dc2626"))
                    item_diff.setFont(QFont("Segoe UI", 9, QFont.Bold))
                else:
                    d = sym_sz - old_sz
                    if d > 0:
                        item_diff = NumericTableWidgetItem(d, f"+{format_bytes(d)}")
                        item_diff.setForeground(QColor("#dc2626"))
                    elif d < 0:
                        item_diff = NumericTableWidgetItem(d, f"-{format_bytes(abs(d))}")
                        item_diff.setForeground(QColor("#16a34a"))
                    else:
                        item_diff = NumericTableWidgetItem(0, "-")
                        item_diff.setForeground(QColor("#94a3b8"))
            else:
                item_diff = NumericTableWidgetItem(0, "-")
                item_diff.setForeground(QColor("#94a3b8"))

            for it in [item_rank, item_addr, item_size, item_diff, item_type]:
                it.setTextAlignment(Qt.AlignCenter)

            self.tbl_symbols.setItem(row, 0, item_rank)
            self.tbl_symbols.setItem(row, 1, item_name)
            self.tbl_symbols.setItem(row, 2, item_type)
            self.tbl_symbols.setItem(row, 3, item_sec)
            self.tbl_symbols.setItem(row, 4, item_mod)
            self.tbl_symbols.setItem(row, 5, item_addr)
            self.tbl_symbols.setItem(row, 6, item_size)
            self.tbl_symbols.setItem(row, 7, item_size_str)
            self.tbl_symbols.setItem(row, 8, item_diff)

        self.tbl_symbols.setSortingEnabled(True)

    def populate_modules(self):
        self.tbl_modules.setSortingEnabled(False)
        self.tbl_modules.setRowCount(0)

        modules = self.current_data.get('modules', {}) if self.current_data else {}
        for name, m in modules.items():
            row = self.tbl_modules.rowCount()
            self.tbl_modules.insertRow(row)

            item_name = QTableWidgetItem(name)
            item_name.setFont(QFont("Consolas", 10))
            item_code = NumericTableWidgetItem(m['code'], format_bytes(m['code']))
            item_ro = NumericTableWidgetItem(m['ro_data'], format_bytes(m['ro_data']))
            item_rw = NumericTableWidgetItem(m['rw_data'], format_bytes(m['rw_data']))
            item_zi = NumericTableWidgetItem(m['zi_data'], format_bytes(m['zi_data']))
            item_flash = NumericTableWidgetItem(m['flash'], format_bytes(m['flash']))
            item_flash.setForeground(QColor("#2563eb"))
            item_ram = NumericTableWidgetItem(m['ram'], format_bytes(m['ram']))
            item_ram.setForeground(QColor("#059669"))

            for it in [item_code, item_ro, item_rw, item_zi, item_flash, item_ram]:
                it.setTextAlignment(Qt.AlignCenter)

            self.tbl_modules.setItem(row, 0, item_name)
            self.tbl_modules.setItem(row, 1, item_code)
            self.tbl_modules.setItem(row, 2, item_ro)
            self.tbl_modules.setItem(row, 3, item_rw)
            self.tbl_modules.setItem(row, 4, item_zi)
            self.tbl_modules.setItem(row, 5, item_flash)
            self.tbl_modules.setItem(row, 6, item_ram)

        self.tbl_modules.setSortingEnabled(True)

    # -------------------------------------------------------------------------
    # Filtering
    # -------------------------------------------------------------------------
    def filter_sections(self):
        query = self.search_sec.text().strip().lower()
        filter_type = self.cb_sec_filter.currentText()

        for r in range(self.tbl_sections.rowCount()):
            name = self.tbl_sections.item(r, 1).text().lower()
            cat = self.tbl_sections.item(r, 2).text()
            diff_txt = self.tbl_sections.item(r, 6).text()
            flags = self.tbl_sections.item(r, 7).text()

            match_query = (query in name) if query else True
            match_filter = True
            if filter_type == "仅看 Flash 相关段":
                match_filter = "Flash" in cat
            elif filter_type == "仅看片内 RAM 段":
                match_filter = "片内" in cat or "Internal" in cat or "SRAM" in cat
            elif filter_type == "仅看片外 RAM 段":
                match_filter = "片外" in cat or "PSRAM" in cat or "SDRAM" in cat
            elif filter_type == "仅看代码段 (Exec)":
                match_filter = "X" in flags or "Code" in cat
            elif filter_type == "仅看有变动的段 (Diff)":
                match_filter = (diff_txt != "-")

            self.tbl_sections.setRowHidden(r, not (match_query and match_filter))

    def filter_symbols(self):
        query = self.search_sym.text().strip().lower()
        filter_type = self.cb_sym_type.currentText()

        for r in range(self.tbl_symbols.rowCount()):
            name = self.tbl_symbols.item(r, 1).text().lower()
            tooltip = self.tbl_symbols.item(r, 1).toolTip().lower()
            kind = self.tbl_symbols.item(r, 2).text()
            diff_txt = self.tbl_symbols.item(r, 8).text()

            match_query = (query in name or query in tooltip) if query else True
            match_filter = True
            if filter_type == "仅看函数 (Functions)":
                match_filter = "FUNC" in kind
            elif filter_type == "仅看变量 (Variables)":
                match_filter = "OBJECT" in kind
            elif filter_type == "仅看有变化的符号 (Only Changed)":
                match_filter = (diff_txt != "-")

            self.tbl_symbols.setRowHidden(r, not (match_query and match_filter))

    def filter_modules(self):
        query = self.search_mod.text().strip().lower()
        for r in range(self.tbl_modules.rowCount()):
            name = self.tbl_modules.item(r, 0).text().lower()
            self.tbl_modules.setRowHidden(r, query not in name if query else False)

    def on_table_double_clicked(self, index):
        table = self.sender()
        if isinstance(table, QTableWidget):
            name_item = table.item(index.row(), 1)
            addr_item = table.item(index.row(), 5) if table == self.tbl_symbols else table.item(index.row(), 3)
            if name_item:
                clip = QApplication.clipboard()
                clip.setText(f"{name_item.text()} ({addr_item.text() if addr_item else ''})")
                self.status.showMessage(f"已复制到剪贴板: {name_item.text()}", 3000)

    # -------------------------------------------------------------------------
    # Copy Markdown Summary
    # -------------------------------------------------------------------------
    def copy_markdown_summary(self):
        if not self.current_data:
            return
        d = self.current_data
        md = []
        md.append(f"### 📊 固件内存分析摘要: `{d['file_name']}`")
        ext_badge = f" | **外存**: {d.get('external_ram_name')}" if d.get('has_external_ram') else ""
        md.append(f"- **目标架构**: {d['arch']}{ext_badge} | **分析时间**: {time.strftime('%Y-%m-%d %H:%M:%S')}")
        md.append("")
        md.append("| 内存区域 | 当前占用 | 额定/预算上限 | 占用率 | 状态 |")
        md.append("| :--- | :--- | :--- | :--- | :--- |")

        fl = d.get('flash_total', 0)
        try:
            fl_cap_kb = float(self.txt_flash_cap.text().strip() or "0")
        except ValueError:
            fl_cap_kb = 0
        fl_cap_bytes = fl_cap_kb * 1024
        fl_pct = (fl / fl_cap_bytes * 100) if fl_cap_bytes else 0
        fl_st = "🔴 已超限" if fl_pct > 100 else ("🟡 紧缺" if fl_pct > 90 else "🟢 正常")
        diff_fl = ""
        if self.baseline_data:
            df = fl - self.baseline_data.get('flash_total', 0)
            diff_fl = f" ({'+' if df > 0 else ''}{format_bytes(df)})"
        fl_sub_label = f" ({self.lbl_flash_sub.text()})" if self.lbl_flash_sub.text() else ""
        md.append(f"| **Flash (ROM)** | {format_bytes(fl)}{diff_fl} | {fl_cap_kb:.0f} KB{fl_sub_label} | {fl_pct:.1f}% | {fl_st} |")

        ram_int = d.get('ram_internal_total', 0)
        try:
            ram_int_cap_kb = float(self.txt_ram_int_cap.text().strip() or "0")
        except ValueError:
            ram_int_cap_kb = 0
        ram_int_cap_bytes = ram_int_cap_kb * 1024
        ram_int_pct = (ram_int / ram_int_cap_bytes * 100) if ram_int_cap_bytes else 0
        ram_int_st = "🔴 已超限" if ram_int_pct > 100 else ("🟡 紧缺" if ram_int_pct > 90 else "🟢 正常")
        diff_ram = ""
        if self.baseline_data:
            dr = ram_int - self.baseline_data.get('ram_internal_total', 0)
            diff_ram = f" ({'+' if dr > 0 else ''}{format_bytes(dr)})"
        ram_sub_label = f" ({self.lbl_ram_int_sub.text()})" if self.lbl_ram_int_sub.text() else ""
        md.append(f"| **片内 SRAM** | {format_bytes(ram_int)}{diff_ram} | {ram_int_cap_kb:.0f} KB{ram_sub_label} | {ram_int_pct:.1f}% | {ram_int_st} |")

        if d.get('has_external_ram'):
            ram_ext = d.get('ram_external_total', 0)
            ext_cap = self.txt_ram_ext_cap.text()
            ext_st = "🚀 就绪" if ram_ext == 0 else "🟢 已分配"
            md.append(f"| **片外 RAM** | {format_bytes(ram_ext)} | {ext_cap} KB | - | {ext_st} |")

        md.append("")
        md.append("<details>")
        md.append("<summary>🏆 最占内存的 Top 5 函数 / 变量</summary>")
        md.append("")
        for i, s in enumerate(d.get('symbols', [])[:5]):
            name = s.get('demangled_name', s['name'])
            mod = f" (`{s.get('module')}`)" if s.get('module') else ""
            md.append(f"{i+1}. `{name}` - **{s['size_str']}** [{s['type']}]{mod}")
        md.append("")
        md.append("</details>")

        md_text = "\n".join(md)
        QApplication.clipboard().setText(md_text)
        self.status.showMessage("已复制 Markdown 摘要到剪贴板！可以直接粘贴到 PR、Issue 或聊天软件中汇报。", 4000)

    # -------------------------------------------------------------------------
    # Report Export Handlers
    # -------------------------------------------------------------------------
    def export_html(self):
        if not self.current_data:
            return
        default_name = f"{os.path.splitext(self.current_data['file_name'])[0]}_memory_report.html"
        save_path, _ = QFileDialog.getSaveFileName(self, "导出交互式 HTML 报告", default_name, "HTML 网页 (*.html)")
        if not save_path:
            return

        html_content = generate_html_content(
            self.current_data,
            self.txt_flash_cap.text(),
            self.txt_ram_int_cap.text(),
            self.txt_ram_ext_cap.text(),
            self.lbl_flash_pct.text(),
            self.lbl_ram_int_pct.text(),
            self.lbl_flash_sub.text(),
            self.lbl_ram_int_sub.text(),
            self.lbl_ram_ext_sub.text()
        )
        try:
            with open(save_path, 'w', encoding='utf-8') as f:
                f.write(html_content)
            QMessageBox.information(self, "导出成功", f"交互式 HTML 报告已成功导出至:\n{save_path}")
            self.status.showMessage(f"已导出 HTML 报告: {save_path}", 5000)
        except Exception as e:
            QMessageBox.critical(self, "导出失败", f"导出 HTML 报告失败: {e}")

    def export_csv(self):
        if not self.current_data:
            return
        default_name = f"{os.path.splitext(self.current_data['file_name'])[0]}_symbols.csv"
        save_path, _ = QFileDialog.getSaveFileName(self, "导出 CSV 报表", default_name, "CSV 表格 (*.csv)")
        if not save_path:
            return

        try:
            with open(save_path, 'w', newline='', encoding='utf-8-sig') as f:
                writer = csv.writer(f)
                writer.writerow(["排名", "符号名称", "C++还原名", "类型", "所属段", "所属模块/源文件", "虚拟地址", "大小(字节)", "格式化大小"])
                for i, sym in enumerate(self.current_data.get('symbols', [])):
                    writer.writerow([
                        i + 1,
                        sym['name'],
                        sym.get('demangled_name', sym['name']),
                        sym['type'],
                        sym.get('section', ''),
                        sym.get('module', ''),
                        sym['address_hex'],
                        sym['size'],
                        sym['size_str']
                    ])
            QMessageBox.information(self, "导出成功", f"CSV 报表已成功导出（UTF-8 带BOM，Excel直接打开不乱码）:\n{save_path}")
            self.status.showMessage(f"已导出 CSV 报表: {save_path}", 5000)
        except Exception as e:
            QMessageBox.critical(self, "导出失败", f"导出 CSV 失败: {e}")

    def export_json(self):
        if not self.current_data:
            return
        default_name = f"{os.path.splitext(self.current_data['file_name'])[0]}_analysis.json"
        save_path, _ = QFileDialog.getSaveFileName(self, "导出 JSON 数据", default_name, "JSON 数据 (*.json)")
        if not save_path:
            return

        try:
            with open(save_path, 'w', encoding='utf-8') as f:
                json.dump(self.current_data, f, ensure_ascii=False, indent=2)
            QMessageBox.information(self, "导出成功", f"全量 JSON 分析数据已成功保存至:\n{save_path}")
            self.status.showMessage(f"已导出 JSON 数据: {save_path}", 5000)
        except Exception as e:
            QMessageBox.critical(self, "导出失败", f"导出 JSON 失败: {e}")


def handle_cli_mode(argv: List[str]):
    """Run in Headless CLI Mode without creating a Qt window. Suitable for CI/CD."""
    parser = argparse.ArgumentParser(
        prog="FirmwareMemoryVisualizer",
        description="嵌入式固件内存分析器 CLI 模式 (Headless / CI / CD)"
    )
    parser.add_argument("file", nargs="?", help="待分析的固件文件 (.elf / .axf / .out / .map)")
    parser.add_argument("--cli", action="store_true", help="启用无头 CLI 模式输出")
    parser.add_argument("--max-flash", type=float, help="设置 Flash 允许的最大预算上限 (KB)")
    parser.add_argument("--max-ram", type=float, help="设置片内 SRAM 允许的最大预算上限 (KB)")
    parser.add_argument("--diff", help="指定对比基线固件进行增减分析")
    parser.add_argument("--json", action="store_true", help="输出全量结构化 JSON 数据到标准输出")
    parser.add_argument("--export-html", help="直接输出 HTML 报告到指定文件路径")
    parser.add_argument("--export-csv", help="直接输出 CSV 报表到指定文件路径")

    args = parser.parse_args(argv[1:])

    if not args.file:
        parser.print_help()
        sys.exit(0)

    if not os.path.exists(args.file):
        print(f"[ERROR] 文件不存在: {args.file}", file=sys.stderr)
        sys.exit(1)

    data = FirmwareParser.parse_file(args.file)
    baseline_data = FirmwareParser.parse_file(args.diff) if (args.diff and os.path.exists(args.diff)) else None

    # Handle JSON output
    if args.json:
        print(json.dumps(data, ensure_ascii=False, indent=2))
        sys.exit(0)

    # Handle HTML export
    if args.export_html:
        html_code = generate_html_content(
            data,
            str(data.get('chip_flash_kb', 512)),
            str(data.get('chip_internal_ram_kb', 128)),
            str(data.get('chip_external_ram_kb', 8192)),
            f"{(data.get('flash_total', 0)/(data.get('chip_flash_kb', 512)*1024))*100:.1f}%",
            f"{(data.get('ram_internal_total', 0)/(data.get('chip_internal_ram_kb', 128)*1024))*100:.1f}%",
            data.get('flash_sub_note', ''),
            data.get('ram_int_note', ''),
            f"【{data.get('external_ram_name','外存')} 已就绪】" if data.get('has_external_ram') else ''
        )
        with open(args.export_html, 'w', encoding='utf-8') as f:
            f.write(html_code)
        print(f"[SUCCESS] HTML 报告已导出至: {args.export_html}")

    # Handle CSV export
    if args.export_csv:
        with open(args.export_csv, 'w', newline='', encoding='utf-8-sig') as f:
            writer = csv.writer(f)
            writer.writerow(["排名", "符号名称", "C++还原名", "类型", "所属段", "所属模块/源文件", "虚拟地址", "大小(字节)", "格式化大小"])
            for i, sym in enumerate(data.get('symbols', [])):
                writer.writerow([
                    i + 1,
                    sym['name'],
                    sym.get('demangled_name', sym['name']),
                    sym['type'],
                    sym.get('section', ''),
                    sym.get('module', ''),
                    sym['address_hex'],
                    sym['size'],
                    sym['size_str']
                ])
        print(f"[SUCCESS] CSV 报表已导出至: {args.export_csv}")

    fl = data.get('flash_total', 0)
    ram_int = data.get('ram_internal_total', 0)
    ram_ext = data.get('ram_external_total', 0)

    fl_cap_kb = args.max_flash or data.get('chip_flash_kb', 512)
    ram_cap_kb = args.max_ram or data.get('chip_internal_ram_kb', 128)

    fl_pct = (fl / (fl_cap_kb * 1024)) * 100 if fl_cap_kb else 0
    ram_pct = (ram_int / (ram_cap_kb * 1024)) * 100 if ram_cap_kb else 0

    print("=" * 72)
    print("  Firmware Memory Visualizer (CLI Mode)")
    print("=" * 72)
    print(f"File:       {data['file_name']} ({data['file_type']})")
    print(f"Target:     {data['arch']} | Entry: 0x{data.get('entry', 0):08X}")
    if data.get('flash_sub_note'):
        print(f"Flash Note: {data.get('flash_sub_note')}")
    if data.get('ram_int_note'):
        print(f"RAM Note:   {data.get('ram_int_note')}")
    if data.get('has_external_ram'):
        print(f"Ext RAM:    {data.get('external_ram_name')}")
    print("-" * 72)

    # Flash check
    fl_overflow = fl > fl_cap_kb * 1024
    fl_status = "FAIL [OVERFLOW]" if fl_overflow else "PASS"
    diff_fl_str = ""
    if baseline_data:
        d = fl - baseline_data.get('flash_total', 0)
        diff_fl_str = f" [Diff: {'+' if d > 0 else ''}{format_bytes(d)}]"
    print(f"Flash:      {format_bytes(fl):>10} ({fl:,} B) / {fl_cap_kb:.0f} KB ({fl_pct:5.1f}%){diff_fl_str} [{fl_status}]")

    # RAM check
    ram_overflow = ram_int > ram_cap_kb * 1024
    ram_status = "FAIL [OVERFLOW]" if ram_overflow else "PASS"
    diff_ram_str = ""
    if baseline_data:
        d = ram_int - baseline_data.get('ram_internal_total', 0)
        diff_ram_str = f" [Diff: {'+' if d > 0 else ''}{format_bytes(d)}]"
    print(f"SRAM:       {format_bytes(ram_int):>10} ({ram_int:,} B) / {ram_cap_kb:.0f} KB ({ram_pct:5.1f}%){diff_ram_str} [{ram_status}]")

    if data.get('has_external_ram'):
        print(f"Ext RAM:    {format_bytes(ram_ext):>10} ({ram_ext:,} B) / {data.get('chip_external_ram_kb', 8192)} KB (Ready)")

    print("-" * 72)
    print("Top 5 Symbols:")
    for i, s in enumerate(data.get('symbols', [])[:5]):
        name = s.get('demangled_name', s['name'])
        mod = f" ({s.get('module')})" if s.get('module') else ""
        print(f"  {i+1}. {name:<36} {s['size_str']:>9} [{s['type']}]{mod}")
    print("=" * 72)

    if fl_overflow or ram_overflow:
        reasons = []
        if fl_overflow:
            reasons.append(f"Flash ({format_bytes(fl)}) 超出预算 ({fl_cap_kb:.0f} KB)")
        if ram_overflow:
            reasons.append(f"SRAM ({format_bytes(ram_int)}) 超出预算 ({ram_cap_kb:.0f} KB)")
        print(f"RESULT: FAILED! {', '.join(reasons)}")
        sys.exit(1)
    else:
        print(f"RESULT: PASSED! 内存占用在预算范围内。")
        sys.exit(0)


def main():
    # Check for Headless CLI mode arguments first
    cli_flags = ['--cli', '-c', '--json', '--export-html', '--export-csv', '--help', '-h', '--max-flash', '--max-ram']
    if any(arg in sys.argv for arg in cli_flags):
        handle_cli_mode(sys.argv)
        return

    if sys.platform == 'win32':
        try:
            import ctypes
            ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID('mytools.firmwarememvisualizer.app.1.0')
        except Exception:
            pass

    QApplication.setAttribute(Qt.AA_EnableHighDpiScaling, True)
    QApplication.setAttribute(Qt.AA_UseHighDpiPixmaps, True)

    app = QApplication(sys.argv)
    app.setApplicationName("FirmwareMemoryVisualizer")

    icon_path = get_resource_path('app_icon.ico')
    if os.path.exists(icon_path):
        app_icon = QIcon(icon_path)
        app.setWindowIcon(app_icon)

    window = MainWindow()
    if os.path.exists(icon_path):
        window.setWindowIcon(QIcon(icon_path))
    window.show()

    if len(sys.argv) > 1 and os.path.exists(sys.argv[1]):
        window.load_file(sys.argv[1])

    sys.exit(app.exec_())


if __name__ == '__main__':
    main()
