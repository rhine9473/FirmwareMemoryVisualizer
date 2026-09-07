"""
Firmware Memory Visualizer - Native Desktop GUI (PyQt5)
Universal memory allocation analyzer for ELF, AXF and MAP files.
Supports internal SRAM and external PSRAM/SDRAM visual split.
"""

import os
import sys
from typing import Optional, Dict, Any

from PyQt5.QtCore import Qt, QSize, QRectF
from PyQt5.QtGui import (
    QColor, QFont, QIcon, QPainter, QBrush, QPen,
    QDragEnterEvent, QDropEvent
)
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QPushButton, QFileDialog, QTabWidget, QTableWidget,
    QTableWidgetItem, QHeaderView, QLineEdit, QComboBox, QProgressBar,
    QFrame, QStatusBar, QMessageBox, QAbstractItemView
)

from parser import FirmwareParser, format_bytes


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
        self.init_ui()

    def init_ui(self):
        self.setWindowTitle("嵌入式固件内存可视化分析器 (Firmware Memory Visualizer)")

        screen = QApplication.primaryScreen()
        if screen:
            avail = screen.availableGeometry()
            w = min(1080, max(820, int(avail.width() * 0.76)))
            h = min(640, max(480, int(avail.height() * 0.72)))
            self.resize(w, h)
            self.setMinimumSize(780, 460)
            self.move(avail.x() + (avail.width() - w) // 2, avail.y() + (avail.height() - h) // 2)
        else:
            self.resize(1000, 600)
            self.setMinimumSize(780, 460)

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

        self.lbl_file_info = QLabel("请将 <b>.elf</b>、<b>.axf</b> 或 <b>.map</b> 固件文件拖入窗口，或点击右侧按钮打开")
        self.lbl_file_info.setStyleSheet("font-size: 13px; color: #1e293b;")
        top_layout.addWidget(self.lbl_file_info, stretch=1)

        btn_open = QPushButton("📂 打开固件 / Map 文件")
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

        main_layout.addWidget(top_box)

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
        self.card_ram_ext.setVisible(False)  # Hidden until external RAM is detected
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
        self.cb_sec_filter.addItems(["显示全部段", "仅看 Flash 相关段", "仅看片内 RAM 段", "仅看片外 RAM 段", "仅看代码段 (Exec)"])
        self.cb_sec_filter.currentIndexChanged.connect(self.filter_sections)
        sec_ctrl.addWidget(self.cb_sec_filter)
        sec_layout.addLayout(sec_ctrl)

        self.tbl_sections = QTableWidget()
        self.tbl_sections.setColumnCount(7)
        self.tbl_sections.setHorizontalHeaderLabels([
            "序号", "段名称 (Section)", "内存归属类别", "虚拟地址 (VMA)", "大小 (字节)", "格式化大小", "属性 Flags"
        ])
        self.tbl_sections.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.tbl_sections.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.tbl_sections.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeToContents)
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
        self.search_sym.setPlaceholderText("🔍 搜索函数名或全局变量名 (支持实时模糊匹配)...")
        self.search_sym.textChanged.connect(self.filter_symbols)
        sym_ctrl.addWidget(self.search_sym, stretch=1)

        self.cb_sym_type = QComboBox()
        self.cb_sym_type.addItems(["全部符号", "仅看函数 (Functions)", "仅看变量 (Variables)"])
        self.cb_sym_type.currentIndexChanged.connect(self.filter_symbols)
        sym_ctrl.addWidget(self.cb_sym_type)
        sym_layout.addLayout(sym_ctrl)

        self.tbl_symbols = QTableWidget()
        self.tbl_symbols.setColumnCount(7)
        self.tbl_symbols.setHorizontalHeaderLabels([
            "排名", "符号名称 (Symbol)", "类型", "所属段 (Section)", "虚拟地址 (VMA)", "大小 (字节)", "格式化大小"
        ])
        self.tbl_symbols.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.tbl_symbols.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.tbl_symbols.horizontalHeader().setSectionResizeMode(5, QHeaderView.ResizeToContents)
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
        self.search_mod.setPlaceholderText("🔍 过滤源文件或库模块名称...")
        self.search_mod.textChanged.connect(self.filter_modules)
        mod_layout.addWidget(self.search_mod)

        self.tbl_modules = QTableWidget()
        self.tbl_modules.setColumnCount(7)
        self.tbl_modules.setHorizontalHeaderLabels([
            "目标模块 / 文件", "Code 代码", "RO 数据", "RW 数据", "ZI 数据", "总 Flash", "总 RAM"
        ])
        self.tbl_modules.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.tbl_modules.setSortingEnabled(True)
        self.tbl_modules.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.tbl_modules.setEditTriggers(QAbstractItemView.NoEditTriggers)
        mod_layout.addWidget(self.tbl_modules)
        self.tabs.addTab(tab_mod, "📦 模块 / 目标文件分析 (Modules)")

        main_layout.addWidget(self.tabs, stretch=1)

        # Status Bar
        self.status = QStatusBar()
        self.setStatusBar(self.status)
        self.status.showMessage("就绪。直接拖入 .elf / .axf / .map 文件即可瞬间完成全量分析。双击任意行可复制符号信息。")

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

        lbl_cap = QLabel("额定:")
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
                self.status.showMessage(f"解析成功！共提取 {sec_cnt} 个段，{sym_cnt} 个符号。双击任意表格项可复制内容。")

        except Exception as e:
            QMessageBox.critical(self, "解析错误", f"解析文件失败:\n{str(e)}")
            self.status.showMessage(f"解析失败: {str(e)}")

    # -------------------------------------------------------------------------
    # Populate UI Data
    # -------------------------------------------------------------------------
    def update_gauges(self):
        if not self.current_data:
            return

        # 1. Flash
        flash_used = self.current_data.get('flash_total', 0)
        self.lbl_flash_val.setText(format_bytes(flash_used))
        self.lbl_flash_bytes.setText(f"({flash_used:,} 字节)")
        self._calc_gauge(flash_used, self.txt_flash_cap, self.lbl_flash_pct, self.prog_flash, "#2563eb")

        # 2. 片内 SRAM
        ram_int_used = self.current_data.get('ram_internal_total', 0)
        self.lbl_ram_int_val.setText(format_bytes(ram_int_used))
        self.lbl_ram_int_bytes.setText(f"({ram_int_used:,} 字节)")
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

        sections = self.current_data.get('sections', [])
        for i, s in enumerate(sections):
            row = self.tbl_sections.rowCount()
            self.tbl_sections.insertRow(row)

            cat = s.get('category', '')
            cat_color = "#334155"
            if "Flash" in cat:
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
            item_flags = QTableWidgetItem(s.get('flags', ''))

            for it in [item_idx, item_addr, item_size, item_flags]:
                it.setTextAlignment(Qt.AlignCenter)

            self.tbl_sections.setItem(row, 0, item_idx)
            self.tbl_sections.setItem(row, 1, item_name)
            self.tbl_sections.setItem(row, 2, item_cat)
            self.tbl_sections.setItem(row, 3, item_addr)
            self.tbl_sections.setItem(row, 4, item_size)
            self.tbl_sections.setItem(row, 5, item_size_str)
            self.tbl_sections.setItem(row, 6, item_flags)

        self.tbl_sections.setSortingEnabled(True)

    def populate_symbols(self):
        self.tbl_symbols.setSortingEnabled(False)
        self.tbl_symbols.setRowCount(0)

        symbols = self.current_data.get('symbols', [])
        for i, sym in enumerate(symbols):
            row = self.tbl_symbols.rowCount()
            self.tbl_symbols.insertRow(row)

            item_rank = NumericTableWidgetItem(i + 1)
            item_name = QTableWidgetItem(sym['name'])
            item_name.setFont(QFont("Consolas", 10))

            item_type = QTableWidgetItem(sym['type'])
            if "FUNC" in sym['type']:
                item_type.setForeground(QColor("#2563eb"))
            elif "OBJECT" in sym['type']:
                item_type.setForeground(QColor("#059669"))

            item_sec = QTableWidgetItem(sym.get('section', ''))
            item_addr = QTableWidgetItem(sym['address_hex'])
            item_addr.setFont(QFont("Consolas", 10))

            item_size = NumericTableWidgetItem(sym['size'], f"{sym['size']:,}")
            item_size_str = QTableWidgetItem(sym['size_str'])

            for it in [item_rank, item_addr, item_size, item_type]:
                it.setTextAlignment(Qt.AlignCenter)

            self.tbl_symbols.setItem(row, 0, item_rank)
            self.tbl_symbols.setItem(row, 1, item_name)
            self.tbl_symbols.setItem(row, 2, item_type)
            self.tbl_symbols.setItem(row, 3, item_sec)
            self.tbl_symbols.setItem(row, 4, item_addr)
            self.tbl_symbols.setItem(row, 5, item_size)
            self.tbl_symbols.setItem(row, 6, item_size_str)

        self.tbl_symbols.setSortingEnabled(True)

    def populate_modules(self):
        self.tbl_modules.setSortingEnabled(False)
        self.tbl_modules.setRowCount(0)

        modules = self.current_data.get('modules', {})
        for name, m in modules.items():
            row = self.tbl_modules.rowCount()
            self.tbl_modules.insertRow(row)

            item_name = QTableWidgetItem(name)
            item_code = NumericTableWidgetItem(m['code'], format_bytes(m['code']))
            item_ro = NumericTableWidgetItem(m['ro_data'], format_bytes(m['ro_data']))
            item_rw = NumericTableWidgetItem(m['rw_data'], format_bytes(m['rw_data']))
            item_zi = NumericTableWidgetItem(m['zi_data'], format_bytes(m['zi_data']))
            item_flash = NumericTableWidgetItem(m['flash'], format_bytes(m['flash']))
            item_ram = NumericTableWidgetItem(m['ram'], format_bytes(m['ram']))

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
            flags = self.tbl_sections.item(r, 6).text()

            match_query = (query in name) if query else True
            match_filter = True
            if filter_type == "仅看 Flash 相关段":
                match_filter = "Flash" in cat
            elif filter_type == "仅看片内 RAM 段":
                match_filter = "片内" in cat or "Internal" in cat or "SRAM" in cat
            elif filter_type == "仅看片外 RAM 段":
                match_filter = "片外" in cat or "PSRAM" in cat or "SDRAM" in cat
            elif filter_type == "仅看代码段 (Exec)":
                match_filter = "X" in flags

            self.tbl_sections.setRowHidden(r, not (match_query and match_filter))

    def filter_symbols(self):
        query = self.search_sym.text().strip().lower()
        filter_type = self.cb_sym_type.currentText()

        for r in range(self.tbl_symbols.rowCount()):
            name = self.tbl_symbols.item(r, 1).text().lower()
            kind = self.tbl_symbols.item(r, 2).text()

            match_query = (query in name) if query else True
            match_filter = True
            if filter_type == "仅看函数 (Functions)":
                match_filter = "FUNC" in kind
            elif filter_type == "仅看变量 (Variables)":
                match_filter = "OBJECT" in kind

            self.tbl_symbols.setRowHidden(r, not (match_query and match_filter))

    def filter_modules(self):
        query = self.search_mod.text().strip().lower()
        for r in range(self.tbl_modules.rowCount()):
            name = self.tbl_modules.item(r, 0).text().lower()
            self.tbl_modules.setRowHidden(r, query not in name if query else False)

    def on_table_double_clicked(self, index):
        table = self.sender()
        if isinstance(table, QTableWidget):
            item = table.item(index.row(), 1)
            addr_item = table.item(index.row(), index.column())
            if item:
                clip = QApplication.clipboard()
                clip.setText(f"{item.text()} ({addr_item.text() if addr_item else ''})")
                self.status.showMessage(f"已复制到剪贴板: {item.text()}", 3000)


def get_resource_path(relative_path):
    base_path = getattr(sys, '_MEIPASS', os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base_path, relative_path)


def main():
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
