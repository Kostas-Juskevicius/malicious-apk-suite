#!/usr/bin/env python3
import sys
from pathlib import Path
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QTabWidget, 
    QVBoxLayout, QHBoxLayout, QWidget, QPushButton,
    QLineEdit, QLabel, QMessageBox, QPlainTextEdit, QTextEdit
)
from PyQt6.QtGui import (
    QFont, QColor, QPalette, QTextCursor, QKeySequence,
    QTextCharFormat, QPainter, QPaintEvent, QFontMetrics
)
from PyQt6.QtCore import Qt, QEvent, QObject, QRect, QSize

# ---------- Horizontal scroll filter (unchanged) ----------
class HorizontalScrollFilter(QObject):
    """Event filter for shift+scroll horizontal scrolling"""
    def __init__(self, parent):
        super().__init__(parent)
        self.parent = parent
        
    def eventFilter(self, obj, event):
        if event.type() == QEvent.Type.Wheel:
            if event.modifiers() & Qt.KeyboardModifier.ShiftModifier:
                text_edit = self.parent
                h_scroll = text_edit.horizontalScrollBar()
                delta = event.angleDelta().y()
                h_scroll.setValue(h_scroll.value() - delta)
                return True
        return False

# ---------- Custom scrollbar that can draw markers ----------
from PyQt6.QtWidgets import QScrollBar
class MarkerScrollBar(QScrollBar):
    def __init__(self, orientation=Qt.Orientation.Vertical, parent=None):
        super().__init__(orientation, parent)
        self._marker_blocks = []    # list of block indices (ints)
        self._total_blocks = 1

    def set_markers(self, block_indices, total_blocks):
        """block_indices: list of ints, total_blocks: int"""
        self._marker_blocks = block_indices or []
        self._total_blocks = max(1, total_blocks)
        self.update()

    def paintEvent(self, event: QPaintEvent):
        # First let the base scrollbar draw itself
        super().paintEvent(event)
        if not self._marker_blocks:
            return
        
        painter = QPainter(self)
        painter.setPen(Qt.PenStyle.NoPen)
        brush_color = QColor(255, 165, 0, 180)  # semi transparent orange
        painter.setBrush(brush_color)
        
        w = self.width()
        h = self.height()
        # markers will be narrow rectangles centered horizontally
        marker_w = max(3, int(w * 0.6))
        marker_h = 6
        
        # We'll map block index -> y on the scrollbar area
        for block in self._marker_blocks:
            # clamp block index
            b = min(max(0, block), self._total_blocks - 1)
            if self._total_blocks <= 1:
                pos_y = h // 2
            else:
                pos_y = int((b / (self._total_blocks - 1)) * (h - marker_h))
            x = (w - marker_w) // 2
            rect = QRect(x, pos_y, marker_w, marker_h)
            painter.drawRect(rect)
        painter.end()

# ---------- Line number area & CodeEditor ----------
from PyQt6.QtWidgets import QWidget

class LineNumberArea(QWidget):
    def __init__(self, editor):
        super().__init__(editor)
        self.code_editor = editor

    def sizeHint(self):
        return QSize(self.code_editor.line_number_area_width(), 0)

    def paintEvent(self, event):
        self.code_editor.line_number_area_paint_event(event)

class CodeEditor(QPlainTextEdit):
    def __init__(self, parent=None):
        super().__init__(parent)
        # Use monospace
        self.setFont(QFont("Courier New", 13))
        self.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)

        # Line number area
        self.lineNumberArea = LineNumberArea(self)
        self.blockCountChanged.connect(self.update_line_number_area_width)
        self.updateRequest.connect(self.update_line_number_area)
        self.cursorPositionChanged.connect(self.highlight_current_line)

        # Replace default vertical scrollbar with our marker scrollbar
        self.setVerticalScrollBar(MarkerScrollBar(Qt.Orientation.Vertical, self))

        # For highlighting search matches
        self._match_blocks = []

        # Install horizontal scroll filter (for shift+wheel)
        scroll_filter = HorizontalScrollFilter(self)
        self.viewport().installEventFilter(scroll_filter)

        self.update_line_number_area_width(0)
        self.highlight_current_line()

    def line_number_area_width(self):
        digits = max(2, len(str(max(1, self.blockCount()))))
        space = 12 + self.fontMetrics().horizontalAdvance('9') * digits
        return space

    def update_line_number_area_width(self, _):
        self.setViewportMargins(self.line_number_area_width(), 0, 0, 0)

    def update_line_number_area(self, rect, dy):
        if dy:
            self.lineNumberArea.scroll(0, dy)
        else:
            self.lineNumberArea.update(0, rect.y(), self.lineNumberArea.width(), rect.height())

        if rect.contains(self.viewport().rect()):
            self.update_line_number_area_width(0)

    def resizeEvent(self, event):
        super().resizeEvent(event)
        cr = self.contentsRect()
        self.lineNumberArea.setGeometry(cr.x(), cr.y(), self.line_number_area_width(), cr.height())

    def line_number_area_paint_event(self, event):
        painter = QPainter(self.lineNumberArea)
        painter.fillRect(event.rect(), QColor(45, 45, 48))  # gutter background

        block = self.firstVisibleBlock()
        block_number = block.blockNumber()
        top = int(self.blockBoundingGeometry(block).translated(self.contentOffset()).top())
        bottom = top + int(self.blockBoundingRect(block).height())

        font = self.font()
        painter.setFont(font)
        fm = QFontMetrics(font)
        painter.setPen(QColor(160, 160, 160))

        # iterate visible blocks
        while block.isValid() and top <= event.rect().bottom():
            if block.isVisible() and bottom >= event.rect().top():
                number = str(block_number + 1)
                # right-align
                painter.drawText(0, top, self.lineNumberArea.width() - 6, fm.height(),
                                 Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter, number)

            block = block.next()
            top = bottom
            bottom = top + int(self.blockBoundingRect(block).height())
            block_number += 1
        painter.end()

    def highlight_current_line(self):
        selection = QTextEdit.ExtraSelection()
        line_color = QColor(255, 255, 255, 20)  # subtle
        selection.format.setBackground(line_color)
        selection.format.setProperty(QTextCharFormat.Property.FullWidthSelection, True)
        selection.cursor = self.textCursor()
        selection.cursor.clearSelection()
        self.setExtraSelections([selection] + self._create_match_selections())

    def _create_match_selections(self):
        """Return list of ExtraSelection for existing matches (so current-line highlight can be combined)."""
        selections = []
        # kept for compatibility; actual matches are set in highlight_all_matches
        return []

    def highlight_all_matches(self, search_text):
        """Highlight all occurrences and return a list of block indices where matches are found."""
        # Reset matches
        self._match_blocks = []
        extra_selections = []

        if not search_text:
            # remove highlights
            self.setExtraSelections([])
            # clear markers on scrollbar
            self.verticalScrollBar().set_markers([], self.blockCount())
            return []

        # highlight format (semi-transparent orange)
        highlight_format = QTextCharFormat()
        highlight_format.setBackground(QColor(255, 165, 0, 100))

        # Iterate through document to find all matches
        doc = self.document()
        cursor = QTextCursor(doc)
        cursor.movePosition(QTextCursor.MoveOperation.Start)

        while True:
            found_cursor = doc.find(search_text, cursor)
            if found_cursor.isNull():
                break
            # create selection
            sel = QTextEdit.ExtraSelection()
            sel.cursor = found_cursor
            sel.format = highlight_format
            extra_selections.append(sel)

            # record block number (line) for scrollbar marker
            block_num = found_cursor.blockNumber()
            if block_num not in self._match_blocks:
                self._match_blocks.append(block_num)

            # move cursor forward
            cursor = found_cursor

        # Also keep the current-line highlight; highlight_current_line will combine them
        # But QPlainTextEdit.setExtraSelections replaces all selections, so we need to include current-line selection here
        current_line_sel = QTextEdit.ExtraSelection()
        current_line_sel.format.setBackground(QColor(255, 255, 255, 20))
        current_line_sel.format.setProperty(QTextCharFormat.Property.FullWidthSelection, True)
        current_line_sel.cursor = self.textCursor()
        current_line_sel.cursor.clearSelection()

        combined = [current_line_sel] + extra_selections
        self.setExtraSelections(combined)

        # Update scrollbar markers
        self.verticalScrollBar().set_markers(self._match_blocks, self.blockCount())
        return self._match_blocks

    # convenience find that wraps and returns whether found
    def find_next(self, text):
        if not text:
            return False
        found = self.find(text)
        if not found:
            # wrap
            cursor = self.textCursor()
            cursor.movePosition(QTextCursor.MoveOperation.Start)
            self.setTextCursor(cursor)
            found = self.find(text)
        # ensure visible
        if found:
            self.ensureCursorVisible()
        return found

    def find_previous(self, text):
        if not text:
            return False
        found = self.find(text, QTextDocument.FindFlag.FindBackward)
        if not found:
            cursor = self.textCursor()
            cursor.movePosition(QTextCursor.MoveOperation.End)
            self.setTextCursor(cursor)
            found = self.find(text, QTextDocument.FindFlag.FindBackward)
        if found:
            self.ensureCursorVisible()
        return found

# ---------- ResultViewer (main window) ----------
from PyQt6.QtGui import QShortcut

class ResultViewer(QMainWindow):
    def __init__(self, results_dir="results"):
        super().__init__()
        self.results_dir = Path(results_dir)
        self.cheatsheet_file = Path("python/resources/permission_cheatsheet.txt")
        self.results = {}
        self.text_widgets = {}
        self.original_contents = {}
        self.cheatsheet_widget = None
        
        self.init_ui()
        self.load_results()
        self.load_cheatsheet()
        
    def init_ui(self):
        self.setWindowTitle("APK Analysis Results")
        self.setGeometry(100, 100, 1200, 800)
        
        # Dark theme
        self.set_dark_theme()
        
        # Central widget
        central = QWidget()
        self.setCentralWidget(central)
        layout = QVBoxLayout(central)
        
        # Top bar with controls
        top_bar = QHBoxLayout()
        
        # Left: compact search area (short search box + prev/next)
        search_label = QLabel("Search:")
        self.search_box = QLineEdit()
        self.search_box.setPlaceholderText("Search in current tab...")
        self.search_box.setMaximumWidth(280)
        self.search_box.returnPressed.connect(self.find_next)
        self.search_box.textChanged.connect(self.on_search_changed)
        
        self.prev_btn = QPushButton("◄")
        self.prev_btn.setToolTip("Previous match (Shift+Enter)")
        self.prev_btn.clicked.connect(self.find_previous)
        
        self.next_btn = QPushButton("►")
        self.next_btn.setToolTip("Next match (Enter)")
        self.next_btn.clicked.connect(self.find_next)
        
        # Ctrl+F focuses search
        search_shortcut = QShortcut(QKeySequence("Ctrl+F"), self)
        search_shortcut.activated.connect(self.focus_search)
        
        left_group = QHBoxLayout()
        left_group.addWidget(search_label)
        left_group.addWidget(self.search_box)
        left_group.addWidget(self.prev_btn)
        left_group.addWidget(self.next_btn)
        
        # Right: action buttons
        copy_btn = QPushButton("Copy Tab")
        copy_btn.clicked.connect(self.copy_current_tab)
        top_btn = QPushButton("Top ↑")
        top_btn.clicked.connect(self.scroll_to_top)
        bottom_btn = QPushButton("Bottom ↓")
        bottom_btn.clicked.connect(self.scroll_to_bottom)
        
        right_group = QHBoxLayout()
        right_group.addWidget(copy_btn)
        right_group.addWidget(top_btn)
        right_group.addWidget(bottom_btn)
        
        # assemble top bar with space between
        top_bar.addLayout(left_group)
        top_bar.addStretch()
        top_bar.addLayout(right_group)
        
        layout.addLayout(top_bar)
        
        # Tab widget
        self.tabs = QTabWidget()
        self.tabs.currentChanged.connect(self.on_tab_changed)
        layout.addWidget(self.tabs)
        
        # Status bar
        self.statusBar().showMessage("Ready")
        
    def focus_search(self):
        """Focus search box and select all text"""
        self.search_box.setFocus()
        self.search_box.selectAll()
        
    def set_dark_theme(self):
        """Apply dark theme"""
        palette = QPalette()
        palette.setColor(QPalette.ColorRole.Window, QColor(30, 30, 30))
        palette.setColor(QPalette.ColorRole.WindowText, QColor(212, 212, 212))
        palette.setColor(QPalette.ColorRole.Base, QColor(25, 25, 25))
        palette.setColor(QPalette.ColorRole.AlternateBase, QColor(45, 45, 48))
        palette.setColor(QPalette.ColorRole.Text, QColor(212, 212, 212))
        palette.setColor(QPalette.ColorRole.Button, QColor(45, 45, 48))
        palette.setColor(QPalette.ColorRole.ButtonText, QColor(212, 212, 212))
        palette.setColor(QPalette.ColorRole.Highlight, QColor(0, 122, 204))
        palette.setColor(QPalette.ColorRole.HighlightedText, QColor(255, 255, 255))
        
        self.setPalette(palette)
        
        self.setStyleSheet("""
            QTabWidget::pane {
                border: 1px solid #3e3e42;
                background: #1e1e1e;
            }
            QTabBar::tab {
                background: #2d2d30;
                color: #d4d4d4;
                padding: 8px 16px;
                margin-right: 2px;
            }
            QTabBar::tab:selected {
                background: #1e1e1e;
                color: #007acc;
                border-bottom: 2px solid #007acc;
            }
            QTabBar::tab:hover {
                background: #3e3e42;
            }
            QPushButton {
                background: #0e639c;
                color: white;
                border: none;
                padding: 6px 10px;
                border-radius: 3px;
            }
            QPushButton:hover {
                background: #1177bb;
            }
            QPushButton:pressed {
                background: #007acc;
            }
            QLineEdit {
                background: #3c3c3c;
                color: #d4d4d4;
                border: 1px solid #555;
                padding: 4px 8px;
                border-radius: 3px;
            }
            QLineEdit:focus {
                border: 1px solid #007acc;
            }
            QPlainTextEdit {
                background: #1e1e1e;
                color: #d4d4d4;
                border: 1px solid #3e3e42;
                font-family: 'Courier New', monospace;
            }
        """)
        
    def load_cheatsheet(self):
        """Load permission cheatsheet as a separate tab"""
        if not self.cheatsheet_file.exists():
            print(f"[*] Cheatsheet file not found: {self.cheatsheet_file}")
            return
        
        try:
            with open(self.cheatsheet_file, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # Create CodeEditor widget for cheatsheet
            text_edit = CodeEditor()
            text_edit.setReadOnly(True)
            text_edit.setPlainText(content)
            text_edit.setFont(QFont("Courier New", 14))
            
            # Store reference
            self.cheatsheet_widget = text_edit
            self.text_widgets['cheatsheet'] = text_edit
            self.original_contents['cheatsheet'] = content
            self.results['cheatsheet'] = content
            
            # Add as first tab
            self.tabs.insertTab(0, text_edit, "Permission Cheatsheet")
            
            print(f"[*] Loaded cheatsheet from {self.cheatsheet_file}")
            
        except Exception as e:
            print(f"[*] Error loading cheatsheet: {e}")

    def load_results(self):
        """Load all result files from the results directory"""
        if not self.results_dir.exists():
            QMessageBox.warning(
                self, 
                "Directory Not Found",
                f"Results directory '{self.results_dir}' not found!\n\n"
                "Make sure you've run the analysis script first."
            )
            return
        
        txt_files = sorted(self.results_dir.glob("*.txt"))
        
        if not txt_files:
            QMessageBox.information(
                self,
                "No Results",
                f"No .txt files found in '{self.results_dir}'/\n\n"
                "Run the analysis script first to generate results."
            )
            return
        
        for file_path in txt_files:
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                
                name = file_path.stem
                self.results[name] = content
                self.original_contents[name] = content
                
                # Create CodeEditor tab
                text_edit = CodeEditor()
                text_edit.setReadOnly(True)
                text_edit.setPlainText(content)
                text_edit.setFont(QFont("Courier New", 14))
                
                # Store reference
                self.text_widgets[name] = text_edit
                
                # Add tab with nice name
                display_name = name.replace('_', ' ').title()
                self.tabs.addTab(text_edit, display_name)
                
            except Exception as e:
                print(f"[!] Error loading {file_path}: {e}")
        
        self.statusBar().showMessage(f"Loaded {len(self.results)} result files")
        
    def copy_current_tab(self):
        """Copy current tab content to clipboard"""
        current_widget = self.tabs.currentWidget()
        if current_widget and isinstance(current_widget, QPlainTextEdit):
            text = current_widget.toPlainText()
            QApplication.clipboard().setText(text)
            self.statusBar().showMessage("✓ Copied to clipboard!", 3000)

    def scroll_to_top(self):
        current = self.tabs.currentWidget()
        if isinstance(current, QPlainTextEdit):
            cursor = current.textCursor()
            cursor.movePosition(QTextCursor.MoveOperation.Start)
            current.setTextCursor(cursor)
            current.ensureCursorVisible()

    def scroll_to_bottom(self):
        current = self.tabs.currentWidget()
        if isinstance(current, QPlainTextEdit):
            cursor = current.textCursor()
            cursor.movePosition(QTextCursor.MoveOperation.End)
            current.setTextCursor(cursor)
            current.ensureCursorVisible()
    
    def on_search_changed(self, text):
        """Called when search text changes"""
        current_widget = self.tabs.currentWidget()
        if current_widget and isinstance(current_widget, CodeEditor):
            block_list = current_widget.highlight_all_matches(text)
            # status message showing number of matches
            self.statusBar().showMessage(f"Matches: {len(block_list)}", 1500)
        
    def find_next(self):
        search_text = self.search_box.text()
        if not search_text:
            return
        current_widget = self.tabs.currentWidget()
        if not current_widget or not isinstance(current_widget, CodeEditor):
            return
        found = current_widget.find_next(search_text)
        if not found:
            self.statusBar().showMessage("Not found", 2000)
        else:
            self.statusBar().showMessage("")

    def find_previous(self):
        search_text = self.search_box.text()
        if not search_text:
            return
        current_widget = self.tabs.currentWidget()
        if not current_widget or not isinstance(current_widget, CodeEditor):
            return
        found = current_widget.find_previous(search_text)
        if not found:
            self.statusBar().showMessage("Not found", 2000)
        else:
            self.statusBar().showMessage("")

    def on_tab_changed(self, index):
        """Handle tab change - re-highlight matches in new tab"""
        search_text = self.search_box.text()
        if search_text:
            current_widget = self.tabs.currentWidget()
            if current_widget and isinstance(current_widget, CodeEditor):
                block_list = current_widget.highlight_all_matches(search_text)
                self.statusBar().showMessage(f"Matches: {len(block_list)}", 1200)
        else:
            # clear markers for new tab
            current_widget = self.tabs.currentWidget()
            if current_widget and isinstance(current_widget, CodeEditor):
                current_widget.verticalScrollBar().set_markers([], current_widget.blockCount())


def main():
    app = QApplication(sys.argv)
    
    # Get results directory from command line or use default
    results_dir = sys.argv[1] if len(sys.argv) > 1 else "results"
    
    viewer = ResultViewer(results_dir)
    viewer.show()
    
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
