#!/usr/bin/env python3
import sys
from pathlib import Path
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QTabWidget, QTextEdit, 
    QVBoxLayout, QHBoxLayout, QWidget, QPushButton,
    QLineEdit, QLabel, QMessageBox, QPlainTextEdit
)
from PyQt6.QtGui import QFont, QColor, QPalette, QTextCursor, QShortcut, QKeySequence, QTextDocument, QTextCharFormat, QPainter, QTextFormat
from PyQt6.QtCore import Qt, QEvent, QObject, QRect, QSize

class HorizontalScrollFilter(QObject):
    """Event filter for shift+scroll horizontal scrolling"""
    def __init__(self, parent):
        super().__init__(parent)
        self.parent = parent
        
    def eventFilter(self, obj, event):
        if event.type() == QEvent.Type.Wheel:
            if event.modifiers() & Qt.KeyboardModifier.ShiftModifier:
                # Get the text edit widget
                text_edit = self.parent
                h_scroll = text_edit.horizontalScrollBar()
                
                # Scroll horizontally
                delta = event.angleDelta().y()
                h_scroll.setValue(h_scroll.value() - delta)
                return True
        return False


class LineNumberArea(QWidget):
    """Line number area widget"""
    def __init__(self, editor):
        super().__init__(editor)
        self.editor = editor
        
    def sizeHint(self):
        return QSize(self.editor.line_number_area_width(), 0)
    
    def paintEvent(self, event):
        self.editor.line_number_area_paint_event(event)


class NumberedTextEdit(QPlainTextEdit):
    """Plain text edit with line numbers"""
    def __init__(self):
        super().__init__()
        self.line_number_area = LineNumberArea(self)
        
        self.blockCountChanged.connect(self.update_line_number_area_width)
        self.updateRequest.connect(self.update_line_number_area)
        
        self.update_line_number_area_width(0)
        
    def line_number_area_width(self):
        digits = len(str(max(1, self.blockCount())))
        space = 10 + self.fontMetrics().horizontalAdvance('9') * digits
        return space
    
    def update_line_number_area_width(self, _):
        self.setViewportMargins(self.line_number_area_width(), 0, 0, 0)
    
    def update_line_number_area(self, rect, dy):
        if dy:
            self.line_number_area.scroll(0, dy)
        else:
            self.line_number_area.update(0, rect.y(), self.line_number_area.width(), rect.height())
        
        if rect.contains(self.viewport().rect()):
            self.update_line_number_area_width(0)
    
    def resizeEvent(self, event):
        super().resizeEvent(event)
        cr = self.contentsRect()
        self.line_number_area.setGeometry(QRect(cr.left(), cr.top(), self.line_number_area_width(), cr.height()))
    
    def line_number_area_paint_event(self, event):
        painter = QPainter(self.line_number_area)
        painter.fillRect(event.rect(), QColor(40, 40, 40))
        
        block = self.firstVisibleBlock()
        block_number = block.blockNumber()
        top = int(self.blockBoundingGeometry(block).translated(self.contentOffset()).top())
        bottom = top + int(self.blockBoundingRect(block).height())
        
        while block.isValid() and top <= event.rect().bottom():
            if block.isVisible() and bottom >= event.rect().top():
                number = str(block_number + 1)
                painter.setPen(QColor(100, 100, 100))
                painter.drawText(0, top, self.line_number_area.width() - 5, 
                               self.fontMetrics().height(), Qt.AlignmentFlag.AlignRight, number)
            
            block = block.next()
            top = bottom
            bottom = top + int(self.blockBoundingRect(block).height())
            block_number += 1


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
        
        # Search section (compact)
        search_label = QLabel("Search:")
        self.search_box = QLineEdit()
        self.search_box.setPlaceholderText("Find...")
        self.search_box.setMaximumWidth(200)
        self.search_box.returnPressed.connect(self.find_next)
        self.search_box.textChanged.connect(self.on_search_changed)
        
        # Ctrl+F focuses search
        search_shortcut = QShortcut(QKeySequence("Ctrl+F"), self)
        search_shortcut.activated.connect(self.focus_search)
        
        # Navigation buttons (compact, next to search)
        self.prev_btn = QPushButton("◄")
        self.prev_btn.setMaximumWidth(40)
        self.prev_btn.clicked.connect(self.find_previous)
        self.prev_btn.setToolTip("Previous match")
        
        self.next_btn = QPushButton("►")
        self.next_btn.setMaximumWidth(40)
        self.next_btn.clicked.connect(self.find_next)
        self.next_btn.setToolTip("Next match")
        
        # Spacer
        top_bar.addWidget(search_label)
        top_bar.addWidget(self.search_box)
        top_bar.addWidget(self.prev_btn)
        top_bar.addWidget(self.next_btn)
        top_bar.addStretch()
        
        # Navigation buttons
        top_btn = QPushButton("⇱ Top")
        top_btn.clicked.connect(self.go_to_top)
        top_btn.setToolTip("Go to top of file")
        
        bottom_btn = QPushButton("⇲ Bottom")
        bottom_btn.clicked.connect(self.go_to_bottom)
        bottom_btn.setToolTip("Go to bottom of file")
        
        # Copy button
        copy_btn = QPushButton("Copy Tab")
        copy_btn.clicked.connect(self.copy_current_tab)
        
        top_bar.addWidget(top_btn)
        top_bar.addWidget(bottom_btn)
        top_bar.addWidget(copy_btn)
        
        layout.addLayout(top_bar)
        
        # Tab widget
        self.tabs = QTabWidget()
        self.tabs.currentChanged.connect(self.on_tab_changed)
        layout.addWidget(self.tabs)
        
        # Status bar
        self.statusBar().showMessage("Ready")
        
    def go_to_top(self):
        """Jump to top of current tab"""
        current_widget = self.tabs.currentWidget()
        if current_widget and isinstance(current_widget, (QTextEdit, QPlainTextEdit)):
            cursor = current_widget.textCursor()
            cursor.movePosition(QTextCursor.MoveOperation.Start)
            current_widget.setTextCursor(cursor)
            current_widget.ensureCursorVisible()
    
    def go_to_bottom(self):
        """Jump to bottom of current tab"""
        current_widget = self.tabs.currentWidget()
        if current_widget and isinstance(current_widget, (QTextEdit, QPlainTextEdit)):
            cursor = current_widget.textCursor()
            cursor.movePosition(QTextCursor.MoveOperation.End)
            current_widget.setTextCursor(cursor)
            current_widget.ensureCursorVisible()
        
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
                padding: 6px 12px;
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
            QTextEdit, QPlainTextEdit {
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
            
            # Create text widget with line numbers
            text_edit = NumberedTextEdit()
            text_edit.setReadOnly(True)
            text_edit.setPlainText(content)
            text_edit.setFont(QFont("Courier New", 14))
            text_edit.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
            
            # Add horizontal scroll filter
            scroll_filter = HorizontalScrollFilter(text_edit)
            text_edit.viewport().installEventFilter(scroll_filter)
            
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
                
                # Create tab with text widget and line numbers
                text_edit = NumberedTextEdit()
                text_edit.setReadOnly(True)
                text_edit.setPlainText(content)
                text_edit.setFont(QFont("Courier New", 14))
                text_edit.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
                
                # Add horizontal scroll filter
                scroll_filter = HorizontalScrollFilter(text_edit)
                text_edit.viewport().installEventFilter(scroll_filter)
                
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
        if current_widget and isinstance(current_widget, (QTextEdit, QPlainTextEdit)):
            text = current_widget.toPlainText()
            QApplication.clipboard().setText(text)
            self.statusBar().showMessage("✓ Copied to clipboard!", 3000)
    
    def highlight_all_matches(self, text_edit, search_text):
        """Highlight all occurrences of search text"""
        if not search_text or not isinstance(text_edit, QPlainTextEdit):
            if hasattr(text_edit, 'setExtraSelections'):
                text_edit.setExtraSelections([])
            return
        
        extra_selections = []
        
        # Create highlight format
        highlight_format = QTextCharFormat()
        highlight_format.setBackground(QColor(255, 165, 0, 100))  # Semi-transparent orange
        
        # Search and highlight all matches
        cursor = QTextCursor(text_edit.document())
        cursor.movePosition(QTextCursor.MoveOperation.Start)
        
        while True:
            cursor = text_edit.document().find(search_text, cursor)
            if cursor.isNull():
                break
            
            selection = QPlainTextEdit.ExtraSelection()
            selection.cursor = cursor
            selection.format = highlight_format
            extra_selections.append(selection)
        
        text_edit.setExtraSelections(extra_selections)
    
    def on_search_changed(self, text):
        """Called when search text changes"""
        current_widget = self.tabs.currentWidget()
        if current_widget and isinstance(current_widget, (QTextEdit, QPlainTextEdit)):
            self.highlight_all_matches(current_widget, text)
        
    def find_next(self):
        """Find next occurrence of search text"""
        search_text = self.search_box.text()
        if not search_text:
            return
            
        current_widget = self.tabs.currentWidget()
        if not current_widget or not isinstance(current_widget, (QTextEdit, QPlainTextEdit)):
            return
        
        # Search from current cursor position
        found = current_widget.find(search_text)
        
        if not found:
            # Wrap around to beginning
            cursor = current_widget.textCursor()
            cursor.movePosition(QTextCursor.MoveOperation.Start)
            current_widget.setTextCursor(cursor)
            found = current_widget.find(search_text)
            
            if found:
                self.statusBar().showMessage("Wrapped to beginning", 2000)
            else:
                self.statusBar().showMessage("Not found", 2000)
        else:
            self.statusBar().showMessage("")
            
    def find_previous(self):
        """Find previous occurrence of search text"""
        search_text = self.search_box.text()
        if not search_text:
            return
            
        current_widget = self.tabs.currentWidget()
        if not current_widget or not isinstance(current_widget, (QTextEdit, QPlainTextEdit)):
            return
        
        # Search backwards
        found = current_widget.find(search_text, QTextDocument.FindFlag.FindBackward)
        
        if not found:
            # Wrap around to end
            cursor = current_widget.textCursor()
            cursor.movePosition(QTextCursor.MoveOperation.End)
            current_widget.setTextCursor(cursor)
            found = current_widget.find(search_text, QTextDocument.FindFlag.FindBackward)
            
            if found:
                self.statusBar().showMessage("Wrapped to end", 2000)
            else:
                self.statusBar().showMessage("Not found", 2000)
        else:
            self.statusBar().showMessage("")
        
    def on_tab_changed(self, index):
        """Handle tab change - re-highlight matches in new tab"""
        search_text = self.search_box.text()
        if search_text:
            current_widget = self.tabs.currentWidget()
            if current_widget and isinstance(current_widget, (QTextEdit, QPlainTextEdit)):
                self.highlight_all_matches(current_widget, search_text)


def main():
    app = QApplication(sys.argv)
    
    # Get results directory from command line or use default
    results_dir = sys.argv[1] if len(sys.argv) > 1 else "results"
    
    viewer = ResultViewer(results_dir)
    viewer.show()
    
    sys.exit(app.exec())


if __name__ == "__main__":
    main()