#!/usr/bin/env python3
import sys
from pathlib import Path
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QTabWidget, QTextEdit, 
    QVBoxLayout, QHBoxLayout, QWidget, QPushButton,
    QLineEdit, QLabel, QMessageBox
)
from PyQt6.QtGui import QFont, QColor, QPalette, QTextCursor, QShortcut, QKeySequence, QTextDocument, QTextCharFormat
from PyQt6.QtCore import Qt, QEvent, QObject

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
        
        # Search box
        search_label = QLabel("Search:")
        self.search_box = QLineEdit()
        self.search_box.setPlaceholderText("Search in current tab...")
        self.search_box.returnPressed.connect(self.find_next)
        self.search_box.textChanged.connect(self.on_search_changed)
        
        # Ctrl+F focuses search
        search_shortcut = QShortcut(QKeySequence("Ctrl+F"), self)
        search_shortcut.activated.connect(self.focus_search)
        
        # Navigation buttons
        self.prev_btn = QPushButton("◄ Previous")
        self.prev_btn.clicked.connect(self.find_previous)
        
        self.next_btn = QPushButton("Next ►")
        self.next_btn.clicked.connect(self.find_next)
        
        # Copy button
        copy_btn = QPushButton("Copy Tab")
        copy_btn.clicked.connect(self.copy_current_tab)
        
        top_bar.addWidget(search_label)
        top_bar.addWidget(self.search_box, stretch=1)
        top_bar.addWidget(self.prev_btn)
        top_bar.addWidget(self.next_btn)
        top_bar.addWidget(copy_btn)
        
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
            QTextEdit {
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
            
            # Create text widget for cheatsheet
            text_edit = QTextEdit()
            text_edit.setReadOnly(True)
            text_edit.setPlainText(content)
            text_edit.setFont(QFont("Courier New", 14))
            text_edit.setLineWrapMode(QTextEdit.LineWrapMode.NoWrap)
            
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
                
                # Create tab with text widget
                text_edit = QTextEdit()
                text_edit.setReadOnly(True)
                text_edit.setPlainText(content)
                text_edit.setFont(QFont("Courier New", 14))
                text_edit.setLineWrapMode(QTextEdit.LineWrapMode.NoWrap)
                
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
        if current_widget and isinstance(current_widget, QTextEdit):
            text = current_widget.toPlainText()
            QApplication.clipboard().setText(text)
            self.statusBar().showMessage("✓ Copied to clipboard!", 3000)
    
    def highlight_all_matches(self, text_edit, search_text):
        """Highlight all occurrences of search text"""
        if not search_text:
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
            
            selection = QTextEdit.ExtraSelection()
            selection.cursor = cursor
            selection.format = highlight_format
            extra_selections.append(selection)
        
        text_edit.setExtraSelections(extra_selections)
    
    def on_search_changed(self, text):
        """Called when search text changes"""
        current_widget = self.tabs.currentWidget()
        if current_widget and isinstance(current_widget, QTextEdit):
            self.highlight_all_matches(current_widget, text)
        
    def find_next(self):
        """Find next occurrence of search text"""
        search_text = self.search_box.text()
        if not search_text:
            return
            
        current_widget = self.tabs.currentWidget()
        if not current_widget or not isinstance(current_widget, QTextEdit):
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
        if not current_widget or not isinstance(current_widget, QTextEdit):
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
            if current_widget and isinstance(current_widget, QTextEdit):
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